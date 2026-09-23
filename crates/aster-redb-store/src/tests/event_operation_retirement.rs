use super::*;
use crate::event_operation::*;
use redb::TableHandle;

const SAMPLE: aster_mesh::CustodySample = aster_mesh::CustodySample {
    clock_id: [0xa5; 16],
    tick_ms: 1_000,
};
const EXPIRED: aster_mesh::CustodySample = aster_mesh::CustodySample {
    tick_ms: 1_100,
    ..SAMPLE
};

fn fixture(aliases: u8) -> (TestFile, EventServices, Store, StoredEvent) {
    let file = TestFile::new("operation retirement");
    let mut services = event_services(0xa5);
    // Exactly 64 active aliases plus the mandatory one-record reserve.
    let store = Store::open_with_limits_and_operation_limits_for_mission(
        &file.0,
        StoreLimits::default(),
        BlobDepotLimits::DEFAULT,
        EventOperationLimits::new(65, 10_530, 1).expect("limits"),
        services.authority,
    )
    .expect("store");
    let policy = store.control_policy_snapshot().expect("policy");
    let reservation = store
        .reserve_event_with_policy(
            &policy,
            services.publisher.identity(),
            &event_topic(),
            &event_scope(),
        )
        .expect("reservation");
    let header = reservation
        .header(
            Priority::Routine,
            b"retirement".to_vec(),
            Some(100),
            7,
            false,
            1,
        )
        .expect("header");
    let sealed = services
        .publisher
        .seal_event(&header, b"payload")
        .expect("seal");
    let event = content_event(&mut services.reader, &sealed.bytes);
    let transfer = EventTransferId::new(event.envelope_id());
    // A real unkeyed Event acceptance permits testing the zero-alias boundary.
    let prepared =
        PreparedEvent::from_verified_with_custody(&event, &sealed.bytes, EventOrigin::Local)
            .expect("prepared");
    store
        .commit_prepared_event(
            &prepared,
            Some(&reservation),
            None,
            EventAdmissionGuard::Control(&policy),
            Some(PendingEventCustody {
                expected_policy: store.custody_policy_revision().expect("revision"),
                authenticated_age_ms: 0,
                sample: Some(SAMPLE),
            }),
        )
        .expect("accept unkeyed Event");
    let intent = event_publication_intent(&header, b"payload");
    for alias in 0..aliases {
        let key = EventOperationKey::new(vec![0xa5, alias]).expect("key");
        let request = EventOperationRequest::new(&key, &intent, b"payload", None).expect("request");
        store
            .commit_reserved_event_once_with_custody_policy(
                &policy,
                LocalCustodyCheckpoint::new(
                    store.custody_policy_revision().expect("revision"),
                    SAMPLE,
                ),
                &request,
                &reservation,
                &event,
                &sealed.bytes,
            )
            .expect("alias");
    }
    let stored = store.get_event(transfer).expect("lookup").expect("Event");
    (file, services, store, stored)
}

fn stats(store: &Store) -> EventOperationStats {
    inspect_event_operation_accounting_read(&store.database.begin_read().expect("read"))
        .expect("operation stats")
}

fn retire(store: &Store) -> Result<CustodyGcReport, StoreError> {
    store.collect_custody_garbage(Some(EXPIRED), store.custody_policy_revision()?, 64)
}

type Snapshot = Vec<(String, Vec<(String, String)>)>;

fn snapshot(read: &redb::ReadTransaction) -> Snapshot {
    read.list_tables()
        .expect("tables")
        .map(|table| {
            let name = table.name().to_owned();
            let rows = super::event_operation_migration::snapshot_table(read, &name);
            (name, rows)
        })
        .collect()
}

fn shared_snapshot(store: &Store) -> Snapshot {
    let read = store.database.begin_read().expect("read shared metadata");
    [
        EVENTS.name(),
        SEMANTIC_ITEMS.name(),
        ACCEPTED_DOTS.name(),
        ACCEPTED_EVENTS.name(),
        CAUSAL_FRONTIER.name(),
        PUBLISHER_HIGH_WATER.name(),
        EVENT_HIGH_WATER.name(),
        EVENT_ACCEPTANCE_MARKERS.name(),
        EVENT_ACCEPTANCE_ORDER.name(),
        EVENT_OPERATION_WITNESSES.name(),
        EVENT_OPERATIONS.name(),
    ]
    .into_iter()
    .map(|name| {
        (
            name.to_owned(),
            super::event_operation_migration::snapshot_table(&read, name),
        )
    })
    .collect()
}

#[test]
fn retirement_compacts_zero_one_and_64_aliases_at_full_capacity_and_reopens() {
    // Missing compaction, a wrong delta, quota admission during conversion, or
    // deleting shared metadata breaks these hand-derived expectations.
    for (aliases, before_bytes, after_bytes) in [(0, 0, 0), (1, 162, 67), (64, 10_368, 4_288)] {
        let (file, services, store, stored) = fixture(aliases);
        let audit = store
            .audit_event_operations(7, |_| {})
            .expect("audit active aliases");
        assert_eq!(
            (audit.scanned, audit.total),
            (u64::from(aliases) * 2, u64::from(aliases) * 2)
        );
        assert_eq!(
            stats(&store),
            EventOperationStats {
                records_total: u64::from(aliases),
                records_active: u64::from(aliases),
                records_retired: 0,
                reverse_rows: u64::from(aliases),
                logical_bytes: before_bytes,
            }
        );
        let shared = shared_snapshot(&store);
        let report = retire(&store).expect("retire");
        assert_eq!(
            report.retired,
            vec![CustodyObjectKey::event(stored.transfer_id)]
        );
        assert_eq!(shared_snapshot(&store), shared);
        assert_eq!(
            stats(&store),
            EventOperationStats {
                records_total: u64::from(aliases),
                records_active: 0,
                records_retired: u64::from(aliases),
                reverse_rows: 0,
                logical_bytes: after_bytes,
            }
        );
        assert!(
            store
                .get_event(stored.transfer_id)
                .expect("payload lookup")
                .is_none()
        );
        let read = store.database.begin_read().expect("read retired");
        assert_eq!(
            read.open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                .expect("reverse")
                .len()
                .expect("len"),
            0
        );
        for row in read
            .open_table(EVENT_OPERATION_LEDGER_V3)
            .expect("ledger")
            .iter()
            .expect("rows")
        {
            let (key, value) = row.expect("row");
            assert_eq!((key.value().len(), value.value().len()), (32, 35));
        }
        assert_eq!(
            custody::retired_event_receipt_read(&read, stored.transfer_id).expect("receipt"),
            Some((
                stored.semantic_id,
                stored.acceptance_marker,
                CustodyRetirementReason::Expired
            ))
        );
        drop(read);
        drop(store);
        let reopened =
            Store::open_for_mission(&file.0, services.authority).expect("reopen retired");
        let audit = reopened
            .audit_event_operations(7, |_| {})
            .expect("audit compact retired aliases");
        assert_eq!(
            (audit.scanned, audit.total),
            (u64::from(aliases), u64::from(aliases))
        );
        assert_eq!(shared_snapshot(&reopened), shared);
        assert_eq!(stats(&reopened).logical_bytes, after_bytes);
        let intent = event_publication_intent(&stored.header, b"payload");
        let changed = event_publication_intent(&stored.header, b"changed");
        for alias in 0..aliases {
            let key = EventOperationKey::new(vec![0xa5, alias]).expect("key");
            let exact = EventOperationRequest::new(&key, &intent, b"payload", None).expect("exact");
            assert_eq!(
                reopened
                    .event_operation_resolution_for_request(&exact)
                    .expect("exact retry"),
                Some(EventOperationResolution::RetiredOperation {
                    reason: CustodyRetirementReason::Expired
                })
            );
            let changed =
                EventOperationRequest::new(&key, &changed, b"changed", None).expect("changed");
            assert!(matches!(
                reopened.event_operation_resolution_for_request(&changed),
                Err(StoreError::EventOperationConflict)
            ));
        }
    }
}

#[test]
fn retirement_rejects_corrupt_edges_targets_and_counters_without_any_commit() {
    // Each mutation must abort the complete GC transaction, including marks,
    // continuity, custody fences, payload deletion, and all earlier aliases.
    let _reset = FaultReset;
    let mut accepted = Vec::new();
    for corruption in [
        "missing-edge",
        "missing-target",
        "short-edge",
        "long-edge",
        "edge-value",
        "malformed-target",
        "wrong-transfer",
        "retired-target",
        "missing-counter",
        "total-counter",
        "active-counter",
        "retired-counter",
        "reverse-counter",
        "byte-counter",
        "coherent-undercount",
        "65-aliases",
    ] {
        let (file, _services, store, stored) = fixture(2);
        let write = store.database.begin_write().expect("corrupt transaction");
        let (fingerprint, encoded) = {
            let ledger = write.open_table(EVENT_OPERATION_LEDGER_V3).expect("ledger");
            let (key, value) = ledger
                .iter()
                .expect("rows")
                .next_back()
                .expect("last row")
                .expect("row");
            (key.value().to_vec(), value.value().to_vec())
        };
        let edge = encode_active_operation_by_event_key(
            stored.transfer_id,
            fingerprint.as_slice().try_into().expect("fingerprint"),
        );
        match corruption {
            "missing-edge" => {
                write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .expect("reverse")
                    .remove(edge.as_slice())
                    .expect("remove");
            }
            "missing-target" => {
                let mut ledger = write.open_table(EVENT_OPERATION_LEDGER_V3).expect("ledger");
                ledger.remove(fingerprint.as_slice()).expect("remove");
                ledger
                    .insert([0xff; 32].as_slice(), encoded.as_slice())
                    .expect("unreferenced target");
            }
            "short-edge" | "long-edge" => {
                let mut reverse = write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .expect("reverse");
                reverse.remove(edge.as_slice()).expect("remove");
                let mut malformed = edge.to_vec();
                if corruption == "short-edge" {
                    malformed.truncate(32);
                } else {
                    malformed.push(0);
                }
                reverse
                    .insert(malformed.as_slice(), &[][..])
                    .expect("malformed edge");
            }
            "edge-value" => {
                write
                    .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                    .expect("reverse")
                    .insert(edge.as_slice(), &[1][..])
                    .expect("value");
            }
            "malformed-target" | "wrong-transfer" | "retired-target" => {
                let mut target = encoded;
                if corruption == "malformed-target" {
                    target.truncate(4);
                } else if corruption == "wrong-transfer" {
                    target[34..].fill(0xff);
                } else {
                    target[1] = 2;
                    target.truncate(35);
                    target[34] = CustodyRetirementReason::Expired as u8;
                }
                write
                    .open_table(EVENT_OPERATION_LEDGER_V3)
                    .expect("ledger")
                    .insert(fingerprint.as_slice(), target.as_slice())
                    .expect("target");
            }
            "65-aliases" => {
                // Bypass the publication cap only to emulate a corrupt durable image.
                for n in 0..63u8 {
                    let extra = [n; 32];
                    write
                        .open_table(EVENT_OPERATION_LEDGER_V3)
                        .expect("ledger")
                        .insert(extra.as_slice(), encoded.as_slice())
                        .expect("extra ledger");
                    write
                        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
                        .expect("reverse")
                        .insert(
                            encode_active_operation_by_event_key(stored.transfer_id, extra)
                                .as_slice(),
                            &[][..],
                        )
                        .expect("extra edge");
                }
                write_event_operation_stats(
                    &mut write.open_table(METADATA).expect("metadata"),
                    EventOperationStats {
                        records_total: 65,
                        records_active: 65,
                        records_retired: 0,
                        reverse_rows: 65,
                        logical_bytes: 10_530,
                    },
                )
                .expect("65 alias accounting");
            }
            "coherent-undercount" => {
                write_event_operation_stats(
                    &mut write.open_table(METADATA).expect("metadata"),
                    EventOperationStats::default(),
                )
                .expect("undercount");
            }
            name => {
                let field = match name {
                    "missing-counter" | "total-counter" => EVENT_OPERATION_RECORDS_TOTAL,
                    "active-counter" => EVENT_OPERATION_RECORDS_ACTIVE,
                    "retired-counter" => EVENT_OPERATION_RECORDS_RETIRED,
                    "reverse-counter" => EVENT_OPERATION_REVERSE_ROWS,
                    "byte-counter" => EVENT_OPERATION_LOGICAL_BYTES,
                    _ => unreachable!(),
                };
                let mut metadata = write.open_table(METADATA).expect("metadata");
                if name == "missing-counter" {
                    metadata.remove(field).expect("remove counter");
                } else {
                    metadata.insert(field, 99).expect("corrupt counter");
                }
            }
        }
        write.commit().expect("commit corrupt fixture");
        let before = snapshot(&store.database.begin_read().expect("before"));
        // Point 1 is immediately before the first operation mutation. Every
        // invalid edge/target/counter must fail before reaching that point.
        RETIREMENT_TEST_FAULT.set(1);
        let result = retire(&store);
        RETIREMENT_TEST_FAULT.set(0);
        if result.is_ok() {
            accepted.push(corruption);
            continue;
        }
        let error = match result.unwrap_err() {
            StoreError::EventOperationRetirementInvariant(error) => *error,
            error => error,
        };
        assert!(
            !matches!(
                error,
                StoreError::SemanticInvariant("injected Event operation retirement failure")
            ),
            "{corruption} reached mutation before validation"
        );
        assert_eq!(
            snapshot(&store.database.begin_read().expect("after")),
            before,
            "mutated {corruption}"
        );
        drop(store);
        // Raw reopen is intentional: the fixture was already corrupt before GC.
        let database = Database::open(&file.0).expect("raw reopen");
        assert_eq!(
            snapshot(&database.begin_read().expect("reopened read")),
            before,
            "reopen changed {corruption}"
        );
    }
    assert!(accepted.is_empty(), "accepted corruptions: {accepted:?}");
}

struct FaultReset;

impl Drop for FaultReset {
    fn drop(&mut self) {
        RETIREMENT_TEST_FAULT.set(0);
    }
}

#[test]
fn retirement_faults_before_during_and_after_compaction_reopen_the_complete_before_image() {
    let _reset = FaultReset;
    let mut missed = Vec::new();
    for point in 1..=4 {
        let (file, services, store, stored) = fixture(2);
        let before = snapshot(&store.database.begin_read().expect("before"));
        RETIREMENT_TEST_FAULT.set(point);
        let result = retire(&store);
        RETIREMENT_TEST_FAULT.set(0);
        if result.is_ok() {
            missed.push(point);
            continue;
        }
        let error = match (point, result.unwrap_err()) {
            (1..=3, StoreError::EventOperationRetirementInvariant(error)) => *error,
            (4, error) => error,
            (_, error) => panic!("unexpected retirement error category: {error:?}"),
        };
        assert!(matches!(
            error,
            StoreError::SemanticInvariant("injected Event operation retirement failure")
        ));
        assert_eq!(
            snapshot(&store.database.begin_read().expect("after error")),
            before
        );
        drop(store);
        {
            let database = Database::open(&file.0).expect("raw reopen");
            assert_eq!(snapshot(&database.begin_read().expect("raw read")), before);
        }
        let reopened =
            Store::open_for_mission(&file.0, services.authority).expect("audited reopen");
        assert_eq!(
            stats(&reopened),
            EventOperationStats {
                records_total: 2,
                records_active: 2,
                records_retired: 0,
                reverse_rows: 2,
                logical_bytes: 324,
            }
        );
        assert!(
            reopened
                .get_event(stored.transfer_id)
                .expect("retained payload")
                .is_some()
        );
        assert_eq!(
            retire(&reopened).expect("retry retirement").retired,
            vec![CustodyObjectKey::event(stored.transfer_id)]
        );
        assert_eq!(
            stats(&reopened),
            EventOperationStats {
                records_total: 2,
                records_active: 0,
                records_retired: 2,
                reverse_rows: 0,
                logical_bytes: 134,
            }
        );
    }
    assert!(
        missed.is_empty(),
        "missed retirement fault points: {missed:?}"
    );
}

#[test]
fn retirement_ranges_only_the_selected_event_and_preserves_other_aliases() {
    let (file, mut services, store, stored) = fixture(2);
    let other = accept_local_finite_event(&store, &mut services, 7, b"other", 10_000, SAMPLE);
    let key = EventOperationKey::new(vec![b'f', 7]).expect("other key");
    let fingerprint = event_operation_fingerprint(&services.authority, &key);
    let edge = encode_active_operation_by_event_key(other, fingerprint);
    let write = store.database.begin_write().expect("write");
    // An unrelated invalid value exposes an accidental full reverse scan.
    // Complete validation of other Events belongs to the ledger audit.
    write
        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
        .expect("reverse")
        .insert(edge.as_slice(), b"unrelated".as_slice())
        .expect("unrelated edge");
    write.commit().expect("commit unrelated fixture");
    assert_eq!(
        retire(&store).expect("retire selected").retired,
        vec![CustodyObjectKey::event(stored.transfer_id)]
    );
    assert_eq!(
        stats(&store),
        EventOperationStats {
            records_total: 3,
            records_active: 1,
            records_retired: 2,
            reverse_rows: 1,
            logical_bytes: 296,
        }
    );
    let read = store.database.begin_read().expect("read");
    let reverse = read
        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
        .expect("reverse");
    assert_eq!(
        reverse
            .get(edge.as_slice())
            .expect("edge")
            .expect("retained edge")
            .value(),
        b"unrelated"
    );
    assert!(store.get_event(other).expect("other payload").is_some());
    drop((reverse, read));
    // Repair only the injected unrelated corruption before a normal reopen.
    let write = store.database.begin_write().expect("repair fixture");
    write
        .open_table(ACTIVE_OPERATION_BY_EVENT_V1)
        .expect("reverse")
        .insert(edge.as_slice(), &[][..])
        .expect("repair edge");
    write.commit().expect("commit repair");
    drop(store);
    let reopened =
        Store::open_for_mission(&file.0, services.authority).expect("reopen selected retirement");
    assert!(
        reopened
            .get_event(other)
            .expect("retained other Event")
            .is_some()
    );
    assert_eq!(stats(&reopened).logical_bytes, 296);
}

#[test]
fn retirement_compacts_live_pressure_victims_with_the_pressure_reason() {
    let (file, services, store, stored) = fixture(1);
    let shared = shared_snapshot(&store);
    let revision = store
        .set_custody_quota(CustodyQuota::global(1, 1_000_000).expect("quota"))
        .expect("set quota");
    let report = store
        .collect_custody_pressure(
            None,
            CustodyPressureDemand {
                usage: CustodyUsage { items: 1, bytes: 1 },
                priority: Priority::Immediate,
            },
            Some(SAMPLE),
            revision,
            1,
        )
        .expect("pressure retirement");
    assert_eq!(
        report.retired,
        vec![CustodyObjectKey::event(stored.transfer_id)]
    );
    assert_eq!(shared_snapshot(&store), shared);
    drop(store);
    let reopened =
        Store::open_for_mission(&file.0, services.authority).expect("reopen pressure victim");
    assert_eq!(stats(&reopened).logical_bytes, 67);
    let key = EventOperationKey::new(vec![0xa5, 0]).expect("key");
    assert_eq!(
        reopened
            .event_operation_resolution(&key)
            .expect("resolution"),
        Some(EventOperationResolution::RetiredOperation {
            reason: CustodyRetirementReason::QuotaPressure
        })
    );
}

fn numbered_finite_fixture(
    priority: Priority,
) -> (
    TestFile,
    EventServices,
    Store,
    EventClientId,
    EventRecoverySnapshot,
    NumberedEventResult,
) {
    let file = TestFile::new("numbered finite retirement");
    let mut services = event_services(0xa6);
    let store = Store::open_for_mission(&file.0, services.authority).expect("store");
    let client = EventClientId::new(b"numbered-retirement".to_vec()).expect("client");
    let claimed = store
        .begin_event_publication_session(&client, 0, b"initial-claim")
        .expect("claim client");
    store
        .complete_event_publication_recovery(&client, claimed.session, claimed.snapshot_revision)
        .expect("complete initial recovery");
    let policy = store.control_policy_snapshot().expect("control policy");
    let reservation = store
        .reserve_event_with_policy(
            &policy,
            services.publisher.identity(),
            &event_topic(),
            &event_scope(),
        )
        .expect("reservation");
    let payload = b"numbered";
    let header = reservation
        .header(
            priority,
            b"numbered-retirement".to_vec(),
            Some(100),
            payload.len() as u64,
            false,
            1,
        )
        .expect("header");
    let intent = event_publication_intent(&header, payload);
    let request = NumberedEventOperationRequest::new(
        &client,
        claimed.session,
        EventOperationSequence::new(1).expect("sequence"),
        None,
        &intent,
        payload,
    )
    .expect("numbered request");
    let sealed = services
        .publisher
        .seal_event(&header, payload)
        .expect("seal");
    let event = content_event(&mut services.reader, &sealed.bytes);
    let published = store
        .commit_reserved_numbered_event_with_custody_policy(
            &policy,
            LocalCustodyCheckpoint::new(
                store.custody_policy_revision().expect("custody revision"),
                SAMPLE,
            ),
            &request,
            &reservation,
            &event,
            &sealed.bytes,
        )
        .expect("numbered finite commit");
    assert!(published.inserted);
    assert_eq!(published.result.content, CommittedEventContent::Available);
    let before = store
        .begin_event_publication_session(&client, claimed.session.get(), b"before-retirement")
        .expect("recover committed result");
    assert_eq!(before.outstanding, vec![published.result]);
    (file, services, store, client, before, published.result)
}

#[test]
fn numbered_result_retires_at_expiry_mark_while_lease_holds_payload() {
    let (_file, services, store, client, before, published) =
        numbered_finite_fixture(Priority::Routine);
    let key = CustodyObjectKey::event(published.receipt.transfer_id);
    let lease = store
        .begin_custody_send(
            services.relay.identity(),
            key,
            CustodyPeerSelectorRevision::new(1),
            Some(SAMPLE),
            1,
            store.custody_policy_revision().expect("lease revision"),
        )
        .expect("active transfer lease");

    let marked = retire(&store).expect("mark expired Event");
    assert_eq!(marked.marked, vec![key]);
    assert!(marked.retired.is_empty());
    assert_eq!(marked.blocked_by_leases, 1);
    assert_eq!(
        store
            .get_event(published.receipt.transfer_id)
            .expect("logical lookup"),
        None
    );
    assert_eq!(store.event_stats().expect("retained bytes").events, 1);
    let first = store
        .begin_event_publication_session(&client, before.session.get(), b"after-mark")
        .expect("recover after logical mark");
    assert_eq!(first.outstanding.len(), 1);
    assert_eq!(first.outstanding[0].receipt, published.receipt);
    assert_eq!(
        first.outstanding[0].content,
        CommittedEventContent::Retired(CustodyRetirementReason::Expired)
    );
    assert_eq!(first.snapshot_revision, before.snapshot_revision + 1);

    let repeated = retire(&store).expect("repeat mark while leased");
    assert!(repeated.marked.is_empty());
    assert!(repeated.retired.is_empty());
    assert_eq!(repeated.blocked_by_leases, 1);
    let replay = store
        .begin_event_publication_session(&client, first.session.get(), b"after-repeat")
        .expect("recover after repeat");
    assert_eq!(replay.snapshot_revision, first.snapshot_revision);
    assert_eq!(replay.outstanding, first.outstanding);

    store
        .release_transfer_lease(lease.id)
        .expect("release lease");
    let finalized = retire(&store).expect("finalize expiry");
    assert_eq!(finalized.retired, vec![key]);
    assert_eq!(store.event_stats().expect("after cleanup").events, 0);
    let after = store
        .begin_event_publication_session(&client, replay.session.get(), b"after-finalize")
        .expect("recover after physical cleanup");
    assert_eq!(after.snapshot_revision, first.snapshot_revision);
    assert_eq!(after.outstanding, first.outstanding);
}

#[test]
fn numbered_result_keeps_quota_pressure_reason_after_later_expiry() {
    let (_file, services, store, client, before, published) =
        numbered_finite_fixture(Priority::Routine);
    let key = CustodyObjectKey::event(published.receipt.transfer_id);
    let quota_revision = store
        .set_custody_quota(CustodyQuota::global(1, 1_000_000).expect("quota"))
        .expect("set quota");
    let lease = store
        .begin_custody_send(
            services.relay.identity(),
            key,
            CustodyPeerSelectorRevision::new(1),
            Some(SAMPLE),
            1,
            quota_revision,
        )
        .expect("active transfer lease");
    assert!(
        store
            .collect_custody_pressure(
                None,
                CustodyPressureDemand {
                    usage: CustodyUsage { items: 1, bytes: 1 },
                    priority: Priority::Immediate,
                },
                Some(SAMPLE),
                quota_revision,
                1,
            )
            .is_err(),
        "held bytes cannot satisfy the requested quota"
    );
    assert_eq!(
        store
            .get_event(published.receipt.transfer_id)
            .expect("logical lookup"),
        None
    );
    assert_eq!(store.event_stats().expect("retained bytes").events, 1);
    let marked = store
        .begin_event_publication_session(&client, before.session.get(), b"pressure-mark")
        .expect("recover pressure mark");
    assert_eq!(marked.outstanding.len(), 1);
    assert_eq!(marked.outstanding[0].receipt, published.receipt);
    assert_eq!(
        marked.outstanding[0].content,
        CommittedEventContent::Retired(CustodyRetirementReason::QuotaPressure)
    );
    assert_eq!(marked.snapshot_revision, before.snapshot_revision + 1);

    store
        .release_transfer_lease(lease.id)
        .expect("release lease");
    let finalized = retire(&store).expect("finish after TTL elapsed");
    assert_eq!(finalized.retired, vec![key]);
    let after = store
        .begin_event_publication_session(&client, marked.session.get(), b"pressure-final")
        .expect("recover after finalization");
    assert_eq!(after.snapshot_revision, marked.snapshot_revision);
    assert_eq!(after.outstanding, marked.outstanding);
}

#[test]
fn numbered_retirement_invariant_failure_rolls_back_custody_mark() {
    let (_file, services, store, client, before, published) =
        numbered_finite_fixture(Priority::Routine);
    let key = CustodyObjectKey::event(published.receipt.transfer_id);
    let _lease = store
        .begin_custody_send(
            services.relay.identity(),
            key,
            CustodyPeerSelectorRevision::new(1),
            Some(SAMPLE),
            1,
            store.custody_policy_revision().expect("lease revision"),
        )
        .expect("active transfer lease");
    const REVERSE: redb::TableDefinition<&[u8], &[u8]> =
        redb::TableDefinition::new("aster.numbered-event-result-by-event.v1");
    let edge = {
        let write = store.database.begin_write().expect("corrupt reverse edge");
        let mut reverse = write.open_table(REVERSE).expect("reverse table");
        let edge = reverse
            .iter()
            .expect("reverse rows")
            .next()
            .expect("one reverse row")
            .expect("reverse row")
            .0
            .value()
            .to_vec();
        reverse
            .insert(edge.as_slice(), b"invalid".as_slice())
            .expect("insert malformed reverse value");
        drop(reverse);
        write.commit().expect("commit malformed edge");
        edge
    };

    retire(&store).expect_err("invalid numbered result must abort custody mark");
    assert!(
        store
            .get_event(published.receipt.transfer_id)
            .expect("Event remains available")
            .is_some()
    );
    assert_eq!(
        store.event_stats().expect("unmarked stats").retiring_events,
        0
    );
    let after_failure = store
        .begin_event_publication_session(&client, before.session.get(), b"after-failure")
        .expect("recover after rollback");
    assert_eq!(after_failure.snapshot_revision, before.snapshot_revision);
    assert_eq!(after_failure.outstanding, before.outstanding);

    let write = store.database.begin_write().expect("repair reverse edge");
    write
        .open_table(REVERSE)
        .expect("reverse table")
        .insert(edge.as_slice(), &[][..])
        .expect("restore empty reverse value");
    write.commit().expect("commit reverse repair");
    let marked = retire(&store).expect("mark repaired Event");
    assert_eq!(marked.marked, vec![key]);
    assert_eq!(marked.blocked_by_leases, 1);
    let recovered = store
        .begin_event_publication_session(&client, after_failure.session.get(), b"after-repair")
        .expect("recover after repaired mark");
    assert_eq!(
        recovered.outstanding[0].content,
        CommittedEventContent::Retired(CustodyRetirementReason::Expired)
    );
}

#[test]
fn route_only_pressure_retirement_does_not_scan_numbered_result_edges() {
    let (_file, mut services, store, client, before, published) =
        numbered_finite_fixture(Priority::Flash);
    let payload = b"route-only";
    let mut header = event_header(
        services.publisher.identity(),
        2,
        2,
        VersionVector::default(),
        b"route-only",
        payload,
        None,
    );
    header.priority = Priority::Routine;
    let sealed = services
        .publisher
        .seal_event(&header, payload)
        .expect("seal route-only Event");
    let route = services
        .relay
        .verify_event(&sealed.bytes)
        .expect("verify route-only Event");
    let route_id = EventTransferId::new(route.envelope_id());
    store
        .cache_route_verified_event(&route, &sealed.bytes)
        .expect("cache route-only Event");
    let route_key = CustodyObjectKey::route_event(route_id);
    const REVERSE: redb::TableDefinition<&[u8], &[u8]> =
        redb::TableDefinition::new("aster.numbered-event-result-by-event.v1");
    let mut unrelated_edge = route_id.as_bytes().to_vec();
    unrelated_edge.push(0);
    let write = store
        .database
        .begin_write()
        .expect("inject unrelated reverse row");
    write
        .open_table(REVERSE)
        .expect("reverse table")
        .insert(unrelated_edge.as_slice(), b"invalid".as_slice())
        .expect("insert unrelated malformed edge");
    write.commit().expect("commit unrelated row");

    let revision = store
        .set_custody_quota(CustodyQuota::global(2, 1_000_000).expect("quota"))
        .expect("set quota");
    let retired = store
        .collect_custody_pressure(
            None,
            CustodyPressureDemand {
                usage: CustodyUsage { items: 1, bytes: 1 },
                priority: Priority::Immediate,
            },
            Some(SAMPLE),
            revision,
            1,
        )
        .expect("route pressure retirement");
    assert_eq!(retired.retired, vec![route_key]);
    let recovered = store
        .begin_event_publication_session(&client, before.session.get(), b"after-route")
        .expect("recover numbered result");
    assert_eq!(recovered.snapshot_revision, before.snapshot_revision);
    assert_eq!(recovered.outstanding, vec![published]);

    let write = store.database.begin_write().expect("remove injected row");
    write
        .open_table(REVERSE)
        .expect("reverse table")
        .remove(unrelated_edge.as_slice())
        .expect("remove injected reverse edge");
    write.commit().expect("commit reverse cleanup");
}
