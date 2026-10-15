use super::blob_ranges_stream_test::Boundary as StreamBoundary;

#[tokio::test]
async fn blob_ranges_stream_live_lost_terminal_after_complete_prefix_reopens_without_refetch() {
    stream_live_boundary(StreamBoundary::LostTerminal).await;
}
#[tokio::test]
async fn blob_ranges_stream_live_bad_aead_retains_prefix() {
    stream_live_boundary(StreamBoundary::BadAead).await;
}
#[tokio::test]
async fn blob_ranges_stream_live_wrong_aad_retains_prefix() {
    stream_live_boundary(StreamBoundary::WrongAad).await;
}
#[tokio::test]
async fn blob_ranges_stream_live_revocation_rejects_next_append() {
    stream_live_boundary(StreamBoundary::Revocation).await;
}
#[tokio::test]
async fn blob_ranges_stream_live_append_capacity_yields_preserving_prefix() {
    stream_live_boundary(StreamBoundary::AppendCapacity).await;
}
#[tokio::test]
async fn blob_ranges_stream_lost_terminal_after_append_capacity_is_cursor_neutral() {
    stream_live_boundary(StreamBoundary::AppendCapacityLostTerminal).await;
}
#[tokio::test]
async fn blob_ranges_stream_live_unavailable_gap_does_not_erase_prefix() {
    stream_live_boundary(StreamBoundary::UnavailableGap).await;
}
#[tokio::test]
async fn blob_ranges_stream_bad_terminal_is_cursor_neutral() {
    stream_live_boundary(StreamBoundary::BadTerminalAad).await;
}

#[tokio::test]
async fn blob_ranges_stream_expiry_between_ranges_retires_pending_without_cursor_advance() {
    stream_receiver_lifetime_loss_between_ranges(false).await;
}

#[tokio::test]
async fn blob_ranges_stream_continuity_loss_between_ranges_hides_pending_without_retirement() {
    stream_receiver_lifetime_loss_between_ranges(true).await;
}

async fn stream_receiver_lifetime_loss_between_ranges(discontinuity: bool) {
    // Mutation caught: accepting the authenticated terminal after a later
    // range becomes lifetime-unavailable must not treat the scheduled object
    // as settled or rotate its object-level carrier cursor.
    let services = control_test_services(if discontinuity {
        [0x76; 32]
    } else {
        [0x75; 32]
    });
    let authority = services.member.mission_authority_id();
    let source_root = root(&format!(
        "stream-receiver-lifecycle-source-{discontinuity}"
    ));
    let receiver_root = root(&format!(
        "stream-receiver-lifecycle-receiver-{discontinuity}"
    ));
    fs::create_dir_all(&source_root).unwrap();
    fs::create_dir_all(&receiver_root).unwrap();
    let source_store =
        Arc::new(Store::open_for_mission(source_root.join(STORE_FILE), authority).unwrap());
    let receiver_store =
        Arc::new(Store::open_for_mission(receiver_root.join(STORE_FILE), authority).unwrap());
    let transfer = publish_test_finite_blob(
        &source_store,
        &mut open_test_sealer(&services.member),
        &services.topic,
        &services.scope,
        1,
        &[0x75; 192 * 1024],
        600_000,
        25,
        CustodySample {
            clock_id: [0xb1; 16],
            tick_ms: 0,
        },
    );
    let interests = || {
        MutableSourceInterests::default().with_blob(vec![SourceInterestSelector::new(
            services.topic.clone(),
            services.scope.clone(),
            false,
        )])
    };
    let fault = blob_ranges_stream_test::install_boundary(
        &source_store,
        &receiver_store,
        false,
        StreamBoundary::SenderLifecycle,
    );
    let receiver_cache = test_event_route_cache(&receiver_store, &services.other);
    let transfer_task = tokio::spawn({
        let source_store = Arc::clone(&source_store);
        let receiver_store = Arc::clone(&receiver_store);
        let source_mission = services.member.clone();
        let receiver_mission = services.other.clone();
        let source_cache = test_event_route_cache(&source_store, &source_mission);
        let receiver_cache = Arc::clone(&receiver_cache);
        let source_interests = interests();
        let receiver_interests = interests();
        async move {
            blob_contact_test_pair_with_caches_results(
                source_store,
                source_mission,
                source_interests,
                source_cache,
                receiver_store,
                receiver_mission,
                receiver_interests,
                receiver_cache,
                None,
                None,
                None,
                None,
                0,
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        fault.sender_paused.notified().await;
        fault.receiver_paused.notified().await;
    })
    .await
    .expect("first finite range reaches both live stream boundaries");
    assert_eq!(
        receiver_store
            .blob_carrier_fetch_cursor(services.member.identity())
            .unwrap(),
        None,
        "accepted prefix is not an object-level terminal outcome"
    );
    let transition = if discontinuity {
        CustodySample {
            clock_id: [0x32; 16],
            tick_ms: 0,
        }
    } else {
        CustodySample {
            clock_id: BLOB_CONTACT_TEST_CLIENT_CLOCK_ID,
            tick_ms: 1_000_000,
        }
    };
    receiver_store
        .test_observe_blob_custody_sample(transition)
        .expect("observe receiver lifetime transition between ranges");
    fault.release_sender.notify_one();
    fault.release_receiver.notify_one();
    let (client_result, server_result) =
        tokio::time::timeout(Duration::from_secs(15), transfer_task)
            .await
            .expect("lifetime-unavailable receiver drains its bounded stream")
            .unwrap();
    assert!(
        client_result.is_ok() && server_result.is_ok(),
        "authenticated remainder and terminal must drain normally: client={client_result:?}, server={server_result:?}"
    );
    assert_eq!(
        receiver_store
            .blob_carrier_fetch_cursor(services.member.identity())
            .unwrap(),
        None,
        "lifetime-unsettled scheduled work cannot rotate the carrier cursor"
    );
    assert!(receiver_store.get_blob(transfer).unwrap().is_none());
    assert!(
        !matches!(
            receiver_store.custody_v1_pending_blob_source(transfer),
            Ok(Some(_))
        ),
        "expired or indeterminate pending work is not contact-visible"
    );
    if discontinuity {
        assert_eq!(
            receiver_store.blob_stats().unwrap().pending_sources,
            1,
            "continuity loss hides but does not retire the pending source"
        );
        assert!(receiver_cache.has_blob_claim_for_test(transfer));
    } else {
        assert_eq!(
            receiver_store.blob_stats().unwrap().pending_sources,
            0,
            "proven expiry retires the exact pending source immediately"
        );
    }
    blob_ranges_stream_test::remove(&source_store);
    blob_ranges_stream_test::remove(&receiver_store);
    drop((source_store, receiver_store));
    fs::remove_dir_all(source_root).unwrap();
    fs::remove_dir_all(receiver_root).unwrap();
}

#[tokio::test]
async fn blob_ranges_stream_sender_stops_service_after_mid_schedule_lifetime_loss() {
    // Mutation caught: continuing to call the exact range service helper after
    // one lifecycle-unavailable result can re-enter retired/indeterminate
    // custody state and serve a later scheduled range after the boundary.
    for discontinuity in [false, true] {
        let services = control_test_services(if discontinuity {
            [0x74; 32]
        } else {
            [0x73; 32]
        });
        let authority = services.member.mission_authority_id();
        let source_root = root(&format!("stream-sender-lifecycle-source-{discontinuity}"));
        let receiver_root = root(&format!("stream-sender-lifecycle-receiver-{discontinuity}"));
        fs::create_dir_all(&source_root).unwrap();
        fs::create_dir_all(&receiver_root).unwrap();
        let source_store = Arc::new(
            Store::open_for_mission(source_root.join(STORE_FILE), authority).unwrap(),
        );
        let receiver_store = Arc::new(
            Store::open_for_mission(receiver_root.join(STORE_FILE), authority).unwrap(),
        );
        let source_sample = CustodySample {
            clock_id: [0xb1; 16],
            tick_ms: 0,
        };
        let transfer = publish_test_finite_blob(
            &source_store,
            &mut open_test_sealer(&services.member),
            &services.topic,
            &services.scope,
            1,
            &[0x73; 192 * 1024],
            600_000,
            25,
            source_sample,
        );
        let interests = || {
            MutableSourceInterests::default().with_blob(vec![SourceInterestSelector::new(
                services.topic.clone(),
                services.scope.clone(),
                false,
            )])
        };
        let fault = blob_ranges_stream_test::install_boundary(
            &source_store,
            &receiver_store,
            false,
            StreamBoundary::SenderLifecycle,
        );
        let transfer_task = tokio::spawn({
            let source_store = Arc::clone(&source_store);
            let receiver_store = Arc::clone(&receiver_store);
            let source_mission = services.member.clone();
            let receiver_mission = services.other.clone();
            let interests = interests();
            async move {
                blob_contact_test_pair(
                    source_store,
                    source_mission,
                    interests.clone(),
                    receiver_store,
                    receiver_mission,
                    interests,
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            fault.sender_paused.notified().await;
            fault.receiver_paused.notified().await;
        })
        .await
        .expect("first finite range reaches both live sender and receiver boundaries");
        assert_eq!(
            fault.sender_service_attempts.load(Ordering::Acquire),
            1,
            "exactly the first range passed its lifecycle boundary"
        );
        assert!(
            fault.sender_schedule_ranges.load(Ordering::Acquire) > 2,
            "fixture must retain at least one scheduled range after unavailability"
        );

        let transition = if discontinuity {
            CustodySample {
                clock_id: [0x31; 16],
                tick_ms: 0,
            }
        } else {
            CustodySample {
                tick_ms: 1_000_000,
                ..source_sample
            }
        };
        source_store
            .test_observe_blob_custody_sample(transition)
            .expect("observe sender lifetime transition between ranges");
        if !discontinuity {
            for _ in 0..8 {
                source_store
                    .run_blob_maintenance_turn(blob_maintenance_runtime_budget())
                    .expect("retire proven-expired finite publication");
                if matches!(
                    source_store.get_blob(transfer),
                    Ok(None) | Err(StoreError::Blob(BlobStoreError::ExpiredOrRetired))
                ) {
                    break;
                }
            }
            assert!(
                matches!(
                    source_store.get_blob(transfer),
                    Ok(None) | Err(StoreError::Blob(BlobStoreError::ExpiredOrRetired))
                ),
                "proven expiry retires the exact finite publication"
            );
        } else {
            assert_eq!(
                source_store.blob_stats().unwrap().publications,
                1,
                "continuity loss stays retained and must not be falsely retired"
            );
        }
        fault.release_sender.notify_one();
        fault.release_receiver.notify_one();
        let (receiver_receipt, _, _, _) =
            tokio::time::timeout(Duration::from_secs(15), transfer_task)
            .await
            .expect("lifecycle-unavailable stream drains its authenticated schedule")
            .unwrap();
        assert_eq!(receiver_receipt.blob_ranges_fetched, 1);
        assert_eq!(
            fault.sender_service_attempts.load(Ordering::Acquire),
            2,
            "the first unavailable range must suppress every later service attempt"
        );
        assert!(
            receiver_store.pending_blob_source(transfer).unwrap().is_some(),
            "the receiver retains only its accepted prefix and pending authority"
        );
        blob_ranges_stream_test::remove(&source_store);
        blob_ranges_stream_test::remove(&receiver_store);
        drop(source_store);
        drop(receiver_store);
        fs::remove_dir_all(source_root).unwrap();
        fs::remove_dir_all(receiver_root).unwrap();
    }
}

async fn stream_live_boundary(boundary: StreamBoundary) {
    let services = control_test_services([0x71; 32]);
    let a = services.member.clone();
    let b = services.other.clone();
    let authority = a.mission_authority_id();
    let topic = services.topic.clone();
    let scope = services.scope.clone();
    let interests = || {
        MutableSourceInterests::default().with_blob(vec![SourceInterestSelector::new(
            topic.clone(),
            scope.clone(),
            false,
        )])
    };
    let ar = root(&format!("stream-live-a-{boundary:?}"));
    let br = root(&format!("stream-live-b-{boundary:?}"));
    fs::create_dir_all(&ar).unwrap();
    fs::create_dir_all(&br).unwrap();
    let a_store = Arc::new(Store::open_for_mission(ar.join(STORE_FILE), authority).unwrap());
    let mut b_store = Arc::new(Store::open_for_mission(br.join(STORE_FILE), authority).unwrap());
    let plaintext = vec![0x36; 96 * 1024];
    let source = publish_test_blob(
        &a_store,
        &mut open_test_sealer(&a),
        &topic,
        &scope,
        1,
        &plaintext,
    );
    let plan = completed_test_blob_plan(&a_store, &mut open_test_sealer(&a), source);
    let total: u64 = plan
        .carrier_ids()
        .map(|id| plan.carrier_total_len(&id.wire_bytes()).unwrap())
        .sum();
    let prefix = |store: &Store| -> u64 {
        plan.carrier_ids()
            .filter_map(|id| {
                store
                    .blob_carrier_prefix_status(
                        source,
                        BlobCarrierObjectId::new(id.wire_bytes()).unwrap(),
                    )
                    .unwrap()
            })
            .map(|s| s.prefix_len())
            .sum()
    };
    let fault = blob_ranges_stream_test::install_boundary(&a_store, &b_store, false, boundary);
    if boundary == StreamBoundary::BadTerminalAad {
        // This case observes the fully received prefix after terminal
        // authentication fails; it does not need an interactive mid-range
        // pause, but pre-releases the shared harness gates.
        fault.release_sender.notify_one();
        fault.release_receiver.notify_one();
    }
    let transfer = tokio::spawn({
        let sa = a_store.clone();
        let sb = b_store.clone();
        let a = a.clone();
        let b = b.clone();
        let interests = interests();
        async move { blob_contact_test_pair(sa, a, interests.clone(), sb, b, interests).await }
    });
    if boundary != StreamBoundary::BadTerminalAad {
        tokio::time::timeout(Duration::from_secs(10), async {
            fault.sender_paused.notified().await;
            fault.receiver_paused.notified().await;
        })
        .await
        .expect("controlled live boundary reached before terminal");
        if boundary == StreamBoundary::LostTerminal {
            assert_eq!(prefix(&b_store), total);
            assert!(
                b_store.get_blob(source).unwrap().is_none(),
                "complete prefix must not publish before an authenticated terminal"
            );
        } else {
            assert_eq!(prefix(&b_store), MAX_BLOB_NETWORK_RANGE_BYTES as u64);
            assert!(b_store.get_blob(source).unwrap().is_none());
        }
        if boundary == StreamBoundary::Revocation {
            let mut authority = open_test_sealer(&services.authority);
            let revocation = authority
                .seal_chained_revocation_control(a.identity(), 1, 1, None)
                .unwrap();
            let id = ControlTransferId::new(
                authority
                    .verify_control(&revocation)
                    .unwrap()
                    .envelope_id(),
            );
            accept_received_control(
                &b_store,
                &mut open_test_sealer(&b),
                services.authority.identity(),
                id,
                &revocation,
            )
            .unwrap();
            assert!(b_store.is_control_principal_revoked(a.identity()).unwrap());
        }
        fault.release_sender.notify_one();
        fault.release_receiver.notify_one();
    }
    let result = tokio::time::timeout(Duration::from_secs(15), transfer)
        .await
        .expect("contact exits at injected boundary");
    assert!(
        fault.fired.load(Ordering::Acquire),
        "requested live fault actually fired"
    );
    if matches!(
        boundary,
        StreamBoundary::AppendCapacity | StreamBoundary::UnavailableGap
    ) {
        assert!(
            result.is_ok(),
            "typed no-progress drains its bounded turn without a gap append"
        );
    } else {
        let error = match &result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("fault must reject contact, not settle"),
        };
        let expected = match boundary {
            StreamBoundary::BadAead | StreamBoundary::WrongAad => "envelope authentication failed",
            StreamBoundary::Revocation => "Revoked(",
            StreamBoundary::LostTerminal => "injected lost terminal after complete prefix",
            StreamBoundary::AppendCapacityLostTerminal => "connection lost",
            StreamBoundary::BadTerminalAad => "envelope authentication failed",
            _ => unreachable!(),
        };
        assert!(error.contains(expected), "wrong rejection: {error}");
    }
    if boundary == StreamBoundary::AppendCapacity {
        assert_eq!(result.as_ref().unwrap().0.blob_deferred, 1);
    }
    let cursor_after_turn = b_store
        .blob_carrier_fetch_cursor(a.identity())
        .unwrap();
    if boundary == StreamBoundary::AppendCapacity {
        assert!(cursor_after_turn.is_some(), "valid terminal authorizes source rotation");
    } else {
        assert_eq!(
            cursor_after_turn, None,
            "failed, unavailable, or lifecycle-unsettled work is cursor-neutral"
        );
    }
    blob_ranges_stream_test::remove(&a_store);
    blob_ranges_stream_test::remove(&b_store);
    tokio::time::timeout(Duration::from_secs(10), async {
        while Arc::strong_count(&a_store) != 1 || Arc::strong_count(&b_store) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    if boundary != StreamBoundary::LostTerminal {
        let expected_prefix = if boundary == StreamBoundary::BadTerminalAad {
            total
        } else {
            MAX_BLOB_NETWORK_RANGE_BYTES as u64
        };
        assert_eq!(
            prefix(&b_store),
            expected_prefix,
            "first durable prefix survives later rejection"
        );
    }
    if boundary == StreamBoundary::AppendCapacity {
        assert_eq!(
            b_store
                .blob_carrier_fetch_cursor(a.identity())
                .unwrap()
                .unwrap()
                .source(),
            source,
            "capacity advances scheduling, not bytes"
        );
    }
    drop(b_store);
    b_store = Arc::new(Store::open_for_mission(br.join(STORE_FILE), authority).unwrap());
    if boundary == StreamBoundary::Revocation {
        assert_eq!(prefix(&b_store), MAX_BLOB_NETWORK_RANGE_BYTES as u64);
        assert!(b_store.get_blob(source).unwrap().is_none());
        assert!(b_store.is_control_principal_revoked(a.identity()).unwrap());
    } else {
        if boundary == StreamBoundary::AppendCapacity {
            let second = publish_test_blob(
                &a_store,
                &mut open_test_sealer(&a),
                &topic,
                &scope,
                1,
                &[0x81; 32 * 1024],
            );
            blob_contact_test_pair(
                a_store.clone(),
                a.clone(),
                interests(),
                b_store.clone(),
                b.clone(),
                interests(),
            )
            .await;
            assert!(
                b_store.get_blob(second).unwrap().is_some(),
                "next eligible source is not starved by append capacity"
            );
            assert!(b_store.get_blob(source).unwrap().is_none());
            assert_eq!(prefix(&b_store), MAX_BLOB_NETWORK_RANGE_BYTES as u64);
        }
        let (receipt, _, _, _) = blob_contact_test_pair(
            a_store.clone(),
            a.clone(),
            interests(),
            b_store.clone(),
            b.clone(),
            interests(),
        )
        .await;
        assert_eq!(
            receipt.blob_bytes_fetched as u64,
            if matches!(
                boundary,
                StreamBoundary::LostTerminal | StreamBoundary::BadTerminalAad
            ) {
                0
            } else {
                total - MAX_BLOB_NETWORK_RANGE_BYTES as u64
            }
        );
        assert_eq!(receipt.duplicates, 0);
        let stored = b_store.get_blob(source).unwrap().unwrap();
        let mut sealer = open_test_sealer(&b);
        let route = sealer.verify_blob(&stored.sealed).unwrap();
        let BlobContentVerification::ContentVerified {
            blob,
            manifest_bytes,
        } = sealer.verify_blob_content(route, &stored.sealed).unwrap()
        else {
            panic!("content grant")
        };
        let mut service = sealer
            .blob_service_with_store(&scope, &topic, 1, b_store.blob_depot().unwrap())
            .unwrap();
        service
            .install_verified_manifest(&blob, &manifest_bytes)
            .unwrap();
        let mut output = Vec::new();
        service
            .reader_for_verified(&blob)
            .unwrap()
            .stream_into(&mut output)
            .unwrap();
        assert_eq!(output, plaintext);
    }
    drop(a_store);
    drop(b_store);
    fs::remove_dir_all(ar).unwrap();
    fs::remove_dir_all(br).unwrap();
}
