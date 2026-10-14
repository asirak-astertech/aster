use super::blob_ranges_stream_test::Boundary as StreamBoundary;

#[tokio::test]
async fn blob_ranges_stream_live_lost_terminal_after_publication_reopens_without_refetch() {
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
async fn blob_ranges_stream_live_unavailable_gap_does_not_erase_prefix() {
    stream_live_boundary(StreamBoundary::UnavailableGap).await;
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
    let transfer = tokio::spawn({
        let sa = a_store.clone();
        let sb = b_store.clone();
        let a = a.clone();
        let b = b.clone();
        let interests = interests();
        async move { blob_contact_test_pair(sa, a, interests.clone(), sb, b, interests).await }
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        fault.sender_paused.notified().await;
        fault.receiver_paused.notified().await;
    })
    .await
    .expect("controlled live boundary reached before terminal");
    if boundary == StreamBoundary::LostTerminal {
        assert!(
            b_store.get_blob(source).unwrap().is_some(),
            "publication committed before lost terminal"
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
        let id =
            ControlTransferId::new(authority.verify_control(&revocation).unwrap().envelope_id());
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
            StreamBoundary::LostTerminal => "injected lost terminal after publication",
            _ => unreachable!(),
        };
        assert!(error.contains(expected), "wrong rejection: {error}");
    }
    if boundary == StreamBoundary::AppendCapacity {
        assert_eq!(result.as_ref().unwrap().0.blob_deferred, 1);
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
        assert_eq!(
            prefix(&b_store),
            MAX_BLOB_NETWORK_RANGE_BYTES as u64,
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
            if boundary == StreamBoundary::LostTerminal {
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
