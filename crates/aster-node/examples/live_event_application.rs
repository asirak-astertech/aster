use std::{env, error::Error, net::SocketAddr, path::PathBuf, time::Duration};

use aster_node::{
    NodeApplication, NodeConfig,
    application::{
        EventGapQuery, EventPollRequest, EventPublishRequest, EventQuery, EventSubscriptionRequest,
        Priority, Scope, Topic,
    },
    mission::UnprotectedReferenceMission,
    start_node,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "live_event_application".into());
    let Some(state) = arguments.next().map(PathBuf::from) else {
        return Err(usage(&program).into());
    };
    let Some(mission_bundle) = arguments.next().map(PathBuf::from) else {
        return Err(usage(&program).into());
    };
    let Some(scope) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return Err(usage(&program).into());
    };
    let Some(topic) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return Err(usage(&program).into());
    };
    if arguments.next().is_some() {
        return Err(usage(&program).into());
    }
    let scope = Scope::new(scope)?;
    let topic = Topic::new(topic)?;
    let mission = UnprotectedReferenceMission::load(mission_bundle)?;
    let running = start_node(NodeConfig {
        state,
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mission,
        peers: Vec::new(),
        mutable_interests: Default::default(),
        sync_interval: Duration::from_millis(250),
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await?;
    let events = running.selected_events();

    let subscription = events
        .subscribe(EventSubscriptionRequest {
            operation_key: b"aster.example.live/receive".to_vec(),
            topic: topic.clone(),
            scope: scope.clone(),
            include_descendant_scopes: false,
        })
        .await?;
    let publication = events
        .publish(EventPublishRequest {
            operation_key: b"aster.example.live/publish".to_vec(),
            predecessor: None,
            topic: topic.clone(),
            scope: scope.clone(),
            priority: Priority::Priority,
            logical_key: b"hello".to_vec(),
            payload: b"hello from the live selected Event API".to_vec(),
            tombstone: false,
        })
        .await?;
    let page = events
        .query(EventQuery {
            publisher: Some(events.identity()),
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            limit: 16,
            ..EventQuery::default()
        })
        .await?;
    let deliveries = events
        .poll(EventPollRequest {
            subscription: subscription.id,
            delivery_limit: 16,
            scan_limit: 16,
        })
        .await?;
    for delivery in &deliveries.deliveries {
        events
            .acknowledge(subscription.id, delivery.event.id)
            .await?;
    }
    let gaps = events
        .gaps(EventGapQuery {
            publisher: events.identity(),
            topic,
            scope,
            after_sequence: 0,
            scan_limit: 16,
        })
        .await?;
    let status = events.status().await?;
    println!(
        "LIVE_EVENT id={} inserted={} query_items={} deliveries={} gaps={} scanned_through={} sync={:?}",
        publication.id,
        publication.inserted,
        page.items.len(),
        deliveries.deliveries.len(),
        gaps.gaps.len(),
        gaps.scanned_through_sequence,
        status.sync,
    );
    events.unsubscribe(subscription.id).await?;
    running.shutdown().await?;
    Ok(())
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} STATE_DIRECTORY MISSION_BUNDLE SCOPE TOPIC\n\
         example: cargo run -p aster-node --example live_event_application -- \
         /tmp/aster-live node.bundle mission/apps ops.alpha"
    )
}
