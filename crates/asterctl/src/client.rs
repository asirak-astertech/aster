use crate::{api, auth::Token, blob_publish, blob_read, operation_key::Key};
use connectrpc::{
    Protocol,
    client::{ClientConfig, Http2Connection, HttpClient, SharedHttp2Connection},
};
use std::{fs::File, net::SocketAddr, path::PathBuf, time::Duration};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

fn rpc_hint(code: connectrpc::ErrorCode) -> &'static str {
    use connectrpc::ErrorCode::*;
    match code {
        Unavailable => {
            "\nCheck that aster-agent is running and that --host and --port are correct."
        }
        Unauthenticated => {
            "\nCheck that the supplied token matches the agent's configured client token."
        }
        PermissionDenied => {
            "\nCheck the permissions for this operation and the requested topic and scope."
        }
        DeadlineExceeded => {
            "\nCheck agent responsiveness; increase --timeout if needed (agent-side limits still apply)."
        }
        _ => "",
    }
}

pub fn describe_rpc_error(method: &str, code: connectrpc::ErrorCode) -> String {
    format!("{method} failed: {}{}", code.as_str(), rpc_hint(code))
}

pub struct MutationError {
    reason: &'static str,
    unknown: bool,
    hint: &'static str,
}

impl MutationError {
    fn rpc(code: connectrpc::ErrorCode) -> Self {
        use connectrpc::ErrorCode::*;
        // These codes reject the request. Other errors may follow a commit,
        // including transport failures, timeouts, and response decoding errors.
        // ResourceExhausted also covers local response-size/decode limits, so
        // its code alone cannot confirm a server rejection.
        let rejected = matches!(
            code,
            InvalidArgument
                | NotFound
                | AlreadyExists
                | PermissionDenied
                | FailedPrecondition
                | Aborted
                | OutOfRange
                | Unimplemented
                | Unauthenticated
        );
        Self {
            reason: code.as_str(),
            unknown: !rejected,
            hint: rpc_hint(code),
        }
    }

    fn unknown(reason: &'static str) -> Self {
        Self {
            reason,
            unknown: true,
            hint: "",
        }
    }

    pub fn describe_unsubscribe(&self) -> String {
        if self.unknown {
            format!(
                "DeleteEventSubscription outcome unknown: {}\nretry unsubscribe with the same subscription ID",
                self.reason
            )
        } else {
            format!(
                "DeleteEventSubscription failed: {}{}",
                self.reason, self.hint
            )
        }
    }

    pub fn describe(&self, method: &str, key: &Key) -> String {
        if self.unknown {
            format!(
                "{method} outcome unknown: {}{}\n{}",
                self.reason,
                self.hint,
                key.retry_instruction()
            )
        } else {
            format!("{method} failed: {}{}", self.reason, self.hint)
        }
    }
}

pub fn query_client(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
) -> api::AsterApplicationServiceClient<HttpClient> {
    api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        config(address, token, timeout),
    )
}

pub async fn query(
    client: &api::AsterApplicationServiceClient<HttpClient>,
    request: &api::QueryEventsRequest,
    timeout: Duration,
) -> Result<api::QueryEventsResponse, connectrpc::ErrorCode> {
    let response = tokio::time::timeout(timeout, client.query_events(request.clone()))
        .await
        .map_err(|_| connectrpc::ErrorCode::DeadlineExceeded)?
        .map_err(|error| error.code)?;
    Ok(response.into_owned())
}

fn config(address: SocketAddr, token: &Token, timeout: Duration) -> ClientConfig {
    protocol_config(address, token, timeout, Protocol::Connect)
}

fn protocol_config(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
    protocol: Protocol,
) -> ClientConfig {
    ClientConfig::new(
        format!("http://{address}")
            .parse()
            .expect("socket address URI"),
    )
    .with_protocol(protocol)
    .with_default_header(http::header::AUTHORIZATION, token.header())
    .with_default_timeout(timeout)
    .with_default_max_message_size(4 * 1024 * 1024)
    .with_default_element_memory_limit(4 * 1024 * 1024)
}

fn blob_client(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
) -> api::AsterApplicationServiceClient<SharedHttp2Connection> {
    let uri = format!("http://{address}")
        .parse()
        .expect("socket address URI");
    let transport = Http2Connection::lazy_plaintext(uri).shared(1);
    api::AsterApplicationServiceClient::new(
        transport,
        protocol_config(address, token, timeout, Protocol::Grpc),
    )
}

pub async fn status(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
) -> Result<api::GetStatusResponse, String> {
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        config(address, token, timeout),
    );
    let response =
        tokio::time::timeout(timeout, client.get_status(api::GetStatusRequest::default()))
            .await
            .map_err(|_| describe_rpc_error("GetStatus", connectrpc::ErrorCode::DeadlineExceeded))?
            // A remote server can put arbitrary text, including credentials, into
            // error messages. Report only the protocol's fixed error code.
            .map_err(|error| describe_rpc_error("GetStatus", error.code))?;
    Ok(response.into_owned())
}

pub async fn publish(
    address: SocketAddr,
    token: &Token,
    request: api::PublishEventRequest,
    timeout: Duration,
) -> Result<api::PublishEventResponse, MutationError> {
    let ttl_ms = request.ttl_ms;
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        config(address, token, timeout),
    );
    let response = tokio::time::timeout(timeout, client.publish_event(request))
        .await
        .map_err(|_| MutationError::rpc(connectrpc::ErrorCode::DeadlineExceeded))?
        .map_err(|error| MutationError::rpc(error.code))?;
    let response = response.into_owned();
    if response.id.len() != 32 || response.publisher.len() != 32 {
        return Err(MutationError::unknown("invalid publication receipt"));
    }
    if ttl_ms.is_some() && response.ttl_ms != ttl_ms {
        return Err(MutationError::unknown(
            "agent did not confirm the requested TTL",
        ));
    }
    Ok(response)
}

pub async fn publish_blob(
    address: SocketAddr,
    token: &Token,
    metadata: api::PublishBlobMetadata,
    file: File,
    timeout: Duration,
) -> Result<api::PublishBlobResponse, MutationError> {
    let requested = metadata.clone();
    let (frames, reader) = blob_publish::stream_file(metadata, file);
    let result = blob_client(address, token, timeout)
        .publish_blob(frames)
        .await;
    let read_result = reader.await.map_err(|_| {
        MutationError::unknown("source reader failed while request may have been sent")
    })?;
    if let Err(reason) = read_result {
        return Err(MutationError::unknown(reason));
    }
    let response = result
        .map_err(|error| MutationError::rpc(error.code))?
        .into_owned();
    if !blob_publish::receipt_matches(&requested, &response) {
        return Err(MutationError::unknown("invalid publication receipt"));
    }
    Ok(response)
}

pub async fn read_blob(
    address: SocketAddr,
    token: &Token,
    request: api::ReadBlobRequest,
    output_path: PathBuf,
    timeout: Duration,
) -> Result<blob_read::Metadata, String> {
    let mut output = blob_read::OutputFile::create(output_path).map_err(str::to_owned)?;
    let mut validator = blob_read::Validator::new(request.clone());
    let transfer = async {
        let mut stream = blob_client(address, token, timeout)
            .read_blob(request)
            .await
            .map_err(|error| describe_rpc_error("ReadBlob", error.code))?;
        while let Some(page) = stream
            .message()
            .await
            .map_err(|error| describe_rpc_error("ReadBlob", error.code))?
        {
            let page = page.to_owned_message();
            validator.accept(&page).map_err(str::to_owned)?;
            output.write_page(&page.chunk).map_err(str::to_owned)?;
        }
        validator.finish().map_err(str::to_owned)
    }
    .await;
    match transfer {
        Ok(metadata) => match output.finish() {
            Ok(()) => Ok(metadata),
            Err(error) => Err(discard_output(output, error.to_owned())),
        },
        Err(error) => Err(discard_output(output, error)),
    }
}

fn discard_output(output: blob_read::OutputFile, error: String) -> String {
    drop(output);
    error
}

pub async fn unsubscribe(
    address: SocketAddr,
    token: &Token,
    subscription_id: Vec<u8>,
    timeout: Duration,
) -> Result<api::DeleteEventSubscriptionResponse, MutationError> {
    let client = query_client(address, token, timeout);
    let response = tokio::time::timeout(
        timeout,
        client.delete_event_subscription(api::DeleteEventSubscriptionRequest {
            subscription_id,
            ..Default::default()
        }),
    )
    .await
    .map_err(|_| MutationError::rpc(connectrpc::ErrorCode::DeadlineExceeded))?
    .map_err(|e| MutationError::rpc(e.code))?;
    Ok(response.into_owned())
}

pub async fn subscriptions(
    address: SocketAddr,
    token: &Token,
    timeout: Duration,
) -> Result<api::ListEventSubscriptionsResponse, String> {
    let client = query_client(address, token, timeout);
    let response = tokio::time::timeout(
        timeout,
        client.list_event_subscriptions(api::ListEventSubscriptionsRequest::default()),
    )
    .await
    .map_err(|_| {
        describe_rpc_error(
            "ListEventSubscriptions",
            connectrpc::ErrorCode::DeadlineExceeded,
        )
    })?
    .map_err(|error| describe_rpc_error("ListEventSubscriptions", error.code))?;
    let response = response.into_owned();
    if response
        .subscriptions
        .iter()
        .any(|row| row.subscription_id.len() != 32)
    {
        return Err("ListEventSubscriptions failed: invalid subscription ID".to_owned());
    }
    Ok(response)
}

pub async fn subscribe(
    address: SocketAddr,
    token: &Token,
    request: api::CreateEventSubscriptionRequest,
    timeout: Duration,
) -> Result<api::CreateEventSubscriptionResponse, MutationError> {
    let client = api::AsterApplicationServiceClient::new(
        HttpClient::plaintext(),
        config(address, token, timeout),
    );
    let response = tokio::time::timeout(timeout, client.create_event_subscription(request))
        .await
        .map_err(|_| MutationError::rpc(connectrpc::ErrorCode::DeadlineExceeded))?
        .map_err(|error| MutationError::rpc(error.code))?;
    let response = response.into_owned();
    if response.subscription_id.len() != 32 {
        return Err(MutationError::unknown("invalid subscription ID"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::poll_fn,
        sync::{Arc, Mutex},
    };

    const SERVICE: &str = "aster.application.v1alpha1.AsterApplicationService";

    struct Fixture {
        address: SocketAddr,
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Fixture {
        async fn start(router: connectrpc::Router) -> Self {
            let bound = connectrpc::server::Server::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = bound.local_addr().unwrap();
            let (shutdown, stopped) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                bound
                    .serve_with_graceful_shutdown(router, async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
            Self {
                address,
                shutdown: Some(shutdown),
                task,
            }
        }

        async fn stop(mut self) {
            let _ = self.shutdown.take().unwrap().send(());
            self.task.await.unwrap();
        }
    }

    fn token() -> Token {
        Token::parse("asterctl-test-token-00000000000000".to_owned()).unwrap()
    }

    fn publish_metadata(total_len: u64) -> api::PublishBlobMetadata {
        api::PublishBlobMetadata {
            operation_key: b"native-http2-fixture".to_vec(),
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            priority: api::Priority::Immediate.into(),
            ttl_ms: Some(60_000),
            total_len,
            media_type: Some("application/octet-stream".into()),
            schema_id: b"schema".to_vec(),
            ..Default::default()
        }
    }

    fn receipt(metadata: &api::PublishBlobMetadata) -> api::PublishBlobResponse {
        api::PublishBlobResponse {
            id: vec![1; 32],
            publisher: vec![2; 32],
            publisher_counter: 3,
            priority: metadata.priority,
            ttl_ms: metadata.ttl_ms,
            total_len: metadata.total_len,
            media_type: metadata.media_type.clone(),
            schema_id: metadata.schema_id.clone(),
            acceptance_marker: 4,
            inserted: true,
            ..Default::default()
        }
    }

    fn read_page(offset: u64, chunk: Vec<u8>, complete: bool) -> api::ReadBlobResponse {
        api::ReadBlobResponse {
            id: vec![1; 32],
            publisher: vec![2; 32],
            publisher_counter: 3,
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            priority: api::Priority::Immediate.into(),
            ttl_ms: Some(60_000),
            total_len: (blob_publish::CHUNK_BYTES + 1) as u64,
            media_type: Some("application/octet-stream".into()),
            schema_id: b"schema".to_vec(),
            acceptance_marker: 4,
            offset,
            chunk,
            complete,
            ..Default::default()
        }
    }

    fn test_path(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "asterctl-native-http2-{}-{suffix}",
            std::process::id()
        ))
    }

    #[test]
    fn blob_unknown_outcome_prints_exact_operation_key_retry_guidance() {
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        assert_eq!(
            MutationError::unknown("invalid publication receipt").describe("PublishBlob", &key),
            "PublishBlob outcome unknown: invalid publication receipt\nretry the identical request with --operation-key=blob-key"
        );
    }

    #[tokio::test]
    async fn blob_native_http2_fixture_covers_multi_page_publish_and_read_clients() {
        let payload = vec![0x5a; blob_publish::CHUNK_BYTES + 1];
        let metadata = publish_metadata(payload.len() as u64);
        let expected_receipt = receipt(&metadata);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let observed_by_handler = Arc::clone(&observed);
        let publish_response = expected_receipt.clone();
        let router = connectrpc::Router::new()
            .route_client_stream(
                SERVICE,
                "PublishBlob",
                connectrpc::client_streaming_handler_fn(
                    move |_ctx, mut requests: connectrpc::ServiceStream<api::PublishBlobRequest>| {
                        let observed = Arc::clone(&observed_by_handler);
                        let response = publish_response.clone();
                        async move {
                            let mut frames = Vec::new();
                            while let Some(frame) =
                                poll_fn(|context| requests.as_mut().poll_next(context)).await
                            {
                                frames.push(frame?);
                            }
                            *observed.lock().unwrap() = frames;
                            Ok::<_, connectrpc::ConnectError>(connectrpc::Response::new(response))
                        }
                    },
                ),
            )
            .route_server_stream(
                SERVICE,
                "ReadBlob",
                connectrpc::streaming_handler_fn(
                    |_ctx, _request: api::ReadBlobRequest| async move {
                        connectrpc::Response::stream_ok(connectrpc::stream_iter([
                            Ok(read_page(
                                0,
                                vec![0x5a; blob_publish::CHUNK_BYTES],
                                false,
                            )),
                            Ok(read_page(blob_publish::CHUNK_BYTES as u64, vec![0x5a], true)),
                        ]))
                    },
                ),
            );
        let fixture = Fixture::start(router).await;
        let source = test_path("source");
        let destination = test_path("destination");
        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_file(&destination);
        std::fs::write(&source, &payload).unwrap();

        let response = match publish_blob(
            fixture.address,
            &token(),
            metadata,
            File::open(&source).unwrap(),
            Duration::from_secs(2),
        )
        .await
        {
            Ok(response) => response,
            Err(error) => panic!(
                "{}",
                error.describe(
                    "PublishBlob",
                    &crate::operation_key::Selection::Explicit("native-http2-fixture".to_owned())
                        .resolve()
                        .unwrap()
                )
            ),
        };
        assert_eq!(response, expected_receipt);
        {
            let frames = observed.lock().unwrap();
            assert_eq!(frames.len(), 3);
            assert!(matches!(
                frames[0].frame,
                Some(api::publish_blob_request::Frame::Metadata(_))
            ));
            assert!(matches!(
                frames[1].frame.as_ref(),
                Some(api::publish_blob_request::Frame::Chunk(chunk))
                    if chunk.len() == blob_publish::CHUNK_BYTES
            ));
            assert!(matches!(
                frames[2].frame.as_ref(),
                Some(api::publish_blob_request::Frame::Chunk(chunk)) if chunk.len() == 1
            ));
        }

        let request = api::ReadBlobRequest {
            id: vec![1; 32],
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            ..Default::default()
        };
        let read = read_blob(
            fixture.address,
            &token(),
            request,
            destination.clone(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(read.total_len, payload.len() as u64);
        assert_eq!(std::fs::read(&destination).unwrap(), payload);

        fixture.stop().await;
        std::fs::remove_file(source).unwrap();
        std::fs::remove_file(destination).unwrap();
    }

    async fn publish_error(code: connectrpc::ErrorCode) -> MutationError {
        let router = connectrpc::Router::new().route_client_stream(
            SERVICE,
            "PublishBlob",
            connectrpc::client_streaming_handler_fn(
                move |_ctx, _requests: connectrpc::ServiceStream<api::PublishBlobRequest>| async move {
                    Err::<connectrpc::Response<api::PublishBlobResponse>, _>(
                        connectrpc::ConnectError::new(code, "secret fixture detail"),
                    )
                },
            ),
        );
        let fixture = Fixture::start(router).await;
        let source = test_path("error-source");
        let _ = std::fs::remove_file(&source);
        std::fs::write(&source, b"x").unwrap();
        let error = publish_blob(
            fixture.address,
            &token(),
            publish_metadata(1),
            File::open(&source).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        fixture.stop().await;
        std::fs::remove_file(source).unwrap();
        error
    }

    #[tokio::test]
    async fn blob_native_http2_fixture_preserves_rpc_error_and_unknown_outcome_classification() {
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        let rejected = publish_error(connectrpc::ErrorCode::InvalidArgument).await;
        assert_eq!(
            rejected.describe("PublishBlob", &key),
            "PublishBlob failed: invalid_argument"
        );
        let uncertain = publish_error(connectrpc::ErrorCode::Unavailable).await;
        assert_eq!(
            uncertain.describe("PublishBlob", &key),
            "PublishBlob outcome unknown: unavailable\nCheck that aster-agent is running and that --host and --port are correct.\nretry the identical request with --operation-key=blob-key"
        );
    }

    #[tokio::test]
    async fn blob_native_http2_fixture_classifies_client_deadline_as_unknown() {
        let router = connectrpc::Router::new().route_client_stream(
            SERVICE,
            "PublishBlob",
            connectrpc::client_streaming_handler_fn(
                |_ctx, _requests: connectrpc::ServiceStream<api::PublishBlobRequest>| async move {
                    std::future::pending::<()>().await;
                    Ok::<_, connectrpc::ConnectError>(connectrpc::Response::new(
                        api::PublishBlobResponse::default(),
                    ))
                },
            ),
        );
        let fixture = Fixture::start(router).await;
        let source = test_path("deadline-source");
        let _ = std::fs::remove_file(&source);
        std::fs::write(&source, b"x").unwrap();
        let error = publish_blob(
            fixture.address,
            &token(),
            publish_metadata(1),
            File::open(&source).unwrap(),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        let key = crate::operation_key::Selection::Explicit("blob-key".into())
            .resolve()
            .unwrap();
        let description = error.describe("PublishBlob", &key);
        assert!(description.contains("PublishBlob outcome unknown: deadline_exceeded"));
        assert!(description.contains("--operation-key=blob-key"));
        fixture.stop().await;
        std::fs::remove_file(source).unwrap();
    }

    #[tokio::test]
    async fn blob_native_http2_read_error_discards_anonymous_partial_output() {
        let router = connectrpc::Router::new().route_server_stream(
            SERVICE,
            "ReadBlob",
            connectrpc::streaming_handler_fn(|_ctx, _request: api::ReadBlobRequest| async move {
                connectrpc::Response::stream_ok(connectrpc::stream_iter([
                    Ok(read_page(0, vec![0x5a; blob_publish::CHUNK_BYTES], false)),
                    Err(connectrpc::ConnectError::unavailable(
                        "secret fixture detail",
                    )),
                ]))
            }),
        );
        let fixture = Fixture::start(router).await;
        let destination = test_path("partial-destination");
        let _ = std::fs::remove_file(&destination);
        let request = api::ReadBlobRequest {
            id: vec![1; 32],
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            ..Default::default()
        };
        let error = read_blob(
            fixture.address,
            &token(),
            request,
            destination.clone(),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert!(error.contains("ReadBlob failed: unavailable"), "{error}");
        assert!(!error.contains("secret fixture detail"), "{error}");
        assert!(!destination.exists());
        let parent = destination.parent().unwrap();
        assert!(std::fs::read_dir(parent).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&format!(".asterctl-blob-{}-", std::process::id()))
        }));
        fixture.stop().await;
    }

    #[tokio::test]
    async fn blob_native_http2_read_failure_leaves_no_named_partial_or_unrelated_damage() {
        let directory = test_path("cleanup-directory");
        let destination = directory.join("destination");
        let unrelated = directory.join("unrelated");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(&unrelated, b"unrelated contents").unwrap();
        let directory_by_handler = directory.clone();
        let router = connectrpc::Router::new().route_server_stream(
            SERVICE,
            "ReadBlob",
            connectrpc::streaming_handler_fn(move |_ctx, _request: api::ReadBlobRequest| {
                let directory = directory_by_handler.clone();
                async move {
                    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
                    connectrpc::Response::stream_ok(connectrpc::stream_iter([Err::<
                        api::ReadBlobResponse,
                        _,
                    >(
                        connectrpc::ConnectError::unavailable("fixture failure"),
                    )]))
                }
            }),
        );
        let fixture = Fixture::start(router).await;
        let request = api::ReadBlobRequest {
            id: vec![1; 32],
            topic: "imagery.maps".into(),
            scope: "mission/team/alpha".into(),
            ..Default::default()
        };
        let error = read_blob(
            fixture.address,
            &token(),
            request,
            destination.clone(),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert!(error.contains("ReadBlob failed: unavailable"), "{error}");
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"unrelated contents");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);

        fixture.stop().await;
        std::fs::remove_dir_all(directory).unwrap();
    }
}
