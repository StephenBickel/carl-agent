use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use carl::acp::{AcpServerConfig, PermissionMode, ServiceAcpServer, read_frame};
use carl::delegates::{ModelId, ReasoningEffort};
use carl::policy::Sha256Digest;
use carl::policy::{ActorId, Frontend};
use carl::runtime::agent_port::{
    AgentCapabilities, AgentContextId, AgentEffectKind, AgentEffectRequest, AgentEpochId,
    AgentEvent, AgentFuture, AgentItem, AgentModel, AgentPort, AgentPortError, AgentProcess,
    AgentRequestId, EffectDecision, ResumeAgentContext, StartAgentContext, StartAgentEpoch,
};
use carl::runtime::task::TaskStatus;
use carl::service::client::TaskServiceClient;
use carl::service::protocol::{
    ServiceCommand, ServiceRequest, ServiceResult, StartTaskCommand, TrustedStartTaskCommand,
};
use carl::service::server::{EndpointErrorCode, OwnedLocalEndpoint, TaskService};
use carl::storage::{Store, TrustedFrontendOwnerInput};
use chrono::Utc;
use serde_json::json;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn local_endpoint_is_owner_private_and_exclusive_before_sqlite() -> TestResult {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    let layout = Layout::new()?;
    let endpoint = OwnedLocalEndpoint::bind(&layout.data).await?;
    let metadata = fs::symlink_metadata(layout.data.join("carl.sock"))?;
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(!layout.data.join("carl.sqlite3").exists());

    let client = tokio::net::UnixStream::connect(layout.data.join("carl.sock")).await?;
    let error = OwnedLocalEndpoint::bind(&layout.data)
        .await
        .expect_err("a second owner must fail");
    assert_eq!(error.code(), EndpointErrorCode::Contended);
    drop(client);
    drop(endpoint);
    assert!(!layout.data.join("carl.sock").exists());
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn local_endpoint_rejects_a_preexisting_symlink_or_regular_file() -> TestResult {
    let layout = Layout::new()?;
    let socket = layout.data.join("carl.sock");
    fs::write(&socket, b"not a socket")?;
    assert_eq!(
        OwnedLocalEndpoint::bind(&layout.data)
            .await
            .expect_err("regular entry must fail")
            .code(),
        EndpointErrorCode::UnsafeEntry
    );
    fs::remove_file(&socket)?;
    std::os::unix::fs::symlink(&layout.workspace, &socket)?;
    assert_eq!(
        OwnedLocalEndpoint::bind(&layout.data)
            .await
            .expect_err("symlink entry must fail")
            .code(),
        EndpointErrorCode::UnsafeEntry
    );
    Ok(())
}

#[cfg(windows)]
#[tokio::test(flavor = "current_thread")]
async fn windows_named_pipe_is_hashed_owner_private_and_exclusive_before_sqlite() -> TestResult {
    let layout = Layout::new()?;
    let endpoint = OwnedLocalEndpoint::bind(&layout.data).await?;
    assert!(endpoint.pipe_name().starts_with(r"\\.\pipe\carl-"));
    assert!(
        !endpoint
            .pipe_name()
            .contains(layout.data.to_string_lossy().as_ref())
    );
    assert!(!layout.data.join("carl.sqlite3").exists());
    let client =
        tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint.pipe_name())?;
    assert_eq!(
        OwnedLocalEndpoint::bind(&layout.data)
            .await
            .expect_err("second Windows owner must fail before SQLite")
            .code(),
        EndpointErrorCode::Contended
    );
    drop(client);
    drop(endpoint);
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn client_eof_does_not_cancel_owner_task_and_controls_are_idempotent() -> TestResult {
    let layout = Layout::new()?;
    let port = PendingPort::new();
    let state = Arc::clone(&port.state);
    let cancellation = CancellationToken::new();
    let service = TaskService::bind(&layout.data, port).await?;
    let service_task = tokio::spawn(service.serve(cancellation));

    let mut first = TaskServiceClient::connect(&layout.data).await?;
    let accepted = first
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "start-1".to_owned(),
            idempotency_key: "start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "owner-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "keep working after the frontend disconnects".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
            }),
        })
        .await
        .map_err(|error| format!("start request failed: {error:?}"))?;
    let ServiceResult::Accepted { task_id } = accepted else {
        return Err("start was not accepted".into());
    };
    drop(first);

    let mut second = TaskServiceClient::connect(&layout.data).await?;
    let active = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let result = second
                .request(ServiceRequest {
                    protocol_version: 1,
                    request_id: format!("status-{}", Uuid::new_v4()),
                    idempotency_key: format!("status-key-{}", Uuid::new_v4()),
                    command: ServiceCommand::Status { task_id },
                })
                .await
                .expect("status request succeeds");
            if let ServiceResult::Snapshot(snapshot) = result
                && snapshot.status == TaskStatus::Active
                && snapshot.active_epoch.is_some()
            {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(active.task_id, task_id);
    assert_eq!(state.lock().unwrap().interrupts, 0);

    for request_id in ["cancel-1", "cancel-2"] {
        assert_eq!(
            second
                .request(ServiceRequest {
                    protocol_version: 1,
                    request_id: request_id.to_owned(),
                    idempotency_key: "cancel-key".to_owned(),
                    command: ServiceCommand::Cancel { task_id },
                })
                .await
                .map_err(|error| format!("cancel request failed: {error:?}"))?,
            ServiceResult::Applied
        );
    }
    assert_eq!(state.lock().unwrap().interrupts, 1);
    assert_eq!(
        second
            .request(ServiceRequest {
                protocol_version: 1,
                request_id: "shutdown-1".to_owned(),
                idempotency_key: "shutdown-key".to_owned(),
                command: ServiceCommand::Shutdown,
            })
            .await
            .map_err(|error| format!("shutdown request failed: {error:?}"))?,
        ServiceResult::Applied
    );
    service_task.await??;
    assert!(state.lock().unwrap().shutdowns >= 1);
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn process_cancellation_checkpoints_and_cancels_the_active_task() -> TestResult {
    let layout = Layout::new()?;
    let port = PendingPort::new();
    let state = Arc::clone(&port.state);
    let cancellation = CancellationToken::new();
    let service = TaskService::bind(&layout.data, port).await?;
    let running = tokio::spawn(service.serve(cancellation.clone()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    let ServiceResult::Accepted { task_id } = client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "signal-start".to_owned(),
            idempotency_key: "signal-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "signal-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "remain durable when the owner process stops".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
            }),
        })
        .await?
    else {
        return Err("signal task was not accepted".into());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ServiceResult::Snapshot(snapshot) = client
                .request(ServiceRequest {
                    protocol_version: 1,
                    request_id: format!("signal-status-{}", Uuid::new_v4()),
                    idempotency_key: format!("signal-status-key-{}", Uuid::new_v4()),
                    command: ServiceCommand::Status { task_id },
                })
                .await
                .expect("signal status succeeds")
            else {
                continue;
            };
            if snapshot.status == TaskStatus::Active && snapshot.active_epoch.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;

    drop(client);
    cancellation.cancel();
    match tokio::time::timeout(Duration::from_secs(5), running).await {
        Ok(joined) => joined??,
        Err(error) => {
            let state = state.lock().unwrap();
            panic!(
                "service shutdown timed out after interrupts={} shutdowns={}: {error}",
                state.interrupts, state.shutdowns
            );
        }
    }
    let persisted = Store::open(layout.data.join("carl.sqlite3"))?
        .get_task(task_id)?
        .ok_or("cancelled task missing")?;
    assert_eq!(persisted.snapshot.status, TaskStatus::Cancelled);
    let state = state.lock().unwrap();
    assert_eq!(state.interrupts, 1);
    assert_eq!(state.shutdowns, 1);
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn start_idempotency_survives_owner_restart_without_a_second_task() -> TestResult {
    let layout = Layout::new()?;
    let command = ServiceCommand::StartTask(StartTaskCommand {
        external_session_id: "durable-idempotency-session".to_owned(),
        workspace: layout.workspace.clone(),
        request: "create this durable task exactly once".to_owned(),
        model: ModelId::parse("gpt-test")?,
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::FullAccess,
    });
    let service = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    let ServiceResult::Accepted { task_id } = client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "durable-start-1".to_owned(),
            idempotency_key: "durable-start-key".to_owned(),
            command: command.clone(),
        })
        .await?
    else {
        return Err("first start was not accepted".into());
    };
    client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "durable-cancel".to_owned(),
            idempotency_key: "durable-cancel-key".to_owned(),
            command: ServiceCommand::Cancel { task_id },
        })
        .await?;
    client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "durable-shutdown".to_owned(),
            idempotency_key: "durable-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        })
        .await?;
    running.await??;

    let replacement = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let running = tokio::spawn(replacement.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    assert_eq!(
        client
            .request(ServiceRequest {
                protocol_version: 1,
                request_id: "durable-start-2".to_owned(),
                idempotency_key: "durable-start-key".to_owned(),
                command,
            })
            .await?,
        ServiceResult::Accepted { task_id }
    );
    let ServiceResult::TaskList(tasks) = client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "durable-list".to_owned(),
            idempotency_key: "durable-list-key".to_owned(),
            command: ServiceCommand::List,
        })
        .await?
    else {
        return Err("task list missing".into());
    };
    assert_eq!(tasks.len(), 1);
    client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "durable-shutdown-2".to_owned(),
            idempotency_key: "durable-shutdown-key-2".to_owned(),
            command: ServiceCommand::Shutdown,
        })
        .await?;
    running.await??;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn startup_prepares_every_resumable_task_before_accepting_clients() -> TestResult {
    let layout = Layout::new()?;
    let first = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let running = tokio::spawn(first.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    for index in 1..=2 {
        let ServiceResult::Accepted { .. } = client
            .request(ServiceRequest {
                protocol_version: 1,
                request_id: format!("startup-start-{index}"),
                idempotency_key: format!("startup-start-key-{index}"),
                command: ServiceCommand::StartTask(StartTaskCommand {
                    external_session_id: "startup-session".to_owned(),
                    workspace: layout.workspace.clone(),
                    request: format!("durable startup task {index}"),
                    model: ModelId::parse("gpt-test")?,
                    effort: ReasoningEffort::High,
                    permission_mode: PermissionMode::FullAccess,
                }),
            })
            .await?
        else {
            return Err("startup task was not accepted".into());
        };
    }
    let ServiceResult::TaskList(tasks) = client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "startup-list".to_owned(),
            idempotency_key: "startup-list-key".to_owned(),
            command: ServiceCommand::List,
        })
        .await?
    else {
        return Err("startup task list missing".into());
    };
    assert_eq!(tasks.len(), 2);
    drop(client);
    running.abort();
    let _ = running.await;
    for _ in 0..100 {
        if !layout.data.join("carl.sock").exists() {
            break;
        }
        tokio::task::yield_now().await;
    }

    let replacement_port = PendingPort::new();
    let replacement_state = Arc::clone(&replacement_port.state);
    let replacement = TaskService::bind(&layout.data, replacement_port).await?;
    let state = replacement_state.lock().unwrap();
    assert_eq!(state.started_contexts + state.resumed_contexts, 2);
    drop(state);
    drop(replacement);
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn slow_acp_reader_is_bounded_and_does_not_interrupt_owner_work() -> TestResult {
    let layout = Layout::new()?;
    let port = PendingPort::new();
    let state = Arc::clone(&port.state);
    let service = TaskService::bind(&layout.data, port).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));
    let mut owner = TaskServiceClient::connect(&layout.data).await?;
    let ServiceResult::Accepted { task_id } = owner
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "slow-start".to_owned(),
            idempotency_key: "slow-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "slow-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "stay active while a slow frontend is evicted".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
            }),
        })
        .await?
    else {
        return Err("slow-reader task was not accepted".into());
    };
    for index in 0..160 {
        assert_eq!(
            owner
                .request(ServiceRequest {
                    protocol_version: 1,
                    request_id: format!("slow-config-{index}"),
                    idempotency_key: format!("slow-config-key-{index}"),
                    command: ServiceCommand::Configure {
                        task_id,
                        model: ModelId::parse("gpt-test")?,
                        effort: ReasoningEffort::High,
                        permission_mode: PermissionMode::FullAccess,
                    },
                })
                .await?,
            ServiceResult::Applied
        );
    }

    let acp = ServiceAcpServer::new(
        &layout.data,
        AcpServerConfig {
            frontend: Frontend::Acp,
            model: None,
            effort: None,
            permission_mode: PermissionMode::FullAccess,
            buzz_publisher: None,
        },
    )
    .await?;
    let (mut client_stream, server_stream) = tokio::io::duplex(512);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let acp_task = tokio::spawn(acp.serve(BufReader::new(server_read), server_write));
    client_stream
        .write_all(
            format!(
                "{}\n{}\n",
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientInfo":{"name":"slow-reader","version":"1.0.0"},"clientCapabilities":{}}}),
                json!({"jsonrpc":"2.0","id":2,"method":"session/load","params":{"sessionId":"slow-session","cwd":layout.workspace,"mcpServers":[],"taskId":task_id,"lastEventCursor":0}})
            )
            .as_bytes(),
        )
        .await?;
    client_stream.flush().await?;
    let served = tokio::time::timeout(Duration::from_secs(5), acp_task).await?;
    assert!(served.is_ok(), "the bounded writer task must exit cleanly");
    assert_eq!(state.lock().unwrap().interrupts, 0);
    let ServiceResult::Snapshot(snapshot) = owner
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "slow-status".to_owned(),
            idempotency_key: "slow-status-key".to_owned(),
            command: ServiceCommand::Status { task_id },
        })
        .await?
    else {
        return Err("slow-reader status missing".into());
    };
    assert_eq!(snapshot.status, TaskStatus::Active);
    owner
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "slow-cancel".to_owned(),
            idempotency_key: "slow-cancel-key".to_owned(),
            command: ServiceCommand::Cancel { task_id },
        })
        .await?;
    owner
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "slow-shutdown".to_owned(),
            idempotency_key: "slow-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        })
        .await?;
    running.await??;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn service_restart_resumes_from_checkpoint_without_repeating_effect() -> TestResult {
    let layout = Layout::new()?;
    let shared = Arc::new(Mutex::new(ContinuityState {
        workspace: layout.workspace.clone(),
        ..ContinuityState::default()
    }));
    let first_service = TaskService::bind(
        &layout.data,
        ContinuityPort::new(Arc::clone(&shared), false),
    )
    .await?;
    let first_task = tokio::spawn(first_service.serve(CancellationToken::new()));
    let mut first = TaskServiceClient::connect(&layout.data).await?;
    let result = first
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "restart-start".to_owned(),
            idempotency_key: "restart-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "restart-owner".to_owned(),
                workspace: layout.workspace.clone(),
                request: "apply one effect, checkpoint, and finish after restart".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
            }),
        })
        .await?;
    let ServiceResult::Accepted { task_id } = result else {
        return Err("restart task was not accepted".into());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let result = first
                .request(ServiceRequest {
                    protocol_version: 1,
                    request_id: format!("restart-status-{}", Uuid::new_v4()),
                    idempotency_key: format!("restart-status-key-{}", Uuid::new_v4()),
                    command: ServiceCommand::Status { task_id },
                })
                .await
                .expect("status before crash succeeds");
            if let ServiceResult::Snapshot(snapshot) = result
                && snapshot.latest_checkpoint.is_some()
                && snapshot.active_epoch.is_some()
                && shared.lock().unwrap().effect_count == 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let ServiceResult::Events(events) = first
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "events-before-crash".to_owned(),
            idempotency_key: "events-before-crash-key".to_owned(),
            command: ServiceCommand::Events {
                task_id,
                after_sequence: None,
                limit: 512,
            },
        })
        .await?
    else {
        return Err("event page missing".into());
    };
    let cursor = events.last().ok_or("event cursor missing")?.sequence;
    assert_eq!(first.last_event_cursor(), Some(cursor));
    drop(first);
    first_task.abort();
    let _ = first_task.await;
    for _ in 0..100 {
        if !layout.data.join("carl.sock").exists() {
            break;
        }
        tokio::task::yield_now().await;
    }

    let replacement_service =
        TaskService::bind(&layout.data, ContinuityPort::new(Arc::clone(&shared), true)).await?;
    let replacement_task = tokio::spawn(replacement_service.serve(CancellationToken::new()));
    let mut replacement =
        TaskServiceClient::connect_with_cursor(&layout.data, Some(cursor)).await?;
    let completed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let result = replacement
                .request(ServiceRequest {
                    protocol_version: 1,
                    request_id: format!("replacement-status-{}", Uuid::new_v4()),
                    idempotency_key: format!("replacement-status-key-{}", Uuid::new_v4()),
                    command: ServiceCommand::Status { task_id },
                })
                .await
                .expect("replacement status succeeds");
            if let ServiceResult::Snapshot(snapshot) = result
                && snapshot.status == TaskStatus::Completed
            {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(completed.task_id, task_id);
    let ServiceResult::Events(after_restart) = replacement
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "events-after-restart".to_owned(),
            idempotency_key: "events-after-restart-key".to_owned(),
            command: ServiceCommand::Events {
                task_id,
                after_sequence: replacement.last_event_cursor(),
                limit: 512,
            },
        })
        .await?
    else {
        return Err("replacement event page missing".into());
    };
    assert!(!after_restart.is_empty());
    assert!(after_restart.iter().all(|event| event.sequence > cursor));
    assert!(
        after_restart
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    );
    assert_eq!(shared.lock().unwrap().effect_count, 1);
    assert_eq!(
        replacement
            .request(ServiceRequest {
                protocol_version: 1,
                request_id: "replacement-shutdown".to_owned(),
                idempotency_key: "replacement-shutdown-key".to_owned(),
                command: ServiceCommand::Shutdown,
            })
            .await?,
        ServiceResult::Applied
    );
    replacement_task.await??;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn acp_stdio_disconnect_leaves_the_service_owned_task_running() -> TestResult {
    let layout = Layout::new()?;
    let port = PendingPort::new();
    let state = Arc::clone(&port.state);
    let service = TaskService::bind(&layout.data, port).await?;
    let service_task = tokio::spawn(service.serve(CancellationToken::new()));

    let acp = ServiceAcpServer::new(
        &layout.data,
        AcpServerConfig {
            frontend: Frontend::Acp,
            model: Some(ModelId::parse("gpt-test")?),
            effort: Some(ReasoningEffort::High),
            permission_mode: PermissionMode::FullAccess,
            buzz_publisher: None,
        },
    )
    .await?;
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let acp_task = tokio::spawn(acp.serve(BufReader::new(server_read), server_write));
    client_write
        .write_all(
            format!(
                "{}\n{}\n",
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientInfo":{"name":"contract","version":"1.0.0"},"clientCapabilities":{}}}),
                json!({"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":layout.workspace,"mcpServers":[]}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let mut reader = BufReader::new(client_read);
    let initialized = read_frame(&mut reader, 1024 * 1024)
        .await?
        .ok_or("initialize response missing")?;
    assert_eq!(initialized.value()["id"], 1);
    let session = read_frame(&mut reader, 1024 * 1024)
        .await?
        .ok_or("session response missing")?;
    let session_id = session.value()["result"]["sessionId"]
        .as_str()
        .ok_or("session ID missing")?
        .to_owned();
    client_write
        .write_all(
            format!(
                "{}\n{}\n",
                json!({"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":session_id,"prompt":[{"type":"text","text":"continue after stdio closes"}]}}),
                json!({"jsonrpc":"2.0","id":4,"method":"_session/steering","params":{"sessionId":session_id,"prompt":[{"type":"text","text":"also verify reconnect continuity"}]}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let steered = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = read_frame(&mut reader, 1024 * 1024)
                .await
                .expect("ACP frame is valid")
                .expect("steering response missing");
            assert_ne!(
                frame.value()["id"],
                3,
                "pending prompt must not report end_turn before its task reaches a stop state"
            );
            if frame.value()["id"] == 4 {
                break frame;
            }
        }
    })
    .await?;
    assert_eq!(steered.value()["result"]["outcome"], "injected");
    drop(client_write);
    drop(reader);
    acp_task.await??;
    assert_eq!(state.lock().unwrap().interrupts, 0);

    let mut owner = TaskServiceClient::connect(&layout.data).await?;
    let ServiceResult::TaskList(tasks) = owner
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "acp-list".to_owned(),
            idempotency_key: "acp-list-key".to_owned(),
            command: ServiceCommand::List,
        })
        .await?
    else {
        return Err("task list missing".into());
    };
    let task_id = tasks.first().ok_or("service-owned task missing")?.task_id;
    assert_eq!(tasks[0].status, TaskStatus::Active);
    assert_eq!(
        owner
            .request(ServiceRequest {
                protocol_version: 1,
                request_id: "acp-cancel".to_owned(),
                idempotency_key: "acp-cancel-key".to_owned(),
                command: ServiceCommand::Cancel { task_id },
            })
            .await?,
        ServiceResult::Applied
    );
    assert_eq!(
        owner
            .request(ServiceRequest {
                protocol_version: 1,
                request_id: "acp-shutdown".to_owned(),
                idempotency_key: "acp-shutdown-key".to_owned(),
                command: ServiceCommand::Shutdown,
            })
            .await?,
        ServiceResult::Applied
    );
    service_task.await??;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn buzz_start_is_admitted_by_the_owner_writer_before_task_creation() -> TestResult {
    let layout = Layout::new()?;
    let actor = ActorId::parse("a".repeat(64))?;
    Store::open(layout.data.join("carl.sqlite3"))?.trust_frontend_owner(
        TrustedFrontendOwnerInput {
            frontend: Frontend::Buzz,
            actor_id: actor.clone(),
            workspace: layout.workspace.clone(),
            permission_mode: PermissionMode::FullAccess,
            trusted_at: Utc::now(),
        },
    )?;
    let service = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let service_task = tokio::spawn(service.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    assert_eq!(
        client.info().default_model.as_ref().map(ModelId::as_str),
        Some("gpt-test")
    );

    let trusted = |actor_id: ActorId, event_id: char| {
        ServiceCommand::StartTrustedTask(TrustedStartTaskCommand {
            start: StartTaskCommand {
                external_session_id: "buzz-service-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "trusted owner task".to_owned(),
                model: ModelId::parse("gpt-test").expect("test model is valid"),
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::Plan,
            },
            frontend: Frontend::Buzz,
            actor_id,
            channel_id: Uuid::nil().to_string(),
            event_id: event_id.to_string().repeat(64),
        })
    };
    let rejected = client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "buzz-rejected".to_owned(),
            idempotency_key: "buzz-rejected-key".to_owned(),
            command: trusted(ActorId::parse("b".repeat(64))?, '1'),
        })
        .await
        .expect_err("untrusted actor must fail before enqueue");
    assert_eq!(
        rejected.code(),
        carl::service::client::ServiceClientErrorCode::Rejected
    );
    let ServiceResult::TaskList(tasks) = client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "buzz-list-empty".to_owned(),
            idempotency_key: "buzz-list-empty-key".to_owned(),
            command: ServiceCommand::List,
        })
        .await?
    else {
        return Err("task list missing".into());
    };
    assert!(tasks.is_empty());

    let ServiceResult::Accepted { task_id } = client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "buzz-accepted".to_owned(),
            idempotency_key: "buzz-accepted-key".to_owned(),
            command: trusted(actor, '2'),
        })
        .await?
    else {
        return Err("trusted task was not accepted".into());
    };
    client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "buzz-cancel".to_owned(),
            idempotency_key: "buzz-cancel-key".to_owned(),
            command: ServiceCommand::Cancel { task_id },
        })
        .await?;
    client
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "buzz-shutdown".to_owned(),
            idempotency_key: "buzz-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        })
        .await?;
    service_task.await??;

    let binding = Store::open(layout.data.join("carl.sqlite3"))?
        .get_frontend_session("buzz-service-session")?
        .ok_or("Buzz binding missing")?;
    assert_eq!(binding.frontend, Frontend::Buzz);
    assert_eq!(binding.permission_mode, PermissionMode::FullAccess);
    let expected_channel = Uuid::nil().to_string();
    assert_eq!(
        binding.channel_id.as_ref().map(|channel| channel.as_str()),
        Some(expected_channel.as_str())
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn acp_controls_complete_prompt_and_reconnect_replays_cursor_events() -> TestResult {
    let layout = Layout::new()?;
    let service = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let service_task = tokio::spawn(service.serve(CancellationToken::new()));
    let acp = ServiceAcpServer::new(
        &layout.data,
        AcpServerConfig {
            frontend: Frontend::Acp,
            model: None,
            effort: None,
            permission_mode: PermissionMode::FullAccess,
            buzz_publisher: None,
        },
    )
    .await?;
    let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let acp_task = tokio::spawn(acp.serve(BufReader::new(server_read), server_write));
    let mut reader = BufReader::new(client_read);
    client_write
        .write_all(
            format!(
                "{}\n{}\n",
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientInfo":{"name":"parity","version":"1.0.0"},"clientCapabilities":{}}}),
                json!({"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":layout.workspace,"mcpServers":[]}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let _ = read_frame(&mut reader, 1024 * 1024).await?;
    let session = read_frame(&mut reader, 1024 * 1024)
        .await?
        .ok_or("session response missing")?;
    let session_id = session.value()["result"]["sessionId"]
        .as_str()
        .ok_or("session ID missing")?
        .to_owned();
    client_write
        .write_all(
            format!(
                "{}\n{}\n",
                json!({"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":session_id,"prompt":[{"type":"text","text":"hold for controls"}]}}),
                json!({"jsonrpc":"2.0","id":4,"method":"_task/list","params":{"sessionId":session_id}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let list = loop {
        let frame = read_frame(&mut reader, 1024 * 1024)
            .await?
            .ok_or("list response missing")?;
        assert_ne!(frame.value()["id"], 3);
        if frame.value()["id"] == 4 {
            break frame;
        }
    };
    let task_id = list.value()["result"]["tasks"][0]["task_id"]
        .as_str()
        .ok_or("task ID missing")?
        .to_owned();
    client_write
        .write_all(
            format!(
                "{}\n{}\n{}\n",
                json!({"jsonrpc":"2.0","id":5,"method":"_task/context","params":{"sessionId":session_id,"taskId":task_id}}),
                json!({"jsonrpc":"2.0","id":6,"method":"session/set_config_option","params":{"sessionId":session_id,"configId":"thought_level","value":"high"}}),
                json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":session_id}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let mut saw_context = false;
    let mut saw_config = false;
    let mut sequences = Vec::new();
    let prompt = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = read_frame(&mut reader, 1024 * 1024)
                .await
                .expect("ACP frame is valid")
                .expect("prompt completion missing");
            match frame.value().get("id").and_then(|id| id.as_i64()) {
                Some(3) => break frame,
                Some(5) => saw_context = frame.value()["result"]["context"].is_object(),
                Some(6) => saw_config = frame.value()["result"]["configOptions"].is_array(),
                _ => {
                    if let Some(sequence) =
                        frame.value()["params"]["_meta"]["eventSequence"].as_u64()
                    {
                        sequences.push(sequence);
                    }
                }
            }
        }
    })
    .await?;
    assert_eq!(prompt.value()["result"]["stopReason"], "cancelled");
    assert!(saw_context && saw_config);
    assert!(!sequences.is_empty());
    assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
    let cursor = prompt.value()["result"]["_meta"]["lastEventCursor"]
        .as_u64()
        .ok_or("prompt cursor missing")?;
    drop(client_write);
    drop(reader);
    acp_task.await??;

    let reconnect = ServiceAcpServer::new(
        &layout.data,
        AcpServerConfig {
            frontend: Frontend::Acp,
            model: None,
            effort: None,
            permission_mode: PermissionMode::FullAccess,
            buzz_publisher: None,
        },
    )
    .await?;
    let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let reconnect_task = tokio::spawn(reconnect.serve(BufReader::new(server_read), server_write));
    let mut reader = BufReader::new(client_read);
    client_write
        .write_all(
            format!(
                "{}\n{}\n",
                json!({"jsonrpc":"2.0","id":10,"method":"initialize","params":{"protocolVersion":1,"clientInfo":{"name":"reconnect","version":"1.0.0"},"clientCapabilities":{}}}),
                json!({"jsonrpc":"2.0","id":11,"method":"session/load","params":{"sessionId":session_id,"cwd":layout.workspace,"mcpServers":[],"taskId":task_id,"lastEventCursor":0}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let mut loaded = false;
    let mut replayed = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !(loaded && replayed) {
            let frame = read_frame(&mut reader, 1024 * 1024)
                .await
                .expect("reconnect frame valid")
                .expect("reconnect frame missing");
            loaded |= frame.value()["id"] == 11;
            replayed |= frame.value()["params"]["_meta"]["eventSequence"]
                .as_u64()
                .is_some_and(|sequence| sequence > 0 && sequence <= cursor);
        }
    })
    .await?;
    drop(client_write);
    drop(reader);
    reconnect_task.await??;

    let mut owner = TaskServiceClient::connect(&layout.data).await?;
    owner
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "parity-shutdown".to_owned(),
            idempotency_key: "parity-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        })
        .await?;
    service_task.await??;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn acp_reconnect_during_three_epoch_task_replays_once_and_completes() -> TestResult {
    let layout = Layout::new()?;
    let shared = Arc::new(Mutex::new(ThreeEpochState {
        workspace: layout.workspace.clone(),
        ..ThreeEpochState::default()
    }));
    let service = TaskService::bind(&layout.data, ThreeEpochPort::new(Arc::clone(&shared))).await?;
    let service_task = tokio::spawn(service.serve(CancellationToken::new()));

    let acp = ServiceAcpServer::new(
        &layout.data,
        AcpServerConfig {
            frontend: Frontend::Acp,
            model: None,
            effort: None,
            permission_mode: PermissionMode::FullAccess,
            buzz_publisher: None,
        },
    )
    .await?;
    let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let acp_task = tokio::spawn(acp.serve(BufReader::new(server_read), server_write));
    let mut reader = BufReader::new(client_read);
    client_write
        .write_all(
            format!(
                "{}\n{}\n",
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientInfo":{"name":"three-epoch","version":"1.0.0"},"clientCapabilities":{}}}),
                json!({"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":layout.workspace,"mcpServers":[]}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let _ = read_frame(&mut reader, 1024 * 1024).await?;
    let session = read_frame(&mut reader, 1024 * 1024)
        .await?
        .ok_or("three-epoch session missing")?;
    let session_id = session.value()["result"]["sessionId"]
        .as_str()
        .ok_or("three-epoch session ID missing")?
        .to_owned();
    client_write
        .write_all(
            format!(
                "{}\n",
                json!({"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":session_id,"prompt":[{"type":"text","text":"perform exactly one effect over three durable epochs"}]}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ready = {
                let state = shared.lock().unwrap();
                state.work_epochs == 1 && state.effect_count == 1 && state.operation_id.is_some()
            };
            if ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let mut owner = TaskServiceClient::connect(&layout.data).await?;
    let ServiceResult::TaskList(tasks) = owner
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "three-list".to_owned(),
            idempotency_key: "three-list-key".to_owned(),
            command: ServiceCommand::List,
        })
        .await?
    else {
        return Err("three-epoch task list missing".into());
    };
    let task_id = tasks.first().ok_or("three-epoch task missing")?.task_id;
    let ServiceResult::Events(events) = owner
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "three-before-disconnect".to_owned(),
            idempotency_key: "three-before-disconnect-key".to_owned(),
            command: ServiceCommand::Events {
                task_id,
                after_sequence: None,
                limit: 512,
            },
        })
        .await?
    else {
        return Err("three-epoch cursor page missing".into());
    };
    let cursor = events.last().ok_or("three-epoch cursor missing")?.sequence;
    drop(client_write);
    drop(reader);
    tokio::time::timeout(Duration::from_secs(5), acp_task).await???;
    assert_eq!(shared.lock().unwrap().interrupts, 0);

    shared.lock().unwrap().release_epoch_one = true;
    tokio::time::timeout(Duration::from_secs(5), async {
        while shared.lock().unwrap().work_epochs < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let reconnect = ServiceAcpServer::new(
        &layout.data,
        AcpServerConfig {
            frontend: Frontend::Acp,
            model: None,
            effort: None,
            permission_mode: PermissionMode::FullAccess,
            buzz_publisher: None,
        },
    )
    .await?;
    let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let reconnect_task = tokio::spawn(reconnect.serve(BufReader::new(server_read), server_write));
    let mut reader = BufReader::new(client_read);
    client_write
        .write_all(
            format!(
                "{}\n{}\n",
                json!({"jsonrpc":"2.0","id":10,"method":"initialize","params":{"protocolVersion":1,"clientInfo":{"name":"three-epoch-reconnect","version":"1.0.0"},"clientCapabilities":{}}}),
                json!({"jsonrpc":"2.0","id":11,"method":"session/load","params":{"sessionId":session_id,"cwd":layout.workspace,"mcpServers":[],"taskId":task_id,"lastEventCursor":cursor}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let mut loaded = false;
    while !loaded {
        let frame =
            tokio::time::timeout(Duration::from_secs(5), read_frame(&mut reader, 1024 * 1024))
                .await??
                .ok_or("three-epoch load response missing")?;
        loaded = frame.value()["id"] == 11;
    }
    shared.lock().unwrap().release_epoch_two = true;

    let mut replayed = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = read_frame(&mut reader, 1024 * 1024)
                .await
                .expect("three-epoch replay frame valid")
                .expect("three-epoch replay frame missing");
            if let Some(sequence) = frame.value()["params"]["_meta"]["eventSequence"].as_u64() {
                replayed.push(sequence);
                if frame.value()["params"]["update"]["status"] == "completed" {
                    break;
                }
            }
        }
    })
    .await?;
    assert!(!replayed.is_empty());
    assert!(replayed.iter().all(|sequence| *sequence > cursor));
    assert!(replayed.windows(2).all(|pair| pair[0] < pair[1]));

    let ServiceResult::Snapshot(snapshot) = owner
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "three-completed".to_owned(),
            idempotency_key: "three-completed-key".to_owned(),
            command: ServiceCommand::Status { task_id },
        })
        .await?
    else {
        return Err("three-epoch completion snapshot missing".into());
    };
    assert_eq!(snapshot.status, TaskStatus::Completed);
    {
        let state = shared.lock().unwrap();
        assert_eq!(state.work_epochs, 3);
        assert_eq!(state.effect_count, 1);
        assert_eq!(state.completion_reports, 1);
        assert_eq!(state.interrupts, 0);
    }
    drop(client_write);
    drop(reader);
    tokio::time::timeout(Duration::from_secs(5), reconnect_task).await???;
    owner
        .request(ServiceRequest {
            protocol_version: 1,
            request_id: "three-shutdown".to_owned(),
            idempotency_key: "three-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        })
        .await?;
    service_task.await??;
    Ok(())
}

struct Layout {
    root: PathBuf,
    data: PathBuf,
    workspace: PathBuf,
}

impl Layout {
    fn new() -> TestResult<Self> {
        let root = PathBuf::from("/tmp").join(format!(
            "carl-svc-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ));
        let data = root.join("data");
        let workspace = root.join("workspace");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&workspace)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            root,
            data: fs::canonicalize(data)?,
            workspace: fs::canonicalize(workspace)?,
        })
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn _assert_paths_are_absolute(path: &Path) {
    assert!(path.is_absolute());
}

struct PendingPort {
    state: Arc<Mutex<PendingPortState>>,
}

#[derive(Default)]
struct PendingPortState {
    events: VecDeque<AgentEvent>,
    epoch: u64,
    interrupts: u64,
    shutdowns: u64,
    started_contexts: u64,
    resumed_contexts: u64,
}

impl PendingPort {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(PendingPortState::default())),
        }
    }
}

impl AgentPort for PendingPort {
    fn supports_autonomous_tasks(&self) -> bool {
        true
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: false,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: false,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async {
            Ok(vec![AgentModel {
                id: ModelId::parse("gpt-test").expect("test model is valid"),
                display_name: "GPT Test".to_owned(),
                supported_efforts: vec![ReasoningEffort::High],
                default_effort: ReasoningEffort::High,
            }])
        })
    }

    fn start_context(&mut self, _request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            state.started_contexts += 1;
            AgentContextId::parse(format!("service-context-{}", state.started_contexts))
        })
    }

    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().resumed_contexts += 1;
            Ok(request.context_id)
        })
    }

    fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            state.epoch += 1;
            let epoch_id = AgentEpochId::parse(format!("service-epoch-{}", state.epoch))?;
            state.events.push_back(AgentEvent::EpochStarted {
                context_id: request.context_id,
                epoch_id: epoch_id.clone(),
            });
            Ok(epoch_id)
        })
    }

    fn steer(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
        _text: String,
    ) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn interrupt(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().interrupts += 1;
            Ok(())
        })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            if let Some(event) = state.lock().unwrap().events.pop_front() {
                return Ok(event);
            }
            std::future::pending().await
        })
    }

    fn resolve_effect(
        &mut self,
        _request_id: &AgentRequestId,
        _decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn list_background_processes(
        &mut self,
        _context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn terminate_background_process(
        &mut self,
        _context_id: &AgentContextId,
        _process_id: &str,
    ) -> AgentFuture<'_, bool> {
        Box::pin(async { Ok(true) })
    }

    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().shutdowns += 1;
            Ok(())
        })
    }
}

struct ContinuityPort {
    state: Arc<Mutex<ContinuityState>>,
    replacement: bool,
}

struct ThreeEpochPort {
    state: Arc<Mutex<ThreeEpochState>>,
}

#[derive(Default)]
struct ThreeEpochState {
    workspace: PathBuf,
    events: VecDeque<AgentEvent>,
    provider_epochs: u64,
    work_epochs: u64,
    effect_count: u64,
    operation_id: Option<String>,
    release_epoch_one: bool,
    release_epoch_two: bool,
    epoch_one_finished: bool,
    epoch_two_finished: bool,
    completion_reports: u64,
    interrupts: u64,
}

impl ThreeEpochPort {
    fn new(state: Arc<Mutex<ThreeEpochState>>) -> Self {
        Self { state }
    }
}

impl AgentPort for ThreeEpochPort {
    fn supports_autonomous_tasks(&self) -> bool {
        true
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: false,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: false,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async {
            Ok(vec![AgentModel {
                id: ModelId::parse("gpt-test").expect("test model is valid"),
                display_name: "GPT Test".to_owned(),
                supported_efforts: vec![ReasoningEffort::High],
                default_effort: ReasoningEffort::High,
            }])
        })
    }

    fn start_context(&mut self, _request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async { AgentContextId::parse("three-epoch-context") })
    }

    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async move { Ok(request.context_id) })
    }

    fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            state.provider_epochs += 1;
            let epoch_id =
                AgentEpochId::parse(format!("three-provider-{}", state.provider_epochs))?;
            state.events.push_back(AgentEvent::EpochStarted {
                context_id: request.context_id.clone(),
                epoch_id: epoch_id.clone(),
            });
            if request.permission_mode == PermissionMode::Plan {
                state.events.push_back(AgentEvent::AssistantDelta {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    text: "<carl-completion-contract>{\"version\":1,\"goal\":\"Complete exactly three durable epochs\",\"constraints\":[],\"clauses\":[{\"id\":\"requested-outcome\",\"description\":\"Requested outcome\",\"required\":true,\"status\":\"pending\",\"evidence\":[]},{\"id\":\"explicit-verification\",\"description\":\"Explicit verification\",\"required\":true,\"status\":\"pending\",\"evidence\":[]}]}</carl-completion-contract>".to_owned(),
                });
                state.events.push_back(AgentEvent::EpochCompleted {
                    context_id: request.context_id,
                    epoch_id: epoch_id.clone(),
                    status: "completed".to_owned(),
                });
                return Ok(epoch_id);
            }

            state.work_epochs += 1;
            match state.work_epochs {
                1 => {
                    let item = AgentItem::Command {
                        item_id: "three-effect".to_owned(),
                        command: "apply-once".to_owned(),
                        cwd: state.workspace.clone(),
                        status: "inProgress".to_owned(),
                        exit_code: None,
                        aggregated_output: None,
                        process_id: None,
                    };
                    state.events.push_back(AgentEvent::ItemStarted {
                        context_id: request.context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        item,
                    });
                    state
                        .events
                        .push_back(AgentEvent::EffectRequested(AgentEffectRequest {
                            context_id: request.context_id,
                            epoch_id: epoch_id.clone(),
                            request_id: AgentRequestId::parse("three-effect-request")?,
                            item_id: "three-effect".to_owned(),
                            kind: AgentEffectKind::Command,
                            summary: "apply the effect exactly once".to_owned(),
                            request_digest: Sha256Digest::parse("3".repeat(64))
                                .expect("literal digest is valid"),
                        }));
                }
                3 => {
                    let operation_id = state.operation_id.clone().ok_or_else(|| {
                        AgentPortError::from_code(
                            carl::runtime::agent_port::AgentPortErrorCode::InvalidResponse,
                        )
                    })?;
                    state.completion_reports += 1;
                    state.events.push_back(AgentEvent::AssistantDelta {
                        context_id: request.context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        text: epoch_report("complete", None, Some(&operation_id)),
                    });
                    state.events.push_back(AgentEvent::EpochCompleted {
                        context_id: request.context_id,
                        epoch_id: epoch_id.clone(),
                        status: "completed".to_owned(),
                    });
                }
                _ => {}
            }
            Ok(epoch_id)
        })
    }

    fn steer(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
        text: String,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            if let Some(operation_id) = text.strip_prefix("carl-operation-id:") {
                state.lock().unwrap().operation_id = Some(operation_id.trim().to_owned());
            }
            Ok(())
        })
    }

    fn interrupt(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().interrupts += 1;
            Ok(())
        })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            loop {
                {
                    let mut state = state.lock().unwrap();
                    if let Some(event) = state.events.pop_front() {
                        return Ok(event);
                    }
                    if state.work_epochs == 1
                        && state.release_epoch_one
                        && state.effect_count == 1
                        && state.operation_id.is_some()
                        && !state.epoch_one_finished
                    {
                        state.epoch_one_finished = true;
                        let context_id = AgentContextId::parse("three-epoch-context")?;
                        let epoch_id = AgentEpochId::parse(format!(
                            "three-provider-{}",
                            state.provider_epochs
                        ))?;
                        let workspace = state.workspace.clone();
                        state.events.push_back(AgentEvent::ItemCompleted {
                            context_id: context_id.clone(),
                            epoch_id: epoch_id.clone(),
                            item: AgentItem::Command {
                                item_id: "three-effect".to_owned(),
                                command: "apply-once".to_owned(),
                                cwd: workspace,
                                status: "completed".to_owned(),
                                exit_code: Some(0),
                                aggregated_output: Some("applied once".to_owned()),
                                process_id: None,
                            },
                        });
                        state.events.push_back(AgentEvent::AssistantDelta {
                            context_id: context_id.clone(),
                            epoch_id: epoch_id.clone(),
                            text: epoch_report("continue", Some("run epoch two"), None),
                        });
                        state.events.push_back(AgentEvent::EpochCompleted {
                            context_id,
                            epoch_id,
                            status: "completed".to_owned(),
                        });
                        continue;
                    }
                    if state.work_epochs == 2
                        && state.release_epoch_two
                        && !state.epoch_two_finished
                    {
                        state.epoch_two_finished = true;
                        let context_id = AgentContextId::parse("three-epoch-context")?;
                        let epoch_id = AgentEpochId::parse(format!(
                            "three-provider-{}",
                            state.provider_epochs
                        ))?;
                        state.events.push_back(AgentEvent::AssistantDelta {
                            context_id: context_id.clone(),
                            epoch_id: epoch_id.clone(),
                            text: epoch_report("continue", Some("finish epoch three"), None),
                        });
                        state.events.push_back(AgentEvent::EpochCompleted {
                            context_id,
                            epoch_id,
                            status: "completed".to_owned(),
                        });
                        continue;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    }

    fn resolve_effect(
        &mut self,
        _request_id: &AgentRequestId,
        decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            if decision == EffectDecision::Allow {
                state.lock().unwrap().effect_count += 1;
            }
            Ok(())
        })
    }

    fn list_background_processes(
        &mut self,
        _context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn terminate_background_process(
        &mut self,
        _context_id: &AgentContextId,
        _process_id: &str,
    ) -> AgentFuture<'_, bool> {
        Box::pin(async { Ok(true) })
    }

    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

fn epoch_report(
    disposition: &str,
    next_objective: Option<&str>,
    operation_id: Option<&str>,
) -> String {
    let evidence = operation_id.map_or_else(Vec::new, |operation_id| {
        vec![
            json!({"clause_id":"requested-outcome","operation_ids":[operation_id],"event_sequences":[],"artifact_digests":[]}),
            json!({"clause_id":"explicit-verification","operation_ids":[operation_id],"event_sequences":[],"artifact_digests":[]}),
        ]
    });
    format!(
        "<carl-epoch-report>{}</carl-epoch-report>",
        json!({
            "schema_version":1,
            "disposition":disposition,
            "summary":format!("{disposition} durable epoch"),
            "next_objective":next_objective,
            "clause_evidence":evidence,
            "exact_identifiers":[]
        })
    )
}

#[derive(Default)]
struct ContinuityState {
    workspace: PathBuf,
    events: VecDeque<AgentEvent>,
    epoch: u64,
    effect_count: u64,
    operation_id: Option<String>,
    generated_first_completion: bool,
}

impl ContinuityPort {
    fn new(state: Arc<Mutex<ContinuityState>>, replacement: bool) -> Self {
        Self { state, replacement }
    }
}

impl AgentPort for ContinuityPort {
    fn supports_autonomous_tasks(&self) -> bool {
        true
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: false,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: false,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async {
            Ok(vec![AgentModel {
                id: ModelId::parse("gpt-test").expect("test model is valid"),
                display_name: "GPT Test".to_owned(),
                supported_efforts: vec![ReasoningEffort::High],
                default_effort: ReasoningEffort::High,
            }])
        })
    }

    fn start_context(&mut self, _request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async { AgentContextId::parse("continuity-context") })
    }

    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async move { Ok(request.context_id) })
    }

    fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        let state = Arc::clone(&self.state);
        let replacement = self.replacement;
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            state.epoch += 1;
            let epoch_id = AgentEpochId::parse(format!("continuity-epoch-{}", state.epoch))?;
            state.events.push_back(AgentEvent::EpochStarted {
                context_id: request.context_id.clone(),
                epoch_id: epoch_id.clone(),
            });
            if replacement {
                let operation_id = state.operation_id.clone().ok_or_else(|| {
                    AgentPortError::from_code(
                        carl::runtime::agent_port::AgentPortErrorCode::InvalidResponse,
                    )
                })?;
                let report = format!(
                    "<carl-epoch-report>{}</carl-epoch-report>",
                    json!({
                        "schema_version":1,
                        "disposition":"complete",
                        "summary":"finished after restart",
                        "clause_evidence":[
                            {"clause_id":"requested-outcome","operation_ids":[operation_id.clone()],"event_sequences":[],"artifact_digests":[]},
                            {"clause_id":"explicit-verification","operation_ids":[operation_id],"event_sequences":[],"artifact_digests":[]}
                        ],
                        "exact_identifiers":[]
                    })
                );
                state.events.push_back(AgentEvent::AssistantDelta {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    text: report,
                });
                state.events.push_back(AgentEvent::EpochCompleted {
                    context_id: request.context_id,
                    epoch_id: epoch_id.clone(),
                    status: "completed".to_owned(),
                });
            } else if state.effect_count == 0 {
                let item = AgentItem::Command {
                    item_id: "continuity-effect".to_owned(),
                    command: "apply-once".to_owned(),
                    cwd: state.workspace.clone(),
                    status: "inProgress".to_owned(),
                    exit_code: None,
                    aggregated_output: None,
                    process_id: None,
                };
                state.events.push_back(AgentEvent::ItemStarted {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    item,
                });
                state
                    .events
                    .push_back(AgentEvent::EffectRequested(AgentEffectRequest {
                        context_id: request.context_id,
                        epoch_id: epoch_id.clone(),
                        request_id: AgentRequestId::parse("continuity-request")?,
                        item_id: "continuity-effect".to_owned(),
                        kind: AgentEffectKind::Command,
                        summary: "apply exactly once".to_owned(),
                        request_digest: Sha256Digest::parse("1".repeat(64))
                            .expect("literal digest is valid"),
                    }));
            }
            Ok(epoch_id)
        })
    }

    fn steer(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
        text: String,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            if let Some(operation_id) = text.strip_prefix("carl-operation-id:") {
                state.lock().unwrap().operation_id = Some(operation_id.trim().to_owned());
            }
            Ok(())
        })
    }

    fn interrupt(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        let state = Arc::clone(&self.state);
        let replacement = self.replacement;
        Box::pin(async move {
            {
                let mut state = state.lock().unwrap();
                if let Some(event) = state.events.pop_front() {
                    return Ok(event);
                }
                if !replacement
                    && state.effect_count == 1
                    && state.operation_id.is_some()
                    && !state.generated_first_completion
                {
                    state.generated_first_completion = true;
                    let context_id = AgentContextId::parse("continuity-context")?;
                    let epoch_id =
                        AgentEpochId::parse(format!("continuity-epoch-{}", state.epoch))?;
                    let workspace = state.workspace.clone();
                    state.events.push_back(AgentEvent::ItemCompleted {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        item: AgentItem::Command {
                            item_id: "continuity-effect".to_owned(),
                            command: "apply-once".to_owned(),
                            cwd: workspace,
                            status: "completed".to_owned(),
                            exit_code: Some(0),
                            aggregated_output: Some("applied".to_owned()),
                            process_id: None,
                        },
                    });
                    state.events.push_back(AgentEvent::AssistantDelta {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        text: "<carl-epoch-report>{\"schema_version\":1,\"disposition\":\"continue\",\"summary\":\"effect applied once\",\"next_objective\":\"finish after checkpoint\",\"clause_evidence\":[],\"exact_identifiers\":[]}</carl-epoch-report>".to_owned(),
                    });
                    state.events.push_back(AgentEvent::EpochCompleted {
                        context_id,
                        epoch_id,
                        status: "completed".to_owned(),
                    });
                    return Ok(state.events.pop_front().expect("completion event queued"));
                }
            }
            std::future::pending().await
        })
    }

    fn resolve_effect(
        &mut self,
        _request_id: &AgentRequestId,
        decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            if decision == EffectDecision::Allow {
                state.lock().unwrap().effect_count += 1;
            }
            Ok(())
        })
    }

    fn list_background_processes(
        &mut self,
        _context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn terminate_background_process(
        &mut self,
        _context_id: &AgentContextId,
        _process_id: &str,
    ) -> AgentFuture<'_, bool> {
        Box::pin(async { Ok(true) })
    }

    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}
