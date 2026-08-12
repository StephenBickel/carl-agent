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
use carl::runtime::task::{TaskBudget, TaskControlKind, TaskEvent, TaskId, TaskStatus};
use carl::service::client::{ServiceClientErrorCode, TaskServiceClient};
use carl::service::protocol::{
    SERVICE_PROTOCOL_VERSION, ServiceCommand, ServiceRequest, ServiceResult, StartTaskCommand,
    TaskUpdate, TrustedStartTaskCommand, command_digest,
};
use carl::service::server::{EndpointErrorCode, OwnedLocalEndpoint, TaskService};
use carl::storage::{
    ServiceCommandReceiptClaim, ServiceCommandReceiptInput, Store, TrustedFrontendOwnerInput,
};
use chrono::Utc;
use rusqlite::Connection;
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

#[cfg(windows)]
#[tokio::test(flavor = "current_thread")]
async fn windows_client_rejects_a_permissive_precreated_pipe_before_info() -> TestResult {
    use sha2::{Digest as _, Sha256};
    use std::os::windows::ffi::OsStrExt as _;

    let layout = Layout::new()?;
    let mut hasher = Sha256::new();
    for unit in layout.data.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    let pipe_name = format!(r"\\.\pipe\carl-{:x}", hasher.finalize());
    let server = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)?;
    let accepting = tokio::spawn(async move { server.connect().await });
    let error = match TaskServiceClient::connect(&layout.data).await {
        Ok(_) => return Err("a default permissive pipe passed identity verification".into()),
        Err(error) => error,
    };
    assert_eq!(
        error.code(),
        carl::service::client::ServiceClientErrorCode::InvalidEndpoint
    );
    accepting.await??;
    assert!(!layout.data.join("carl.sqlite3").exists());
    Ok(())
}

#[cfg(windows)]
#[tokio::test(flavor = "current_thread")]
async fn windows_client_accepts_the_current_user_private_service_pipe() -> TestResult {
    let layout = Layout::new()?;
    let service = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    assert_eq!(client.protocol_version(), SERVICE_PROTOCOL_VERSION);
    assert_eq!(
        client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "windows-shutdown".to_owned(),
                idempotency_key: "windows-shutdown-key".to_owned(),
                command: ServiceCommand::Shutdown,
            })
            .await?,
        ServiceResult::Applied
    );
    running.await??;
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
    assert_eq!(first.info().protocol_version, SERVICE_PROTOCOL_VERSION);
    assert!(first.info().capabilities.explicit_task_budgets);
    let admitted_budget = TaskBudget {
        max_wall_time_seconds: Some(7_200),
        max_provider_requests: Some(321),
        max_tool_calls: Some(654),
        soft_epoch_seconds: 600,
        soft_epoch_tool_calls: 77,
    };
    let start_command = StartTaskCommand {
        external_session_id: "owner-session".to_owned(),
        workspace: layout.workspace.clone(),
        request: "keep working after the frontend disconnects".to_owned(),
        model: ModelId::parse("gpt-test")?,
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::FullAccess,
        budget: admitted_budget,
    };
    let accepted = first
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "start-1".to_owned(),
            idempotency_key: "start-key".to_owned(),
            command: ServiceCommand::StartTask(start_command.clone()),
        })
        .await
        .map_err(|error| format!("start request failed: {error:?}"))?;
    let ServiceResult::Accepted { task_id } = accepted else {
        return Err("start was not accepted".into());
    };
    drop(first);

    let mut second = TaskServiceClient::connect(&layout.data).await?;
    let mut changed_budget = start_command;
    changed_budget.budget.max_tool_calls = Some(655);
    let conflict = second
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "start-budget-conflict".to_owned(),
            idempotency_key: "start-key".to_owned(),
            command: ServiceCommand::StartTask(changed_budget),
        })
        .await
        .expect_err("changed budget must conflict after reconnect");
    assert_eq!(conflict.code(), ServiceClientErrorCode::Rejected);
    let active = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let result = second
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
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
    assert_eq!(active.budget, admitted_budget);
    assert_eq!(state.lock().unwrap().interrupts, 0);

    for request_id in ["cancel-1", "cancel-2"] {
        assert_eq!(
            second
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
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
                protocol_version: SERVICE_PROTOCOL_VERSION,
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
async fn shutdown_preempts_queued_work_and_completes_its_receipt() -> TestResult {
    let layout = Layout::new()?;
    let port = PendingPort::new();
    let state = Arc::clone(&port.state);
    let service = TaskService::bind(&layout.data, port).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    let start = |session: &str, request: &str| StartTaskCommand {
        external_session_id: session.to_owned(),
        workspace: layout.workspace.clone(),
        request: request.to_owned(),
        model: ModelId::parse("gpt-test").expect("test model is valid"),
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::FullAccess,
        budget: TaskBudget::default(),
    };
    let ServiceResult::Accepted {
        task_id: active_task,
    } = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "preempt-start-active".to_owned(),
            idempotency_key: "preempt-start-active-key".to_owned(),
            command: ServiceCommand::StartTask(start(
                "preempt-active-session",
                "remain active until owner shutdown",
            )),
        })
        .await?
    else {
        return Err("active shutdown task was not accepted".into());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ServiceResult::Snapshot(snapshot) = client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("preempt-active-status-{}", Uuid::new_v4()),
                    idempotency_key: format!("preempt-active-status-key-{}", Uuid::new_v4()),
                    command: ServiceCommand::Status {
                        task_id: active_task,
                    },
                })
                .await
                .expect("active shutdown status succeeds")
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
    let ServiceResult::Accepted {
        task_id: queued_task,
    } = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "preempt-start-queued".to_owned(),
            idempotency_key: "preempt-start-queued-key".to_owned(),
            command: ServiceCommand::StartTask(start(
                "preempt-queued-session",
                "must never reach the provider after owner shutdown",
            )),
        })
        .await?
    else {
        return Err("queued shutdown task was not accepted".into());
    };
    let ServiceResult::Snapshot(queued) = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "preempt-queued-status".to_owned(),
            idempotency_key: "preempt-queued-status-key".to_owned(),
            command: ServiceCommand::Status {
                task_id: queued_task,
            },
        })
        .await?
    else {
        return Err("queued shutdown status missing".into());
    };
    assert_eq!(queued.status, TaskStatus::Queued);
    let provider_before = {
        let state = state.lock().unwrap();
        (state.started_contexts, state.resumed_contexts, state.epoch)
    };
    assert_eq!(provider_before.0 + provider_before.1, 1);

    let shutdown = tokio::time::timeout(
        Duration::from_secs(1),
        client.request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "preempt-shutdown".to_owned(),
            idempotency_key: "preempt-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        }),
    )
    .await;
    let shutdown_applied = match shutdown {
        Ok(Ok(ServiceResult::Applied)) => true,
        Ok(Ok(other)) => return Err(format!("unexpected shutdown response: {other:?}").into()),
        Ok(Err(error)) => return Err(format!("shutdown was rejected: {error:?}").into()),
        Err(_) => false,
    };
    drop(client);
    if shutdown_applied {
        tokio::time::timeout(Duration::from_secs(5), running).await???;
    } else {
        running.abort();
        let _ = running.await;
    }

    let provider_after = {
        let state = state.lock().unwrap();
        (
            state.started_contexts,
            state.resumed_contexts,
            state.epoch,
            state.shutdowns,
        )
    };
    let connection = Connection::open(layout.data.join("carl.sqlite3"))?;
    let (receipt_state, result_json) = connection.query_row(
        "SELECT state, result_json FROM service_command_receipts
         WHERE idempotency_key = 'preempt-shutdown-key'",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
    )?;
    let pending = connection.query_row(
        "SELECT COUNT(*) FROM service_command_receipts WHERE state = 'pending'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert!(
        shutdown_applied,
        "shutdown did not preempt queued work: provider before={provider_before:?}, after={provider_after:?}, receipt={receipt_state}, pending={pending}"
    );
    assert_eq!(
        (provider_after.0, provider_after.1, provider_after.2),
        provider_before,
        "queued task reached the provider during shutdown"
    );
    assert_eq!(provider_after.3, 1, "provider shutdown was not exact");
    assert_eq!(receipt_state, "completed");
    assert!(
        result_json
            .as_deref()
            .is_some_and(|result| serde_json::from_str::<serde_json::Value>(result).is_ok())
    );
    assert_eq!(pending, 0);
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn read_polling_does_not_exhaust_process_or_connection_mutation_capacity() -> TestResult {
    let layout = Layout::new()?;
    let port = PendingPort::new();
    let state = Arc::clone(&port.state);
    let service = TaskService::bind(&layout.data, port).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    let ServiceResult::Accepted { task_id } = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "ledger-start".to_owned(),
            idempotency_key: "ledger-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "ledger-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "remain controllable after sustained polling".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
                budget: TaskBudget::default(),
            }),
        })
        .await?
    else {
        return Err("ledger task was not accepted".into());
    };

    for index in 0..8_200_u32 {
        let command = if index % 2 == 0 {
            ServiceCommand::Status { task_id }
        } else {
            ServiceCommand::Events {
                task_id,
                after_sequence: Some(0),
                limit: 1,
            }
        };
        client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: format!("ledger-read-{index}"),
                idempotency_key: format!("ledger-read-key-{index}"),
                command,
            })
            .await
            .map_err(|error| format!("read request {index} failed: {error:?}"))?;
    }

    assert_eq!(
        client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "ledger-cancel".to_owned(),
                idempotency_key: "ledger-cancel-key".to_owned(),
                command: ServiceCommand::Cancel { task_id },
            })
            .await?,
        ServiceResult::Applied
    );
    assert_eq!(state.lock().unwrap().interrupts, 1);
    assert_eq!(
        client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "ledger-shutdown".to_owned(),
                idempotency_key: "ledger-shutdown-key".to_owned(),
                command: ServiceCommand::Shutdown,
            })
            .await?,
        ServiceResult::Applied
    );
    running.await??;
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "signal-start".to_owned(),
            idempotency_key: "signal-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "signal-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "remain durable when the owner process stops".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
                budget: TaskBudget::default(),
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
                    protocol_version: SERVICE_PROTOCOL_VERSION,
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
async fn service_info_identifies_the_ephemeral_live_cursor_generation() -> TestResult {
    let layout = Layout::new()?;
    let service = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    let info = serde_json::to_value(client.info())?;
    let generation = info["live_generation"]
        .as_str()
        .ok_or("service live generation missing")?;
    assert_eq!(generation.len(), 36);
    assert!(Uuid::parse_str(generation).is_ok());
    client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "generation-shutdown".to_owned(),
            idempotency_key: "generation-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        })
        .await?;
    running.await??;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn live_update_pages_bind_cursors_to_the_owner_generation() -> TestResult {
    let layout = Layout::new()?;
    let service = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    let generation = client.info().live_generation.clone();
    let ServiceResult::Accepted { task_id } = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "live-generation-start".to_owned(),
            idempotency_key: "live-generation-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "live-generation-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "hold for a generation-bound poll".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
                budget: TaskBudget::default(),
            }),
        })
        .await?
    else {
        return Err("generation task missing".into());
    };
    let page = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "live-generation-page".to_owned(),
            idempotency_key: "live-generation-page-key".to_owned(),
            command: ServiceCommand::LiveUpdates {
                task_id,
                live_generation: generation.clone(),
                after_cursor: None,
                limit: 128,
            },
        })
        .await?;
    let page = serde_json::to_value(page)?;
    assert_eq!(page["value"]["live_generation"], generation);
    client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "live-generation-cancel".to_owned(),
            idempotency_key: "live-generation-cancel-key".to_owned(),
            command: ServiceCommand::Cancel { task_id },
        })
        .await?;
    client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "live-generation-page-shutdown".to_owned(),
            idempotency_key: "live-generation-page-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        })
        .await?;
    running.await??;
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
        budget: TaskBudget::default(),
    });
    let service = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    let ServiceResult::Accepted { task_id } = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "durable-cancel".to_owned(),
            idempotency_key: "durable-cancel-key".to_owned(),
            command: ServiceCommand::Cancel { task_id },
        })
        .await?;
    client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "durable-start-2".to_owned(),
                idempotency_key: "durable-start-key".to_owned(),
                command,
            })
            .await?,
        ServiceResult::Accepted { task_id }
    );
    let ServiceResult::TaskList(tasks) = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
async fn every_service_mutation_replays_durably_and_keys_never_rebind() -> TestResult {
    let layout = Layout::new()?;
    let service = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    let start = ServiceCommand::StartTask(StartTaskCommand {
        external_session_id: "global-receipt-session".to_owned(),
        workspace: layout.workspace.clone(),
        request: "exercise every durable service mutation".to_owned(),
        model: ModelId::parse("gpt-test")?,
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::FullAccess,
        budget: TaskBudget::default(),
    });
    let ServiceResult::Accepted { task_id } = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "global-start".to_owned(),
            idempotency_key: "global-start-key".to_owned(),
            command: start.clone(),
        })
        .await?
    else {
        return Err("global receipt task was not accepted".into());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ServiceResult::Snapshot(snapshot) = client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("global-status-{}", Uuid::new_v4()),
                    idempotency_key: format!("global-status-key-{}", Uuid::new_v4()),
                    command: ServiceCommand::Status { task_id },
                })
                .await
                .expect("global status succeeds")
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

    let mutations = [
        ("global-resume-key", ServiceCommand::Resume { task_id }),
        (
            "global-steer-key",
            ServiceCommand::Steer {
                task_id,
                text: "preserve this exact owner steering".to_owned(),
            },
        ),
        (
            "global-configure-key",
            ServiceCommand::Configure {
                task_id,
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
            },
        ),
        ("global-cancel-key", ServiceCommand::Cancel { task_id }),
    ];
    for (index, (key, command)) in mutations.iter().enumerate() {
        assert_eq!(
            client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("global-mutation-{index}"),
                    idempotency_key: (*key).to_owned(),
                    command: command.clone(),
                })
                .await?,
            ServiceResult::Applied
        );
    }
    assert_eq!(
        client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "global-shutdown".to_owned(),
                idempotency_key: "global-shutdown-key".to_owned(),
                command: ServiceCommand::Shutdown,
            })
            .await?,
        ServiceResult::Applied
    );
    running.await??;
    let connection = Connection::open(layout.data.join("carl.sqlite3"))?;
    for kind in [
        "start_task",
        "resume",
        "steer",
        "configure",
        "cancel",
        "shutdown",
    ] {
        let (state, result): (String, String) = connection.query_row(
            "SELECT state, result_json FROM service_command_receipts
             WHERE command_kind = ?1",
            [kind],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(state, "completed", "{kind} receipt remained non-canonical");
        assert!(serde_json::from_str::<serde_json::Value>(&result)?.is_object());
    }
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM service_command_receipts WHERE state = 'pending'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0,
        "successful service mutations must not leave pending owner receipts"
    );

    let replacement_port = PendingPort::new();
    let replacement_state = Arc::clone(&replacement_port.state);
    let replacement = TaskService::bind(&layout.data, replacement_port).await?;
    let replacement_running = tokio::spawn(replacement.serve(CancellationToken::new()));
    let mut replay = TaskServiceClient::connect(&layout.data).await?;
    assert_eq!(
        replay
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "global-start-replay".to_owned(),
                idempotency_key: "global-start-key".to_owned(),
                command: start,
            })
            .await?,
        ServiceResult::Accepted { task_id }
    );
    for (index, (key, command)) in mutations.iter().enumerate() {
        assert_eq!(
            replay
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("global-replay-{index}"),
                    idempotency_key: (*key).to_owned(),
                    command: command.clone(),
                })
                .await?,
            ServiceResult::Applied
        );
    }
    drop(replay);

    for (key, _) in
        std::iter::once(&("global-start-key", ServiceCommand::List)).chain(mutations.iter())
    {
        let mut conflict = TaskServiceClient::connect(&layout.data).await?;
        assert!(
            conflict
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("global-conflict-{key}"),
                    idempotency_key: (*key).to_owned(),
                    command: ServiceCommand::Cancel {
                        task_id: TaskId::new(),
                    },
                })
                .await
                .is_err(),
            "global key {key} must reject method/task/payload rebinding"
        );
    }
    {
        let state = replacement_state.lock().unwrap();
        assert_eq!(state.started_contexts, 0);
        assert_eq!(state.resumed_contexts, 0);
        assert_eq!(state.interrupts, 0);
    }
    let mut shutdown = TaskServiceClient::connect(&layout.data).await?;
    assert_eq!(
        shutdown
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "global-shutdown-replay".to_owned(),
                idempotency_key: "global-shutdown-key".to_owned(),
                command: ServiceCommand::Shutdown,
            })
            .await?,
        ServiceResult::Applied
    );
    replacement_running.await??;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn pending_service_receipts_reconcile_control_crash_windows_without_duplicate_work()
-> TestResult {
    for method in ["resume", "steer", "configure", "cancel"] {
        let layout = Layout::new()?;
        let service = TaskService::bind(&layout.data, PendingPort::new()).await?;
        let running = tokio::spawn(service.serve(CancellationToken::new()));
        let mut client = TaskServiceClient::connect(&layout.data).await?;
        let ServiceResult::Accepted { task_id } = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: format!("pending-{method}-start"),
                idempotency_key: format!("pending-{method}-start-key"),
                command: ServiceCommand::StartTask(StartTaskCommand {
                    external_session_id: format!("pending-{method}-session"),
                    workspace: layout.workspace.clone(),
                    request: format!("exercise the {method} receipt crash window"),
                    model: ModelId::parse("gpt-test")?,
                    effort: ReasoningEffort::High,
                    permission_mode: PermissionMode::FullAccess,
                    budget: TaskBudget::default(),
                }),
            })
            .await?
        else {
            return Err(format!("pending {method} task was not accepted").into());
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let ServiceResult::Snapshot(snapshot) = client
                    .request(ServiceRequest {
                        protocol_version: SERVICE_PROTOCOL_VERSION,
                        request_id: format!("pending-{method}-status-{}", Uuid::new_v4()),
                        idempotency_key: format!("pending-{method}-status-key-{}", Uuid::new_v4()),
                        command: ServiceCommand::Status { task_id },
                    })
                    .await
                    .expect("pending status succeeds")
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
        let key = format!("pending-{method}-key");
        let command = match method {
            "resume" => ServiceCommand::Resume { task_id },
            "steer" => ServiceCommand::Steer {
                task_id,
                text: "one crash-window steering intent".to_owned(),
            },
            "configure" => ServiceCommand::Configure {
                task_id,
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
            },
            "cancel" => ServiceCommand::Cancel { task_id },
            _ => unreachable!(),
        };
        rusqlite::Connection::open(layout.data.join("carl.sqlite3"))?.execute_batch(&format!(
            "CREATE TRIGGER fail_{method}_service_receipt
             BEFORE UPDATE OF state ON service_command_receipts
             WHEN OLD.idempotency_key = '{key}' AND NEW.state = 'completed'
             BEGIN SELECT RAISE(FAIL, 'forced service receipt completion failure'); END;"
        ))?;
        assert!(
            client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("pending-{method}-first"),
                    idempotency_key: key.clone(),
                    command: command.clone(),
                })
                .await
                .is_err(),
            "{method} must expose the forced post-action receipt failure"
        );
        assert_eq!(
            rusqlite::Connection::open(layout.data.join("carl.sqlite3"))?.query_row(
                "SELECT state FROM service_command_receipts WHERE idempotency_key = ?1",
                [&key],
                |row| row.get::<_, String>(0),
            )?,
            "pending"
        );
        running.abort();
        let _ = running.await;
        drop(client);
        rusqlite::Connection::open(layout.data.join("carl.sqlite3"))?
            .execute_batch(&format!("DROP TRIGGER fail_{method}_service_receipt"))?;

        let replacement_port = PendingPort::new();
        let replacement_state = Arc::clone(&replacement_port.state);
        let replacement = TaskService::bind(&layout.data, replacement_port).await?;
        let baseline = {
            let state = replacement_state.lock().unwrap();
            (
                state.started_contexts,
                state.resumed_contexts,
                state.interrupts,
            )
        };
        let replacement_running = tokio::spawn(replacement.serve(CancellationToken::new()));
        let mut retry = TaskServiceClient::connect(&layout.data).await?;
        let retried = retry
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: format!("pending-{method}-retry"),
                idempotency_key: key,
                command,
            })
            .await
            .map_err(|error| format!("{method} pending retry failed: {error:?}"))?;
        assert_eq!(
            retried,
            ServiceResult::Applied,
            "{method} pending receipt must reconcile canonically"
        );
        {
            let state = replacement_state.lock().unwrap();
            assert_eq!(
                (
                    state.started_contexts,
                    state.resumed_contexts,
                    state.interrupts
                ),
                baseline,
                "{method} retry duplicated provider work"
            );
        }
        retry
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: format!("pending-{method}-shutdown"),
                idempotency_key: format!("pending-{method}-shutdown-key"),
                command: ServiceCommand::Shutdown,
            })
            .await?;
        replacement_running.await??;
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn pending_cancel_marker_without_terminal_state_resumes_the_same_control() -> TestResult {
    use sha2::{Digest as _, Sha256};

    let layout = Layout::new()?;
    let service = TaskService::bind(&layout.data, PendingPort::new()).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));
    let mut client = TaskServiceClient::connect(&layout.data).await?;
    let ServiceResult::Accepted { task_id } = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "marker-only-start".to_owned(),
            idempotency_key: "marker-only-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "marker-only-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "cancel from a marker-only crash cut".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
                budget: TaskBudget::default(),
            }),
        })
        .await?
    else {
        return Err("marker-only task was not accepted".into());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ServiceResult::Snapshot(snapshot) = client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("marker-status-{}", Uuid::new_v4()),
                    idempotency_key: format!("marker-status-key-{}", Uuid::new_v4()),
                    command: ServiceCommand::Status { task_id },
                })
                .await
                .expect("marker status succeeds")
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
    running.abort();
    let _ = running.await;
    drop(client);

    let key = "marker-only-cancel-key";
    let command = ServiceCommand::Cancel { task_id };
    let digest = command_digest(&command)?;
    let receipt = ServiceCommandReceiptInput {
        idempotency_key: key.to_owned(),
        command_digest: Sha256Digest::parse(
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )?,
        command_kind: "cancel".to_owned(),
        created_at: Utc::now(),
    };
    let mut store = Store::open(layout.data.join("carl.sqlite3"))?;
    assert_eq!(
        store.claim_service_command(receipt)?,
        ServiceCommandReceiptClaim::Fresh
    );
    let control_id = format!(
        "{:x}",
        Sha256::digest(format!("carl-service-v1:{task_id}:cancel:{key}").as_bytes())
    );
    let current = store.get_task(task_id)?.ok_or("marker task missing")?;
    assert!(!current.snapshot.status.is_terminal());
    store
        .append_task_event(
            task_id,
            current.revision,
            TaskEvent::ControlRequested {
                control_id: control_id.clone(),
                kind: TaskControlKind::Cancel,
            },
            Utc::now(),
        )?
        .ok_or("cancel marker was not appended")?;
    drop(store);

    let replacement_port = PendingPort::new();
    let replacement_state = Arc::clone(&replacement_port.state);
    let replacement = TaskService::bind(&layout.data, replacement_port).await?;
    let replacement_running = tokio::spawn(replacement.serve(CancellationToken::new()));
    let mut retry = TaskServiceClient::connect(&layout.data).await?;
    assert_eq!(
        retry
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "marker-only-cancel-retry".to_owned(),
                idempotency_key: key.to_owned(),
                command,
            })
            .await?,
        ServiceResult::Applied
    );
    assert_eq!(
        rusqlite::Connection::open(layout.data.join("carl.sqlite3"))?.query_row(
            "SELECT COUNT(*) FROM task_control_markers
             WHERE task_id = ?1 AND control_id = ?2 AND kind = 'cancel'",
            rusqlite::params![task_id.to_string(), control_id],
            |row| row.get::<_, i64>(0),
        )?,
        1,
        "retry must not append a second cancel marker"
    );
    assert!(replacement_state.lock().unwrap().interrupts <= 1);
    assert_eq!(
        Store::open(layout.data.join("carl.sqlite3"))?
            .get_task(task_id)?
            .ok_or("cancelled marker task missing")?
            .snapshot
            .status,
        TaskStatus::Cancelled
    );
    retry
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "marker-only-shutdown".to_owned(),
            idempotency_key: "marker-only-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        })
        .await?;
    replacement_running.await??;
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
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: format!("startup-start-{index}"),
                idempotency_key: format!("startup-start-key-{index}"),
                command: ServiceCommand::StartTask(StartTaskCommand {
                    external_session_id: "startup-session".to_owned(),
                    workspace: layout.workspace.clone(),
                    request: format!("durable startup task {index}"),
                    model: ModelId::parse("gpt-test")?,
                    effort: ReasoningEffort::High,
                    permission_mode: PermissionMode::FullAccess,
                    budget: TaskBudget::default(),
                }),
            })
            .await?
        else {
            return Err("startup task was not accepted".into());
        };
    }
    let ServiceResult::TaskList(tasks) = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "slow-start".to_owned(),
            idempotency_key: "slow-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "slow-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "stay active while a slow frontend is evicted".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
                budget: TaskBudget::default(),
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
                    protocol_version: SERVICE_PROTOCOL_VERSION,
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
            budget: TaskBudget::default(),
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "slow-cancel".to_owned(),
            idempotency_key: "slow-cancel-key".to_owned(),
            command: ServiceCommand::Cancel { task_id },
        })
        .await?;
    owner
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
async fn owner_restart_resets_live_cursor_for_assistant_diff_and_approval_once() -> TestResult {
    let layout = Layout::new()?;
    let shared = Arc::new(Mutex::new(RestartApprovalState {
        workspace: layout.workspace.clone(),
        ..RestartApprovalState::default()
    }));
    let first_service = TaskService::bind(
        &layout.data,
        RestartApprovalPort::new(Arc::clone(&shared), false),
    )
    .await?;
    let first_running = tokio::spawn(first_service.serve(CancellationToken::new()));
    let mut first = TaskServiceClient::connect(&layout.data).await?;
    let first_generation = first.info().live_generation.clone();
    let ServiceResult::Accepted { task_id } = first
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "restart-live-start".to_owned(),
            idempotency_key: "restart-live-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "restart-live-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "request approval only after owner restart".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::Default,
                budget: TaskBudget::default(),
            }),
        })
        .await
        .map_err(|error| format!("restart live start failed: {error}"))?
    else {
        return Err("restart live task missing".into());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while !shared.lock().unwrap().initial_work_started {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let first_live_cursor = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ServiceResult::LiveUpdates(page) = first
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("restart-live-old-page-{}", Uuid::new_v4()),
                    idempotency_key: format!("restart-live-old-key-{}", Uuid::new_v4()),
                    command: ServiceCommand::LiveUpdates {
                        task_id,
                        live_generation: first_generation.clone(),
                        after_cursor: None,
                        limit: 128,
                    },
                })
                .await
                .expect("old-generation live page succeeds")
            else {
                continue;
            };
            if let Some(cursor) = page.cursor {
                break cursor;
            }
        }
    })
    .await?;
    assert!(first_live_cursor > 0);
    drop(first);
    first_running.abort();
    let _ = first_running.await;
    for _ in 0..100 {
        if !layout.data.join("carl.sock").exists() {
            break;
        }
        tokio::task::yield_now().await;
    }

    let replacement_service = TaskService::bind(
        &layout.data,
        RestartApprovalPort::new(Arc::clone(&shared), true),
    )
    .await?;
    let replacement_running = tokio::spawn(replacement_service.serve(CancellationToken::new()));
    let mut replacement = TaskServiceClient::connect(&layout.data).await?;
    let replacement_generation = replacement.info().live_generation.clone();
    assert_ne!(replacement_generation, first_generation);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !shared.lock().unwrap().replacement_effect_requested {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let acp = ServiceAcpServer::new(
        &layout.data,
        AcpServerConfig {
            frontend: Frontend::Acp,
            model: Some(ModelId::parse("gpt-test")?),
            effort: Some(ReasoningEffort::High),
            permission_mode: PermissionMode::Default,
            budget: TaskBudget::default(),
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
                json!({"jsonrpc":"2.0","id":20,"method":"initialize","params":{"protocolVersion":1,"clientInfo":{"name":"restart-generation","version":"1.0.0"},"clientCapabilities":{}}}),
                json!({"jsonrpc":"2.0","id":21,"method":"session/load","params":{"sessionId":"restart-live-session","cwd":layout.workspace.clone(),"mcpServers":[],"taskId":task_id,"lastLiveGeneration":first_generation.clone(),"lastLiveCursor":first_live_cursor}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let mut initialized = false;
    let mut load_response = None;
    let mut acp_assistant = 0_u64;
    let mut acp_diff = 0_u64;
    let mut acp_approval = 0_u64;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = read_frame(&mut reader, 1024 * 1024)
                .await
                .expect("restart ACP frame is valid")
                .expect("restart ACP frame missing");
            initialized |= frame.value()["id"] == 20;
            if frame.value()["id"] == 21 {
                load_response = Some(frame.value().clone());
            }
            acp_assistant += u64::from(
                frame.value()["params"]["update"]["content"]["text"] == "replacement assistant",
            );
            acp_diff += u64::from(
                frame.value()["params"]["update"]["content"][0]["diff"]
                    == "diff --git a/replacement b/replacement",
            );
            acp_approval += u64::from(
                frame.value()["params"]["update"]["content"]["text"]
                    .as_str()
                    .is_some_and(|text| text.starts_with("Approval required:")),
            );
            if initialized
                && load_response.is_some()
                && acp_assistant == 1
                && acp_diff == 1
                && acp_approval == 1
            {
                break;
            }
        }
    })
    .await?;
    let load_response = load_response.ok_or("restart ACP load response missing")?;
    assert_eq!(
        load_response["result"]["_meta"]["lastLiveGeneration"],
        replacement_generation
    );
    assert!(load_response["result"]["_meta"]["lastLiveCursor"].is_null());
    assert_eq!(acp_assistant, 1);
    assert_eq!(acp_diff, 1);
    assert_eq!(acp_approval, 1);
    let unexpected = tokio::time::timeout(
        Duration::from_millis(100),
        read_frame(&mut reader, 1024 * 1024),
    )
    .await;
    assert!(
        unexpected.is_err(),
        "ACP stale-generation replay emitted an unexpected duplicate frame"
    );
    drop(client_write);
    drop(reader);
    acp_task.await??;

    let ServiceResult::LiveUpdates(page) = replacement
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "restart-live-new-page".to_owned(),
            idempotency_key: "restart-live-new-page-key".to_owned(),
            command: ServiceCommand::LiveUpdates {
                task_id,
                live_generation: first_generation.clone(),
                after_cursor: Some(first_live_cursor),
                limit: 128,
            },
        })
        .await
        .map_err(|error| format!("replacement live page failed: {error}"))?
    else {
        return Err("replacement live page missing".into());
    };
    assert_eq!(page.live_generation, replacement_generation);
    assert_eq!(
        page.updates
            .iter()
            .filter(|update| matches!(update.update, TaskUpdate::AssistantDelta(_)))
            .count(),
        1
    );
    assert_eq!(
        page.updates
            .iter()
            .filter(|update| matches!(update.update, TaskUpdate::Diff(_)))
            .count(),
        1
    );
    let approvals = page
        .updates
        .iter()
        .filter_map(|update| match &update.update {
            TaskUpdate::ApprovalRequired {
                display_code,
                session_id,
                turn_id,
                ..
            } => Some((display_code.clone(), *session_id, *turn_id)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(approvals.len(), 1);
    let (display_code, session_id, turn_id) = approvals[0].clone();
    let live_cursor = page.cursor.ok_or("replacement live cursor missing")?;
    assert_eq!(
        replacement
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "restart-live-approve".to_owned(),
                idempotency_key: "restart-live-approve-key".to_owned(),
                command: ServiceCommand::ResolveApproval {
                    task_id,
                    external_session_id: "restart-live-session".to_owned(),
                    workspace: layout.workspace.clone(),
                    frontend: Frontend::Acp,
                    actor_id: ActorId::parse("local-owner")?,
                    channel_id: None,
                    event_id: None,
                    display_code,
                    session_id,
                    turn_id,
                    decision: carl::service::protocol::ServiceApprovalDecision::Approve,
                },
            })
            .await
            .map_err(|error| format!("restart approval resolution failed: {error}"))?,
        ServiceResult::Applied
    );
    let ServiceResult::LiveUpdates(after_resolution) = replacement
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "restart-live-after-resolution".to_owned(),
            idempotency_key: "restart-live-after-resolution-key".to_owned(),
            command: ServiceCommand::LiveUpdates {
                task_id,
                live_generation: replacement_generation,
                after_cursor: Some(live_cursor),
                limit: 128,
            },
        })
        .await
        .map_err(|error| format!("post-resolution live page failed: {error}"))?
    else {
        return Err("post-approval live page missing".into());
    };
    assert_eq!(
        after_resolution
            .updates
            .iter()
            .filter(|update| matches!(
                &update.update,
                TaskUpdate::AssistantDelta(text) if text == "replacement assistant"
            ))
            .count(),
        0
    );
    assert_eq!(
        after_resolution
            .updates
            .iter()
            .filter(|update| matches!(
                &update.update,
                TaskUpdate::Diff(diff) if diff == "diff --git a/replacement b/replacement"
            ))
            .count(),
        0
    );
    assert_eq!(
        after_resolution
            .updates
            .iter()
            .filter(|update| matches!(update.update, TaskUpdate::ApprovalRequired { .. }))
            .count(),
        0
    );
    let completed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ServiceResult::Snapshot(snapshot) = replacement
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("restart-live-status-{}", Uuid::new_v4()),
                    idempotency_key: format!("restart-live-status-key-{}", Uuid::new_v4()),
                    command: ServiceCommand::Status { task_id },
                })
                .await
                .expect("restart live status succeeds")
            else {
                continue;
            };
            if snapshot.status == TaskStatus::Completed {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(completed.task_id, task_id);
    replacement
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "restart-live-shutdown".to_owned(),
            idempotency_key: "restart-live-shutdown-key".to_owned(),
            command: ServiceCommand::Shutdown,
        })
        .await
        .map_err(|error| format!("restart live shutdown failed: {error}"))?;
    replacement_running.await??;
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "restart-start".to_owned(),
            idempotency_key: "restart-start-key".to_owned(),
            command: ServiceCommand::StartTask(StartTaskCommand {
                external_session_id: "restart-owner".to_owned(),
                workspace: layout.workspace.clone(),
                request: "apply one effect, checkpoint, and finish after restart".to_owned(),
                model: ModelId::parse("gpt-test")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::FullAccess,
                budget: TaskBudget::default(),
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
                    protocol_version: SERVICE_PROTOCOL_VERSION,
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
    let first_generation = first.info().live_generation.clone();
    let first_live_cursor = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ServiceResult::LiveUpdates(page) = first
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: format!("live-before-crash-{}", Uuid::new_v4()),
                    idempotency_key: format!("live-before-crash-key-{}", Uuid::new_v4()),
                    command: ServiceCommand::LiveUpdates {
                        task_id,
                        live_generation: first_generation.clone(),
                        after_cursor: None,
                        limit: 128,
                    },
                })
                .await
                .expect("live page before restart succeeds")
            else {
                continue;
            };
            if let Some(cursor) = page.cursor {
                break cursor;
            }
        }
    })
    .await?;
    assert!(first_live_cursor > 0);
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
                    protocol_version: SERVICE_PROTOCOL_VERSION,
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
    let replacement_generation = replacement.info().live_generation.clone();
    assert_ne!(replacement_generation, first_generation);
    let ServiceResult::LiveUpdates(restarted_live) = replacement
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "live-after-restart".to_owned(),
            idempotency_key: "live-after-restart-key".to_owned(),
            command: ServiceCommand::LiveUpdates {
                task_id,
                live_generation: first_generation,
                after_cursor: Some(first_live_cursor),
                limit: 128,
            },
        })
        .await?
    else {
        return Err("live page after restart missing".into());
    };
    assert_eq!(restarted_live.live_generation, replacement_generation);
    assert_eq!(
        restarted_live
            .updates
            .iter()
            .filter(|update| matches!(update.update, TaskUpdate::AssistantDelta(_)))
            .count(),
        1,
        "the replacement owner's first assistant update must not be compared to the old cursor"
    );
    assert_eq!(
        restarted_live
            .updates
            .iter()
            .filter(|update| matches!(update.update, TaskUpdate::Diff(_)))
            .count(),
        1,
        "the replacement owner's first diff must be delivered once"
    );
    let replacement_live_cursor = restarted_live.cursor.ok_or("replacement cursor missing")?;
    let ServiceResult::LiveUpdates(no_duplicate_live) = replacement
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "live-after-restart-again".to_owned(),
            idempotency_key: "live-after-restart-again-key".to_owned(),
            command: ServiceCommand::LiveUpdates {
                task_id,
                live_generation: replacement_generation,
                after_cursor: Some(replacement_live_cursor),
                limit: 128,
            },
        })
        .await?
    else {
        return Err("second live page after restart missing".into());
    };
    assert!(no_duplicate_live.updates.is_empty());
    let ServiceResult::Events(after_restart) = replacement
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
    let ServiceResult::Metrics(restart_metrics) = replacement
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "metrics-after-owner-restart".to_owned(),
            idempotency_key: "metrics-after-owner-restart-key".to_owned(),
            command: ServiceCommand::Metrics { task_id },
        })
        .await?
    else {
        return Err("metrics after owner restart missing".into());
    };
    assert_eq!(restart_metrics.task_id, task_id);
    assert_eq!(restart_metrics.status, TaskStatus::Completed);
    assert_eq!(restart_metrics.provider_requests, 3);
    assert_eq!(restart_metrics.epochs_started, 3);
    assert_eq!(restart_metrics.epochs_completed, 3);
    assert_eq!(restart_metrics.operation_intents, 1);
    assert_eq!(restart_metrics.operations_succeeded, 1);
    assert_eq!(restart_metrics.unresolved_operations, 0);
    assert_eq!(
        replacement
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
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
    let admitted_budget = TaskBudget {
        max_wall_time_seconds: Some(1_800),
        max_provider_requests: Some(111),
        max_tool_calls: Some(222),
        soft_epoch_seconds: 300,
        soft_epoch_tool_calls: 33,
    };

    let acp = ServiceAcpServer::new(
        &layout.data,
        AcpServerConfig {
            frontend: Frontend::Acp,
            model: Some(ModelId::parse("gpt-test")?),
            effort: Some(ReasoningEffort::High),
            permission_mode: PermissionMode::FullAccess,
            budget: admitted_budget,
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
    assert_eq!(tasks[0].budget, admitted_budget);

    let reloaded_acp = ServiceAcpServer::new(
        &layout.data,
        AcpServerConfig {
            frontend: Frontend::Acp,
            model: Some(ModelId::parse("gpt-test")?),
            effort: Some(ReasoningEffort::High),
            permission_mode: PermissionMode::FullAccess,
            budget: TaskBudget {
                max_wall_time_seconds: Some(60),
                max_provider_requests: Some(2),
                max_tool_calls: Some(3),
                soft_epoch_seconds: 30,
                soft_epoch_tool_calls: 1,
            },
            buzz_publisher: None,
        },
    )
    .await?;
    let (reload_client, reload_server) = tokio::io::duplex(64 * 1024);
    let (reload_read, mut reload_write) = tokio::io::split(reload_client);
    let (reload_server_read, reload_server_write) = tokio::io::split(reload_server);
    let reload_task =
        tokio::spawn(reloaded_acp.serve(BufReader::new(reload_server_read), reload_server_write));
    let mut reload_reader = BufReader::new(reload_read);
    reload_write
        .write_all(
            format!(
                "{}\n{}\n",
                json!({"jsonrpc":"2.0","id":10,"method":"initialize","params":{"protocolVersion":1,"clientInfo":{"name":"budget-reload","version":"1.0.0"},"clientCapabilities":{}}}),
                json!({"jsonrpc":"2.0","id":11,"method":"session/load","params":{"sessionId":session_id,"cwd":layout.workspace,"mcpServers":[],"taskId":task_id}})
            )
            .as_bytes(),
        )
        .await?;
    reload_write.flush().await?;
    assert_eq!(
        read_frame(&mut reload_reader, 1024 * 1024)
            .await?
            .ok_or("reload initialize response missing")?
            .value()["id"],
        10
    );
    assert_eq!(
        read_frame(&mut reload_reader, 1024 * 1024)
            .await?
            .ok_or("reload session response missing")?
            .value()["id"],
        11
    );
    drop(reload_write);
    drop(reload_reader);
    reload_task.await??;
    let ServiceResult::Snapshot(reloaded) = owner
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "acp-reloaded-budget-status".to_owned(),
            idempotency_key: "acp-reloaded-budget-status-key".to_owned(),
            command: ServiceCommand::Status { task_id },
        })
        .await?
    else {
        return Err("reloaded task status missing".into());
    };
    assert_eq!(reloaded.budget, admitted_budget);
    assert_eq!(
        owner
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
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
                protocol_version: SERVICE_PROTOCOL_VERSION,
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
    let admitted_budget = TaskBudget {
        max_wall_time_seconds: Some(3_600),
        max_provider_requests: Some(222),
        max_tool_calls: Some(333),
        soft_epoch_seconds: 450,
        soft_epoch_tool_calls: 55,
    };

    let trusted = |actor_id: ActorId, event_id: char| {
        ServiceCommand::StartTrustedTask(TrustedStartTaskCommand {
            start: StartTaskCommand {
                external_session_id: "buzz-service-session".to_owned(),
                workspace: layout.workspace.clone(),
                request: "trusted owner task".to_owned(),
                model: ModelId::parse("gpt-test").expect("test model is valid"),
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::Plan,
                budget: admitted_budget,
            },
            frontend: Frontend::Buzz,
            actor_id,
            channel_id: Uuid::nil().to_string(),
            event_id: event_id.to_string().repeat(64),
        })
    };
    let rejected = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "buzz-accepted".to_owned(),
            idempotency_key: "buzz-accepted-key".to_owned(),
            command: trusted(actor, '2'),
        })
        .await?
    else {
        return Err("trusted task was not accepted".into());
    };
    let ServiceResult::TaskList(tasks) = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "buzz-list-budget".to_owned(),
            idempotency_key: "buzz-list-budget-key".to_owned(),
            command: ServiceCommand::List,
        })
        .await?
    else {
        return Err("trusted task list missing".into());
    };
    assert_eq!(
        tasks
            .iter()
            .find(|snapshot| snapshot.task_id == task_id)
            .map(|snapshot| snapshot.budget),
        Some(admitted_budget)
    );
    client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "buzz-cancel".to_owned(),
            idempotency_key: "buzz-cancel-key".to_owned(),
            command: ServiceCommand::Cancel { task_id },
        })
        .await?;
    client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
    assert_eq!(binding.permission_mode, PermissionMode::Plan);
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
            budget: TaskBudget::default(),
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
            budget: TaskBudget::default(),
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
        emit_live: true,
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
            budget: TaskBudget::default(),
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
    .await
    .map_err(|_| "three-epoch initial effect was not ready")?;

    let mut owner = TaskServiceClient::connect(&layout.data).await?;
    let ServiceResult::TaskList(tasks) = owner
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
            protocol_version: SERVICE_PROTOCOL_VERSION,
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
    tokio::time::timeout(Duration::from_secs(5), acp_task)
        .await
        .map_err(|_| "three-epoch first ACP connection did not close")???;
    assert_eq!(shared.lock().unwrap().interrupts, 0);

    shared.lock().unwrap().release_epoch_one = true;
    tokio::time::timeout(Duration::from_secs(5), async {
        while shared.lock().unwrap().work_epochs < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "three-epoch second work epoch did not start")?;

    let reconnect = ServiceAcpServer::new(
        &layout.data,
        AcpServerConfig {
            frontend: Frontend::Acp,
            model: None,
            effort: None,
            permission_mode: PermissionMode::FullAccess,
            budget: TaskBudget::default(),
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
                .await
                .map_err(|_| "three-epoch load response timed out")??
                .ok_or("three-epoch load response missing")?;
        loaded = frame.value()["id"] == 11;
    }
    client_write
        .write_all(
            format!(
                "{}\n",
                json!({"jsonrpc":"2.0","id":12,"method":"session/prompt","params":{"sessionId":session_id,"prompt":[{"type":"text","text":"continue from the loaded durable cursor"}]}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while shared.lock().unwrap().user_steers < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "three-epoch reconnect steer did not reach the provider")?;

    let mut replayed = Vec::new();
    let mut visible_assistant = 0_u64;
    let mut visible_diff = 0_u64;
    for (id, prompt) in [
        (120, vec!["\n/metrics"]),
        (121, vec!["\r\n/metrics"]),
        (122, vec!["\t/metrics"]),
        (123, vec![" /metrics"]),
        (124, vec!["/metrics\n"]),
        (125, vec!["/metrics "]),
        (126, vec!["/metrics", "second block"]),
        (127, vec!["\"/metrics\""]),
    ] {
        client_write
            .write_all(
                format!(
                    "{}\n",
                    json!({
                        "jsonrpc":"2.0","id":id,"method":"session/prompt","params":{
                            "sessionId":session_id,
                            "prompt":prompt.into_iter().map(|text| json!({"type":"text","text":text})).collect::<Vec<_>>()
                        }
                    })
                )
                .as_bytes(),
            )
            .await?;
        client_write.flush().await?;
        let response = loop {
            let frame =
                tokio::time::timeout(Duration::from_secs(5), read_frame(&mut reader, 1024 * 1024))
                    .await??
                    .ok_or("malformed metrics response missing")?;
            if let Some(sequence) = frame.value()["params"]["_meta"]["eventSequence"].as_u64() {
                replayed.push(sequence);
            }
            visible_assistant += u64::from(
                frame.value()["params"]["update"]["content"]["text"] == "visible assistant update",
            );
            visible_diff += u64::from(
                frame.value()["params"]["update"]["content"][0]["diff"]
                    == "diff --git a/live b/live",
            );
            if frame.value()["id"] == id {
                break frame;
            }
        };
        assert_eq!(
            response.value()["error"]["code"],
            -32602,
            "non-exact metrics prompt must remain ordinary input: {response:?}"
        );
    }

    client_write
        .write_all(
            format!(
                "{}\n",
                json!({"jsonrpc":"2.0","id":128,"method":"session/prompt","params":{"sessionId":session_id,"prompt":[{"type":"text","text":"/metrics"}]}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let mut saw_exact_metrics = false;
    loop {
        let frame =
            tokio::time::timeout(Duration::from_secs(5), read_frame(&mut reader, 1024 * 1024))
                .await??
                .ok_or("exact metrics response missing")?;
        if let Some(sequence) = frame.value()["params"]["_meta"]["eventSequence"].as_u64() {
            replayed.push(sequence);
        }
        visible_assistant += u64::from(
            frame.value()["params"]["update"]["content"]["text"] == "visible assistant update",
        );
        visible_diff += u64::from(
            frame.value()["params"]["update"]["content"][0]["diff"] == "diff --git a/live b/live",
        );
        if let Some(text) = frame.value()["params"]["update"]["content"]["text"].as_str()
            && serde_json::from_str::<serde_json::Value>(text)
                .is_ok_and(|value| value["metrics"]["schema_version"] == 1)
        {
            saw_exact_metrics = true;
        }
        if frame.value()["id"] == 128 {
            assert_eq!(frame.value()["result"]["stopReason"], "end_turn");
            break;
        }
    }
    assert!(
        saw_exact_metrics,
        "exact raw metrics command must remain enabled"
    );

    shared.lock().unwrap().release_epoch_two = true;

    let mut prompt_completed = false;
    let mut prompt_response = None;
    let mut durable_completed = false;
    let reconnect_result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = read_frame(&mut reader, 1024 * 1024)
                .await
                .expect("three-epoch replay frame valid")
                .expect("three-epoch replay frame missing");
            if let Some(sequence) = frame.value()["params"]["_meta"]["eventSequence"].as_u64() {
                replayed.push(sequence);
                if frame.value()["params"]["update"]["status"] == "completed" {
                    durable_completed = true;
                }
            }
            visible_assistant += u64::from(
                frame.value()["params"]["update"]["content"]["text"] == "visible assistant update",
            );
            visible_diff += u64::from(
                frame.value()["params"]["update"]["content"][0]["diff"]
                    == "diff --git a/live b/live",
            );
            if frame.value()["id"] == 12 {
                prompt_completed = true;
                prompt_response = Some(frame.value().clone());
            }
            if durable_completed && prompt_completed {
                break;
            }
        }
    })
    .await;
    if reconnect_result.is_err() {
        let state = shared.lock().unwrap();
        return Err(format!(
            "three-epoch reconnect replay did not complete: replayed={replayed:?}, assistant={visible_assistant}, diff={visible_diff}, prompt_completed={prompt_completed}, prompt_response={prompt_response:?}, durable_completed={durable_completed}, work_epochs={}, effects={}, completion_reports={}",
            state.work_epochs, state.effect_count, state.completion_reports
        )
        .into());
    }
    assert!(!replayed.is_empty());
    assert!(replayed.iter().all(|sequence| *sequence > cursor));
    assert!(
        replayed.windows(2).all(|pair| pair[0] < pair[1]),
        "durable replay duplicated or reordered: {replayed:?}"
    );
    assert_eq!(
        visible_assistant, 1,
        "live assistant output is delivered once"
    );
    assert_eq!(visible_diff, 1, "live diff output is delivered once");

    let ServiceResult::Snapshot(snapshot) = owner
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "three-completed".to_owned(),
            idempotency_key: "three-completed-key".to_owned(),
            command: ServiceCommand::Status { task_id },
        })
        .await?
    else {
        return Err("three-epoch completion snapshot missing".into());
    };
    assert_eq!(snapshot.status, TaskStatus::Completed);
    let database = layout.data.join("carl.sqlite3");
    let before_poll = Connection::open(&database)?.query_row(
        "SELECT
            (SELECT COUNT(*) FROM events),
            (SELECT COUNT(*) FROM service_command_receipts)",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let ServiceResult::Metrics(metrics) = owner
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "three-metrics".to_owned(),
            idempotency_key: "three-metrics-key".to_owned(),
            command: ServiceCommand::Metrics { task_id },
        })
        .await?
    else {
        return Err("three-epoch metrics missing".into());
    };
    assert_eq!(metrics.status, TaskStatus::Completed);
    assert_eq!(metrics.provider_requests, 3);
    assert_eq!(metrics.epochs_started, 3);
    assert_eq!(metrics.epochs_completed, 3);
    assert_eq!(metrics.operation_intents, 1);
    assert_eq!(metrics.operations_succeeded, 1);
    assert_eq!(metrics.operations_failed, 0);
    assert_eq!(metrics.operations_cancelled, 0);
    assert_eq!(metrics.operations_uncertain, 0);
    assert_eq!(metrics.unresolved_operations, 0);
    assert_eq!(metrics.required_clauses_total, 2);
    assert_eq!(metrics.required_clauses_satisfied, 2);
    drop(owner);
    let mut reconnected_owner = TaskServiceClient::connect(&layout.data).await?;
    let ServiceResult::Metrics(reconnected_metrics) = reconnected_owner
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: "three-metrics-reconnected".to_owned(),
            idempotency_key: "three-metrics-reconnected-key".to_owned(),
            command: ServiceCommand::Metrics { task_id },
        })
        .await?
    else {
        return Err("reconnected three-epoch metrics missing".into());
    };
    assert_eq!(reconnected_metrics, metrics);
    let after_poll = Connection::open(&database)?.query_row(
        "SELECT
            (SELECT COUNT(*) FROM events),
            (SELECT COUNT(*) FROM service_command_receipts)",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    assert_eq!(after_poll, before_poll, "metrics polling is read-only");
    assert_eq!(
        reconnected_owner
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "three-metrics-unknown".to_owned(),
                idempotency_key: "three-metrics-unknown-key".to_owned(),
                command: ServiceCommand::Metrics {
                    task_id: TaskId::new(),
                },
            })
            .await
            .expect_err("unknown metrics task must be rejected")
            .code(),
        ServiceClientErrorCode::Rejected
    );
    client_write
        .write_all(
            format!(
                "{}\n",
                json!({"jsonrpc":"2.0","id":13,"method":"_task/metrics","params":{"sessionId":session_id,"taskId":task_id}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let extension = read_frame(&mut reader, 1024 * 1024)
        .await?
        .ok_or("service ACP metrics extension missing")?;
    assert_eq!(extension.value()["id"], 13);
    assert_eq!(
        extension.value()["result"]["metrics"],
        serde_json::to_value(&metrics)?
    );

    client_write
        .write_all(
            format!(
                "{}\n",
                json!({"jsonrpc":"2.0","id":14,"method":"session/prompt","params":{"sessionId":session_id,"prompt":[{"type":"text","text":"/metrics"}]}})
            )
            .as_bytes(),
        )
        .await?;
    client_write.flush().await?;
    let slash_update = read_frame(&mut reader, 1024 * 1024)
        .await?
        .ok_or("service ACP metrics slash update missing")?;
    let slash_text = slash_update.value()["params"]["update"]["content"]["text"]
        .as_str()
        .ok_or("service ACP metrics slash text missing")?;
    let slash: serde_json::Value = serde_json::from_str(slash_text)?;
    assert_eq!(slash["metrics"], serde_json::to_value(&metrics)?);
    let slash_result = read_frame(&mut reader, 1024 * 1024)
        .await?
        .ok_or("service ACP metrics slash result missing")?;
    assert_eq!(slash_result.value()["id"], 14);
    assert_eq!(slash_result.value()["result"]["stopReason"], "end_turn");
    {
        let state = shared.lock().unwrap();
        assert_eq!(state.work_epochs, 3);
        assert_eq!(state.effect_count, 1);
        assert_eq!(state.completion_reports, 1);
        assert_eq!(state.interrupts, 0);
    }
    drop(client_write);
    drop(reader);
    tokio::time::timeout(Duration::from_secs(5), reconnect_task)
        .await
        .map_err(|_| "three-epoch reconnect ACP connection did not close")???;
    reconnected_owner
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
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

struct RestartApprovalPort {
    state: Arc<Mutex<RestartApprovalState>>,
    replacement: bool,
}

#[derive(Default)]
struct RestartApprovalState {
    workspace: PathBuf,
    events: VecDeque<AgentEvent>,
    provider_epochs: u64,
    initial_work_started: bool,
    replacement_effect_requested: bool,
    active_context_id: Option<AgentContextId>,
    active_epoch_id: Option<AgentEpochId>,
    operation_id: Option<String>,
    completion_emitted: bool,
}

impl RestartApprovalPort {
    fn new(state: Arc<Mutex<RestartApprovalState>>, replacement: bool) -> Self {
        Self { state, replacement }
    }
}

impl AgentPort for RestartApprovalPort {
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
        Box::pin(async { AgentContextId::parse("restart-approval-context") })
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
            state.provider_epochs += 1;
            let epoch_id =
                AgentEpochId::parse(format!("restart-approval-{}", state.provider_epochs))?;
            state.events.push_back(AgentEvent::EpochStarted {
                context_id: request.context_id.clone(),
                epoch_id: epoch_id.clone(),
            });
            if request.permission_mode == PermissionMode::Plan {
                state.events.push_back(AgentEvent::AssistantDelta {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    text: "<carl-completion-contract>{\"version\":1,\"goal\":\"Restart and request approval\",\"constraints\":[],\"clauses\":[{\"id\":\"requested-outcome\",\"description\":\"Requested outcome\",\"required\":true,\"status\":\"pending\",\"evidence\":[]},{\"id\":\"explicit-verification\",\"description\":\"Explicit verification\",\"required\":true,\"status\":\"pending\",\"evidence\":[]}]}</carl-completion-contract>".to_owned(),
                });
                state.events.push_back(AgentEvent::EpochCompleted {
                    context_id: request.context_id,
                    epoch_id: epoch_id.clone(),
                    status: "completed".to_owned(),
                });
            } else if replacement {
                state.active_context_id = Some(request.context_id.clone());
                state.active_epoch_id = Some(epoch_id.clone());
                state.events.push_back(AgentEvent::AssistantDelta {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    text: "replacement assistant".to_owned(),
                });
                state.events.push_back(AgentEvent::DiffUpdated {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    diff: "diff --git a/replacement b/replacement".to_owned(),
                });
                let workspace = state.workspace.clone();
                state.events.push_back(AgentEvent::ItemStarted {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    item: AgentItem::Command {
                        item_id: "restart-approval-item".to_owned(),
                        command: "restart-approval".to_owned(),
                        cwd: workspace,
                        status: "inProgress".to_owned(),
                        exit_code: None,
                        aggregated_output: None,
                        process_id: None,
                    },
                });
                state
                    .events
                    .push_back(AgentEvent::EffectRequested(AgentEffectRequest {
                        context_id: request.context_id,
                        epoch_id: epoch_id.clone(),
                        request_id: AgentRequestId::parse("restart-approval-request")?,
                        item_id: "restart-approval-item".to_owned(),
                        kind: AgentEffectKind::Command,
                        summary: "approve after restart".to_owned(),
                        request_digest: Sha256Digest::parse("7".repeat(64))
                            .expect("literal digest is valid"),
                    }));
                state.replacement_effect_requested = true;
            } else {
                state.initial_work_started = true;
                state.events.push_back(AgentEvent::AssistantDelta {
                    context_id: request.context_id,
                    epoch_id: epoch_id.clone(),
                    text: "old generation assistant".to_owned(),
                });
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
        Box::pin(async move {
            loop {
                if let Some(event) = state.lock().unwrap().events.pop_front() {
                    return Ok(event);
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
            if decision != EffectDecision::Allow {
                return Ok(());
            }
            let mut state = state.lock().unwrap();
            if state.completion_emitted {
                return Ok(());
            }
            let context_id = state.active_context_id.clone().ok_or_else(|| {
                AgentPortError::from_code(
                    carl::runtime::agent_port::AgentPortErrorCode::InvalidResponse,
                )
            })?;
            let epoch_id = state.active_epoch_id.clone().ok_or_else(|| {
                AgentPortError::from_code(
                    carl::runtime::agent_port::AgentPortErrorCode::InvalidResponse,
                )
            })?;
            let operation_id = state.operation_id.clone().ok_or_else(|| {
                AgentPortError::from_code(
                    carl::runtime::agent_port::AgentPortErrorCode::InvalidResponse,
                )
            })?;
            state.completion_emitted = true;
            let workspace = state.workspace.clone();
            state.events.push_back(AgentEvent::ItemCompleted {
                context_id: context_id.clone(),
                epoch_id: epoch_id.clone(),
                item: AgentItem::Command {
                    item_id: "restart-approval-item".to_owned(),
                    command: "restart-approval".to_owned(),
                    cwd: workspace,
                    status: "completed".to_owned(),
                    exit_code: Some(0),
                    aggregated_output: Some("approved after restart".to_owned()),
                    process_id: None,
                },
            });
            state.events.push_back(AgentEvent::AssistantDelta {
                context_id: context_id.clone(),
                epoch_id: epoch_id.clone(),
                text: epoch_report("complete", None, Some(&operation_id)),
            });
            state.events.push_back(AgentEvent::EpochCompleted {
                context_id,
                epoch_id,
                status: "completed".to_owned(),
            });
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
    emit_live: bool,
    user_steers: u64,
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
                    if state.emit_live {
                        state.events.push_back(AgentEvent::AssistantDelta {
                            context_id: request.context_id.clone(),
                            epoch_id: epoch_id.clone(),
                            text: "visible assistant update".to_owned(),
                        });
                        state.events.push_back(AgentEvent::DiffUpdated {
                            context_id: request.context_id.clone(),
                            epoch_id: epoch_id.clone(),
                            diff: "diff --git a/live b/live".to_owned(),
                        });
                    }
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
            } else {
                state.lock().unwrap().user_steers += 1;
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
                state.events.push_back(AgentEvent::DiffUpdated {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    diff: "diff --git a/restart b/restart".to_owned(),
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
