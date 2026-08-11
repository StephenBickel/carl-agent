#[path = "support/buzz_acp.rs"]
mod support;

use std::fs;
use std::path::Path;

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::runtime::task::{ClauseStatus, CompletionClause, CompletionContract, TaskBudget};
use carl::storage::{NewTask, Store};
use chrono::Utc;
use libtest_mimic::{Arguments, Failed, Trial};
use rusqlite::Connection;
use serde_json::json;
use support::{
    ACTOR_HEX, CHANNEL_ID, Client, Layout, PRIVATE_KEY, TestResult, dispatch_fixture, fixture,
    prompt_frame, prompt_frame_for_identity,
};

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(status) = dispatch_fixture(&arguments) {
        std::process::exit(status);
    }
    libtest_mimic::run(
        &Arguments::from_args(),
        vec![
            Trial::test(
                "Buzz admission rejects untrusted ambiguous and replayed work before execution",
                || admission_precedes_execution().map_err(|error| Failed::from(error.to_string())),
            ),
            Trial::test(
                "trusted Buzz owner receives full access without an approval ceremony",
                || end_to_end().map_err(|error| Failed::from(error.to_string())),
            ),
            Trial::test(
                "durable task configuration changes wait for a safe epoch boundary",
                || {
                    durable_configuration_boundaries()
                        .map_err(|error| Failed::from(error.to_string()))
                },
            ),
        ],
    )
    .exit();
}

fn end_to_end() -> TestResult {
    let layout = Layout::new("end-to-end")?;
    layout.trust_owner()?;
    let mut client = Client::spawn(&layout, false)?;
    let session = initialize_session(&mut client, &layout, 1, 2)?;
    let mut second_session = fixture("session_new", &layout.workspace, None)?;
    second_session["id"] = json!(3);
    client.send(&second_session)?;
    let second_response = client.read_id(3)?;
    let second_session = second_response["result"]["sessionId"]
        .as_str()
        .ok_or_else(|| format!("second session ID missing: {second_response}"))?
        .to_owned();

    client.send(&prompt_frame(10, &session, "bypass scenario", 'a'))?;
    let (completed, updates) = client.read_id_with_updates(10)?;
    assert_eq!(completed["result"]["stopReason"], "end_turn", "{completed}");
    assert!(
        updates
            .iter()
            .all(|update| !update.to_string().contains("Approve with"))
    );
    client.send(&prompt_frame(20, &session, "wait for cancel", 'b'))?;
    layout.wait_for_provider_method("turn/start", 3)?;
    let task_id = layout.latest_task_id()?;
    let other_task_id = create_queued_task(&layout, &session)?;
    for (id, method, key) in [
        (18, "_task/cancel", "wrong-task-cancel"),
        (19, "_task/steer", "wrong-task-steer"),
    ] {
        let mut params = json!({
            "sessionId":session,"taskId":other_task_id,"idempotencyKey":key
        });
        if method == "_task/steer" {
            params["text"] = json!("must not steer the active task");
        }
        client.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        assert_eq!(client.read_id(id)?["error"]["code"], -32602);
    }
    assert_eq!(layout.provider_method_count("turn/interrupt")?, 0);
    assert_eq!(layout.task_control_marker_count(&other_task_id)?, 0);
    for (id, method) in [(21, "_task/status"), (22, "_task/context")] {
        client.send(&json!({
            "jsonrpc":"2.0","id":id,"method":method,"params":{
                "sessionId":session,"taskId":task_id
            }
        }))?;
        assert!(client.read_id(id)?["result"].is_object());
    }
    client.send(&json!({
        "jsonrpc":"2.0","id":23,"method":"_task/list","params":{"sessionId":session}
    }))?;
    assert!(
        !client.read_id(23)?["result"]["tasks"]
            .as_array()
            .ok_or("task list missing")?
            .is_empty()
    );
    let steer = |id, text| {
        json!({
            "jsonrpc":"2.0","id":id,"method":"_task/steer","params":{
                "sessionId":session,"taskId":task_id,"idempotencyKey":"steer-key","text":text
            }
        })
    };
    client.send(&steer(24, "finish with exact verification"))?;
    let steered = client.read_id(24)?;
    assert_eq!(steered["result"]["outcome"], "accepted");
    client.send(&steer(25, "finish with exact verification"))?;
    assert_eq!(client.read_id(25)?["result"], steered["result"]);
    client.send(&steer(26, "different payload"))?;
    assert_eq!(client.read_id(26)?["error"]["code"], -32602);
    client.send(&json!({
        "jsonrpc":"2.0","id":27,"method":"_task/status","params":{
            "sessionId":second_session,"taskId":task_id
        }
    }))?;
    assert_eq!(client.read_id(27)?["error"]["code"], -32602);
    client.send(&json!({
        "jsonrpc":"2.0","id":29,"method":"_task/cancel","params":{
            "sessionId":session,"taskId":task_id,"idempotencyKey":"steer-key"
        }
    }))?;
    assert_eq!(client.read_id(29)?["error"]["code"], -32602);
    let cancel = json!({
        "jsonrpc":"2.0","id":30,"method":"_task/cancel","params":{
            "sessionId":session,"taskId":task_id,"idempotencyKey":"cancel-key"
        }
    });
    Connection::open(layout.data.join("carl.sqlite3"))?.execute_batch(
        "CREATE TRIGGER fail_cancel_receipt_completion
         BEFORE UPDATE OF state ON task_control_receipts
         WHEN NEW.state = 'completed' AND NEW.method = 'cancel'
         BEGIN SELECT RAISE(ABORT, 'injected crash before cancel receipt completion'); END;",
    )?;
    client.send(&cancel)?;
    assert_eq!(client.read_id(30)?["error"]["code"], -32602);
    assert_eq!(layout.provider_method_count("turn/interrupt")?, 1);
    Connection::open(layout.data.join("carl.sqlite3"))?
        .execute_batch("DROP TRIGGER fail_cancel_receipt_completion;")?;
    let mut cancel_replay = cancel;
    cancel_replay["id"] = json!(31);
    client.send(&cancel_replay)?;
    assert_eq!(client.read_id(31)?["result"]["outcome"], "accepted");
    assert_eq!(layout.provider_method_count("turn/interrupt")?, 1);
    let rejected_resume = json!({
        "jsonrpc":"2.0","id":32,"method":"_task/resume","params":{
            "sessionId":session,"taskId":task_id,"idempotencyKey":"resume-key"
        }
    });
    client.send(&rejected_resume)?;
    assert_eq!(client.read_id(32)?["error"]["code"], -32602);
    let mut rejected_resume_replay = rejected_resume;
    rejected_resume_replay["id"] = json!(33);
    client.send(&rejected_resume_replay)?;
    assert_eq!(client.read_id(33)?["error"]["code"], -32602);
    let first = client.finish()?;
    assert_eq!(
        fs::read_to_string(layout.workspace.join("target.txt"))?,
        "fixed\n"
    );
    assert_eq!(layout.action_count("approved-command")?, 1);

    let publications = layout.publisher_records()?;
    assert!(!publications.is_empty());
    assert_eq!(
        fs::read_to_string(layout.workspace.join("target.txt"))?,
        "fixed\n"
    );
    let provider_requests = fs::read_to_string(layout.workspace.join(".provider-requests.jsonl"))?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<serde_json::Value>, _>>()?;
    let owner_start = provider_requests
        .iter()
        .rfind(|request| request["method"] == "thread/start")
        .ok_or("owner thread/start request missing")?;
    assert_eq!(owner_start["params"]["approvalPolicy"], "on-request");
    assert_eq!(owner_start["params"]["sandbox"], "read-only");
    assert!(provider_requests.iter().any(|request| {
        request["id"] == "approval-bypass" && request["result"]["decision"] == "accept"
    }));

    let mut captured = Vec::new();
    captured.extend(first.stdout);
    captured.extend(first.stderr);
    collect_bytes(&layout.data, &mut captured)?;
    assert!(
        !captured
            .windows(PRIVATE_KEY.len())
            .any(|window| window == PRIVATE_KEY.as_bytes())
    );
    Ok(())
}

fn create_queued_task(layout: &Layout, external_session_id: &str) -> TestResult<String> {
    let mut store = Store::open(layout.data.join("carl.sqlite3"))?;
    let session_id = store
        .get_frontend_session(external_session_id)?
        .ok_or("frontend session missing")?
        .session_id;
    let task = store.create_task(NewTask {
        session_id,
        workspace: fs::canonicalize(&layout.workspace)?,
        contract: CompletionContract {
            version: 1,
            goal: "Remain a distinct queued task".to_owned(),
            constraints: Vec::new(),
            clauses: vec![CompletionClause {
                id: "distinct".to_owned(),
                description: "Do not mutate the active task".to_owned(),
                required: false,
                status: ClauseStatus::Pending,
                evidence: Vec::new(),
            }],
        },
        model: ModelId::parse("gpt-5.6-codex")?,
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::FullAccess,
        budget: TaskBudget::default(),
        created_at: Utc::now(),
    })?;
    Ok(task.snapshot.task_id.to_string())
}

fn admission_precedes_execution() -> TestResult {
    let unknown = Layout::new("unknown-owner")?;
    assert_rejected_without_work(&unknown, false, ACTOR_HEX, CHANNEL_ID, 1, 'a')?;

    let mismatched_actor = Layout::new("mismatched-actor")?;
    mismatched_actor.trust_owner()?;
    assert_rejected_without_work(
        &mismatched_actor,
        false,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        CHANNEL_ID,
        1,
        'b',
    )?;

    let mismatched_channel = Layout::new("mismatched-channel")?;
    mismatched_channel.trust_owner()?;
    mismatched_channel.seed_admitted_event(&"c".repeat(64), CHANNEL_ID)?;
    assert_rejected_without_work(
        &mismatched_channel,
        false,
        ACTOR_HEX,
        "22222222-2222-4222-8222-222222222222",
        1,
        'd',
    )?;

    let group = Layout::new("group-shaped")?;
    group.trust_owner()?;
    assert_rejected_without_work(&group, false, ACTOR_HEX, CHANNEL_ID, 9, 'e')?;

    let replay = Layout::new("replay")?;
    replay.trust_owner()?;
    replay.seed_admitted_event(&"f".repeat(64), CHANNEL_ID)?;
    assert_rejected_without_work(&replay, true, ACTOR_HEX, CHANNEL_ID, 1, 'f')?;
    Ok(())
}

fn durable_configuration_boundaries() -> TestResult {
    let loosening = Layout::new("durable-config-loosening")?;
    loosening.trust_owner()?;
    let mut client = Client::spawn(&loosening, false)?;
    let session = initialize_session(&mut client, &loosening, 1, 2)?;
    client.send(&prompt_frame(3, &session, "/permissions readOnly", 'a'))?;
    assert_eq!(client.read_id(3)?["result"]["stopReason"], "end_turn");
    client.send(&prompt_frame(4, &session, "wait for cancel", 'b'))?;
    loosening.wait_for_provider_method("turn/start", 2)?;
    for (id, config_id, value) in [
        (5, "model", "gpt-5.6-codex"),
        (6, "thought_level", "high"),
        (7, "mode", "fullAccess"),
    ] {
        client.send(&json!({
            "jsonrpc":"2.0","id":id,"method":"session/set_config_option","params":{
                "sessionId":session,"configId":config_id,"value":value
            }
        }))?;
        assert!(client.read_id(id)?["result"]["configOptions"].is_array());
    }
    assert_eq!(loosening.provider_method_count("turn/interrupt")?, 0);
    client.send(&json!({
            "jsonrpc":"2.0","id":8,"method":"_session/steering","params":{
            "sessionId":session,
            "prompt":[{"type":"text","text":"boundary configuration"}]
        }
    }))?;
    assert_eq!(client.read_id(8)?["result"]["outcome"], "injected");
    loosening.wait_for_provider_method("turn/start", 3)?;
    let next_epoch = loosening
        .provider_requests()?
        .into_iter()
        .rev()
        .find(|request| request["method"] == "turn/start")
        .ok_or("next epoch was not started")?;
    assert_eq!(next_epoch["params"]["model"], "gpt-5.6-codex");
    assert_eq!(next_epoch["params"]["effort"], "high");
    assert_eq!(next_epoch["params"]["approvalPolicy"], "on-request");
    assert_eq!(loosening.provider_method_count("turn/interrupt")?, 0);
    client.send(&json!({
        "jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":session}
    }))?;
    assert_eq!(client.read_id(4)?["result"]["stopReason"], "cancelled");
    let _ = client.finish()?;

    let tightening = Layout::new("durable-config-tightening")?;
    tightening.trust_owner()?;
    let mut client = Client::spawn(&tightening, false)?;
    let session = initialize_session(&mut client, &tightening, 11, 12)?;
    client.send(&prompt_frame(13, &session, "wait for cancel", 'c'))?;
    tightening.wait_for_provider_method("turn/start", 2)?;
    let checkpoints_before = tightening.task_lifecycle_event_count("checkpoint_committed")?;
    let progress_before = tightening.task_lifecycle_event_count("progress_assessed")?;
    client.send(&json!({
        "jsonrpc":"2.0","id":14,"method":"session/set_config_option","params":{
            "sessionId":session,"configId":"mode","value":"plan"
        }
    }))?;
    assert!(client.read_id(14)?["result"]["configOptions"].is_array());
    for _ in 0..200 {
        if tightening.provider_method_count("turn/interrupt")? == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(tightening.provider_method_count("turn/interrupt")?, 1);
    assert_eq!(tightening.started_operation_count()?, 0);
    tightening.wait_for_provider_method("turn/start", 3)?;
    let next_epoch = tightening
        .provider_requests()?
        .into_iter()
        .rev()
        .find(|request| request["method"] == "turn/start")
        .ok_or("tightened epoch was not started")?;
    assert_eq!(next_epoch["params"]["approvalPolicy"], "never");
    assert_eq!(next_epoch["params"]["sandboxPolicy"]["type"], "readOnly");
    assert_eq!(tightening.provider_method_count("turn/interrupt")?, 1);
    assert_eq!(tightening.permission_tightening_interrupt_count()?, 1);
    assert_eq!(
        tightening.task_lifecycle_event_count("checkpoint_committed")?,
        checkpoints_before
    );
    assert_eq!(
        tightening.task_lifecycle_event_count("progress_assessed")?,
        progress_before
    );
    client.send(&json!({
        "jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":session}
    }))?;
    assert_eq!(client.read_id(13)?["result"]["stopReason"], "cancelled");
    let _ = client.finish()?;

    let active_operation = Layout::new("durable-config-active-operation")?;
    active_operation.trust_owner()?;
    let mut client = Client::spawn(&active_operation, false)?;
    let session = initialize_session(&mut client, &active_operation, 21, 22)?;
    client.send(&prompt_frame(23, &session, "/permissions approval", 'd'))?;
    assert_eq!(client.read_id(23)?["result"]["stopReason"], "end_turn");
    client.send(&prompt_frame(24, &session, "approval scenario", 'e'))?;
    let approval_response = client.read_id(24)?;
    assert_eq!(
        approval_response["result"]["stopReason"],
        "waiting_for_approval",
        "response={approval_response}; events={:?}; requests={:?}",
        active_operation.task_lifecycle_events()?,
        active_operation.provider_requests()?,
    );
    assert_eq!(active_operation.started_operation_count()?, 1);
    assert_eq!(active_operation.provider_method_count("turn/start")?, 2);
    client.send(&json!({
        "jsonrpc":"2.0","id":25,"method":"session/set_config_option","params":{
            "sessionId":session,"configId":"mode","value":"plan"
        }
    }))?;
    assert!(client.read_id(25)?["result"]["configOptions"].is_array());
    let task_id = active_operation.latest_task_id()?;
    client.send(&json!({
        "jsonrpc":"2.0","id":26,"method":"_task/status","params":{
            "sessionId":session,"taskId":task_id
        }
    }))?;
    assert_eq!(client.read_id(26)?["result"]["task"]["status"], "blocked");
    assert_eq!(active_operation.provider_method_count("turn/interrupt")?, 1);
    assert_eq!(active_operation.provider_method_count("turn/start")?, 2);
    assert_eq!(active_operation.started_operation_count()?, 0);
    assert_eq!(active_operation.operation_status_count("uncertain")?, 1);
    assert_eq!(active_operation.permission_tightening_interrupt_count()?, 1);
    let _ = client.finish()?;
    Ok(())
}

fn assert_rejected_without_work(
    layout: &Layout,
    seeded_event: bool,
    actor: &str,
    channel: &str,
    kind: u32,
    event: char,
) -> TestResult {
    let mut client = Client::spawn(layout, false)?;
    let session = initialize_session(&mut client, layout, 1, 2)?;
    assert_eq!(layout.provider_work_count()?, 0);
    let event_id = if seeded_event {
        "f".repeat(64)
    } else {
        event.to_string().repeat(64)
    };
    client.send(&prompt_frame_for_identity(
        3,
        &session,
        "must not execute",
        &event_id,
        channel,
        actor,
        kind,
    ))?;
    assert_eq!(client.read_id(3)?["error"]["code"], -32602);
    assert_eq!(layout.provider_work_count()?, 0);
    assert_eq!(layout.task_count()?, 0);
    client.finish()?;
    Ok(())
}

fn initialize_session(
    client: &mut Client,
    layout: &Layout,
    initialize_id: i64,
    session_id: i64,
) -> TestResult<String> {
    let mut initialize = fixture("initialize", &layout.workspace, None)?;
    initialize["id"] = json!(initialize_id);
    client.send(&initialize)?;
    assert_eq!(
        client.read_id(initialize_id)?["result"]["protocolVersion"],
        2
    );
    let mut session = fixture("session_new", &layout.workspace, None)?;
    session["id"] = json!(session_id);
    client.send(&session)?;
    Ok(client.read_id(session_id)?["result"]["sessionId"]
        .as_str()
        .ok_or("session ID missing")?
        .to_owned())
}

fn collect_bytes(path: &Path, output: &mut Vec<u8>) -> TestResult {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_bytes(&entry.path(), output)?;
        } else if metadata.is_file() {
            output.extend(fs::read(entry.path())?);
        }
    }
    Ok(())
}
