#[path = "support/buzz_acp.rs"]
mod support;

use std::fs;
use std::path::Path;

use libtest_mimic::{Arguments, Failed, Trial};
use rusqlite::Connection;
use serde_json::{Value, json};
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
            Trial::test(
                "service approval responses are exact durable and single use",
                || durable_service_approval().map_err(|error| Failed::from(error.to_string())),
            ),
            Trial::test(
                "configuration supersession derives authority from durable effective state",
                || {
                    durable_configuration_supersession()
                        .map_err(|error| Failed::from(error.to_string()))
                },
            ),
            Trial::test(
                "rejected configuration delivery preserves journal-owned session state",
                || {
                    rejected_configuration_delivery_rolls_back_session()
                        .map_err(|error| Failed::from(error.to_string()))
                },
            ),
            Trial::test(
                "Buzz steering requires fresh exact owner metadata before mutation",
                || strict_steering_admission().map_err(|error| Failed::from(error.to_string())),
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
    client.send(&prompt_frame(10, &session, "bypass scenario", 'a'))?;
    let (completed, updates) = client.read_id_with_updates(10)?;
    assert_eq!(completed["result"]["stopReason"], "end_turn", "{completed}");
    assert!(
        updates
            .iter()
            .all(|update| !update.to_string().contains("Approve with"))
    );
    client.send(&prompt_frame(20, &session, "wait for cancel", 'b'))?;
    layout.wait_for_provider_method("turn/start", 2)?;
    let task_id = layout.latest_task_id()?;
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
    let steer = |id, text: &str, event: char| {
        json!({
            "jsonrpc":"2.0","id":id,"method":"_session/steering","params":{
                "sessionId":session,"prompt":[
                    {"type":"text","text":text},
                    {"type":"text","text":format!(
                        "Event ID: {}\nChannel: Carl Test (#{CHANNEL_ID})\nKind: 1\nFrom: Owner (hex: {ACTOR_HEX})\nTime: 2026-08-10T12:00:00Z\nContent: command",
                        event.to_string().repeat(64)
                    )}
                ]
            }
        })
    };
    client.send(&steer(24, "finish with exact verification", 'c'))?;
    let steered = client.read_id(24)?;
    assert_eq!(steered["result"]["outcome"], "injected");
    client.send(&steer(25, "finish with exact verification", 'c'))?;
    assert_eq!(client.read_id(25)?["error"]["code"], -32602);
    client.send(&steer(26, "different payload", 'd'))?;
    assert_eq!(client.read_id(26)?["result"]["outcome"], "injected");
    client.send(&json!({
        "jsonrpc":"2.0","id":28,"method":"_task/steer","params":{
            "sessionId":session,"taskId":task_id,"idempotencyKey":"generic-steer","text":"must fail closed"
        }
    }))?;
    assert_eq!(client.read_id(28)?["error"]["code"], -32602);
    client.send(&json!({
        "jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":session}
    }))?;
    assert_eq!(client.read_id(20)?["result"]["stopReason"], "cancelled");
    assert_eq!(layout.provider_method_count("turn/interrupt")?, 1);
    let first = client.finish()?;
    assert_eq!(
        fs::read_to_string(layout.workspace.join("target.txt"))?,
        "fixed\n"
    );
    assert_eq!(layout.action_count("approved-command")?, 1);

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

fn strict_steering_admission() -> TestResult {
    let layout = Layout::new("strict-steering-admission")?;
    layout.trust_owner()?;
    let mut client = Client::spawn(&layout, false)?;
    let session = initialize_session(&mut client, &layout, 1, 2)?;
    client.send(&prompt_frame(3, &session, "wait for cancel", 'a'))?;
    layout.wait_for_provider_method("turn/start", 1)?;
    let task_id = layout.latest_task_id()?;

    let metadata = |event: char, actor: &str, channel: &str, kind: u32| {
        format!(
            "Event ID: {}\nChannel: Carl Test (#{channel})\nKind: {kind}\nFrom: Owner (hex: {actor})\nTime: 2026-08-10T12:00:00Z\nContent: command",
            event.to_string().repeat(64)
        )
    };
    let steering = |id: i64, prompt: Vec<String>| {
        json!({
            "jsonrpc":"2.0","id":id,"method":"_session/steering","params":{
                "sessionId":session,
                "prompt":prompt.into_iter().map(|text| json!({"type":"text","text":text})).collect::<Vec<_>>()
            }
        })
    };
    let wrong_actor = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let wrong_channel = "22222222-2222-4222-8222-222222222222";
    let rejected = [
        steering(10, vec!["missing metadata".to_owned()]),
        steering(
            11,
            vec!["malformed metadata".to_owned(), "Event ID: nope".to_owned()],
        ),
        steering(
            12,
            vec![
                "wrong actor".to_owned(),
                metadata('b', wrong_actor, CHANNEL_ID, 1),
            ],
        ),
        steering(
            13,
            vec![
                "wrong channel".to_owned(),
                metadata('c', ACTOR_HEX, wrong_channel, 1),
            ],
        ),
        steering(
            14,
            vec![
                "group-shaped".to_owned(),
                metadata('d', ACTOR_HEX, CHANNEL_ID, 9),
            ],
        ),
        steering(
            15,
            vec![
                "ambiguous metadata".to_owned(),
                metadata('e', ACTOR_HEX, CHANNEL_ID, 1),
                metadata('f', ACTOR_HEX, CHANNEL_ID, 1),
            ],
        ),
    ];
    for request in rejected {
        let id = request["id"].as_i64().ok_or("steering id missing")?;
        let markers_before = layout.task_control_marker_count(&task_id)?;
        let provider_steers_before = layout.provider_method_count("turn/steer")?;
        client.send(&request)?;
        assert_eq!(client.read_id(id)?["error"]["code"], -32602);
        assert_eq!(layout.task_control_marker_count(&task_id)?, markers_before);
        assert_eq!(
            layout.provider_method_count("turn/steer")?,
            provider_steers_before
        );
    }

    let valid = steering(
        16,
        vec![
            "fresh owner steering".to_owned(),
            metadata('1', ACTOR_HEX, CHANNEL_ID, 1),
        ],
    );
    client.send(&valid)?;
    assert_eq!(client.read_id(16)?["result"]["outcome"], "injected");
    let markers_after_valid = layout.task_control_marker_count(&task_id)?;
    let provider_steers_after_valid = layout.provider_method_count("turn/steer")?;
    client.send(
        &valid
            .as_object()
            .map(|object| {
                let mut replay = object.clone();
                replay.insert("id".to_owned(), json!(17));
                Value::Object(replay)
            })
            .ok_or("valid steering frame must be an object")?,
    )?;
    assert_eq!(client.read_id(17)?["error"]["code"], -32602);
    assert_eq!(
        layout.task_control_marker_count(&task_id)?,
        markers_after_valid
    );
    assert_eq!(
        layout.provider_method_count("turn/steer")?,
        provider_steers_after_valid
    );

    client.send(&json!({
        "jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":session}
    }))?;
    assert_eq!(client.read_id(3)?["result"]["stopReason"], "cancelled");
    let _ = client.finish()?;
    Ok(())
}

fn durable_configuration_boundaries() -> TestResult {
    let loosening = Layout::new("durable-config-loosening")?;
    loosening.trust_owner()?;
    let mut client = Client::spawn(&loosening, false)?;
    let session = initialize_session(&mut client, &loosening, 1, 2)?;
    client.send(&prompt_frame(3, &session, "/permissions readOnly", 'a'))?;
    let configured = client.read_id(3)?;
    assert_eq!(
        configured["result"]["stopReason"], "end_turn",
        "{configured}"
    );
    client.send(&prompt_frame(4, &session, "wait for cancel", 'b'))?;
    loosening.wait_for_provider_method("turn/start", 1)?;
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
            "prompt":[
                {"type":"text","text":"boundary configuration"},
                {"type":"text","text":format!(
                    "Event ID: {}\nChannel: Carl Test (#{CHANNEL_ID})\nKind: 1\nFrom: Owner (hex: {ACTOR_HEX})\nTime: 2026-08-10T12:00:00Z\nContent: command",
                    "c".repeat(64)
                )}
            ]
        }
    }))?;
    assert_eq!(client.read_id(8)?["result"]["outcome"], "injected");
    loosening.wait_for_provider_method("turn/start", 2)?;
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
    tightening.wait_for_provider_method("turn/start", 1)?;
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
    tightening.wait_for_provider_method("turn/start", 2)?;
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
    assert_eq!(active_operation.provider_method_count("turn/start")?, 1);
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
    assert_eq!(active_operation.provider_method_count("turn/start")?, 1);
    assert_eq!(active_operation.started_operation_count()?, 0);
    assert_eq!(active_operation.operation_status_count("uncertain")?, 1);
    assert_eq!(active_operation.permission_tightening_interrupt_count()?, 1);
    let _ = client.finish()?;
    Ok(())
}

fn durable_service_approval() -> TestResult {
    let layout = Layout::new("durable-approval")?;
    layout.trust_owner()?;
    let mut client = Client::spawn(&layout, false)?;
    let session = initialize_session(&mut client, &layout, 51, 52)?;
    client.send(&prompt_frame(53, &session, "/permissions approval", 'a'))?;
    assert_eq!(client.read_id(53)?["result"]["stopReason"], "end_turn");

    client.send(&prompt_frame(54, &session, "approval scenario", 'b'))?;
    let (first, updates) = client.read_id_with_updates(54)?;
    assert_eq!(first["result"]["stopReason"], "waiting_for_approval");
    let first_code = approval_code(&updates)?;

    client.send(&prompt_frame(
        55,
        &session,
        &format!("/approve {first_code}-wrong"),
        'c',
    ))?;
    assert_eq!(client.read_id(55)?["error"]["code"], -32602);

    client.send(&prompt_frame(
        56,
        &session,
        &format!("/approve {first_code}"),
        'd',
    ))?;
    let (second, updates) = client.read_id_with_updates(56)?;
    assert_eq!(second["result"]["stopReason"], "waiting_for_approval");
    let second_code = approval_code(&updates)?;
    assert_ne!(first_code, second_code);

    client.send(&prompt_frame(
        57,
        &session,
        &format!("/approve {second_code}"),
        'e',
    ))?;
    let completed = client.read_id(57)?;
    assert_eq!(
        completed["result"]["stopReason"],
        "end_turn",
        "completed={completed}; events={:?}; requests={:?}",
        layout.task_lifecycle_events()?,
        layout.provider_requests()?
    );
    assert_eq!(layout.action_count("approved-command")?, 1);
    assert_eq!(
        fs::read_to_string(layout.workspace.join("target.txt"))?,
        "fixed\n"
    );

    let receipts = Connection::open(layout.data.join("carl.sqlite3"))?;
    for (kind, minimum) in [
        ("configure_trusted_session", 1_i64),
        ("start_trusted_task", 1_i64),
        ("resolve_approval", 2_i64),
    ] {
        let completed = receipts.query_row(
            "SELECT COUNT(*) FROM service_command_receipts
             WHERE command_kind = ?1 AND state = 'completed'
               AND json_valid(result_json)",
            [kind],
            |row| row.get::<_, i64>(0),
        )?;
        assert!(
            completed >= minimum,
            "{kind} did not leave a canonical owner receipt"
        );
    }

    client.send(&prompt_frame(
        58,
        &session,
        &format!("/approve {first_code}"),
        'f',
    ))?;
    assert_eq!(client.read_id(58)?["error"]["code"], -32602);
    let _ = client.finish()?;
    Ok(())
}

fn approval_code(updates: &[serde_json::Value]) -> TestResult<String> {
    updates
        .iter()
        .filter_map(|update| update.pointer("/params/update/content/text")?.as_str())
        .find_map(|text| {
            text.split_once("Approve with /approve ")
                .and_then(|(_, tail)| tail.split_whitespace().next())
                .map(str::to_owned)
        })
        .ok_or_else(|| format!("approval code missing from updates: {updates:?}").into())
}

fn durable_configuration_supersession() -> TestResult {
    let layout = Layout::new("durable-config-supersession")?;
    layout.trust_owner()?;
    let mut client = Client::spawn(&layout, false)?;
    let session = initialize_session(&mut client, &layout, 31, 32)?;
    client.send(&prompt_frame(33, &session, "/permissions readOnly", 'f'))?;
    let configured = client.read_id(33)?;
    assert_eq!(
        configured["result"]["stopReason"], "end_turn",
        "{configured}"
    );
    client.send(&prompt_frame(34, &session, "wait for cancel", 'a'))?;
    layout.wait_for_provider_method("turn/start", 1)?;
    let task_id = layout.latest_task_id()?;

    for (id, value) in [(35, "fullAccess"), (36, "default")] {
        client.send(&json!({
            "jsonrpc":"2.0","id":id,"method":"session/set_config_option","params":{
                "sessionId":session,"configId":"mode","value":value
            }
        }))?;
        let response = client.read_id(id)?;
        assert!(
            response["result"]["configOptions"].is_array(),
            "configuration {value} was rejected: {response}"
        );
    }
    assert_eq!(
        task_configuration_modes(&layout, &task_id)?,
        (
            "plan".to_owned(),
            "plan".to_owned(),
            Some("default".to_owned()),
        ),
        "the superseding pending configuration must retain the Plan authority ceiling"
    );
    assert_eq!(layout.provider_method_count("turn/interrupt")?, 0);

    client.send(&json!({
        "jsonrpc":"2.0","id":37,"method":"_session/steering","params":{
            "sessionId":session,
            "prompt":[
                {"type":"text","text":"boundary configuration"},
                {"type":"text","text":format!(
                    "Event ID: {}\nChannel: Carl Test (#{CHANNEL_ID})\nKind: 1\nFrom: Owner (hex: {ACTOR_HEX})\nTime: 2026-08-10T12:00:00Z\nContent: command",
                    "b".repeat(64)
                )}
            ]
        }
    }))?;
    assert_eq!(client.read_id(37)?["result"]["outcome"], "injected");
    layout.wait_for_provider_method("turn/start", 2)?;
    let dispatched = layout
        .provider_requests()?
        .into_iter()
        .rev()
        .find(|request| request["method"] == "turn/start")
        .ok_or("superseding epoch was not dispatched")?;
    assert_eq!(dispatched["params"]["approvalPolicy"], "on-request");
    assert_eq!(
        dispatched["params"]["sandboxPolicy"]["type"],
        "workspaceWrite"
    );
    assert_eq!(
        task_configuration_modes(&layout, &task_id)?,
        ("default".to_owned(), "default".to_owned(), None),
        "the superseding Default configuration, never stale FullAccess, must apply"
    );
    assert_eq!(layout.provider_method_count("turn/interrupt")?, 0);
    client.send(&json!({
        "jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":session}
    }))?;
    assert_eq!(client.read_id(34)?["result"]["stopReason"], "cancelled");
    let _ = client.finish()?;
    Ok(())
}

fn task_configuration_modes(
    layout: &Layout,
    task_id: &str,
) -> TestResult<(String, String, Option<String>)> {
    Ok(
        Connection::open(layout.data.join("carl.sqlite3"))?.query_row(
            "SELECT active_permission_mode, effective_permission_mode, pending_permission_mode
         FROM task_configuration_state WHERE task_id = ?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?,
    )
}

fn rejected_configuration_delivery_rolls_back_session() -> TestResult {
    let layout = Layout::new("durable-config-rejected-delivery")?;
    layout.trust_owner()?;
    let mut client = Client::spawn(&layout, false)?;
    let session = initialize_session(&mut client, &layout, 41, 42)?;
    client.send(&prompt_frame(43, &session, "/permissions readOnly", 'b'))?;
    let configured = client.read_id(43)?;
    assert_eq!(
        configured["result"]["stopReason"], "end_turn",
        "{configured}"
    );
    client.send(&prompt_frame(44, &session, "wait for cancel", 'c'))?;
    layout.wait_for_provider_method("turn/start", 1)?;
    let task_id = layout.latest_task_id()?;
    let connection = Connection::open(layout.data.join("carl.sqlite3"))?;
    connection.execute_batch(
        "CREATE TRIGGER reject_configuration_queue
         BEFORE INSERT ON events
         WHEN json_extract(NEW.event_json, '$.event.task_event') = 'configuration_queued'
         BEGIN SELECT RAISE(ABORT, 'injected configuration delivery rejection'); END;",
    )?;
    drop(connection);

    client.send(&json!({
        "jsonrpc":"2.0","id":45,"method":"session/set_config_option","params":{
            "sessionId":session,"configId":"mode","value":"fullAccess"
        }
    }))?;
    assert!(client.read_id(45)?["error"].is_object());
    let prompt = client.read_id(44)?;
    assert_eq!(
        prompt["result"]["stopReason"],
        "failed",
        "prompt={prompt}; events={:?}",
        layout.task_lifecycle_events()?
    );
    let connection = Connection::open(layout.data.join("carl.sqlite3"))?;
    assert_eq!(
        connection.query_row(
            "SELECT permission_mode FROM frontend_sessions WHERE external_session_id = ?1",
            [&session],
            |row| row.get::<_, String>(0),
        )?,
        "plan",
        "a rejected delivery must not escape into session configuration"
    );
    assert_eq!(
        task_configuration_modes(&layout, &task_id)?,
        ("plan".to_owned(), "plan".to_owned(), None),
        "the rejected configuration must be absent from the task journal projection"
    );
    drop(connection);
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
    let response = client.read_id(session_id)?;
    Ok(response["result"]["sessionId"]
        .as_str()
        .ok_or_else(|| format!("session ID missing: {response}"))?
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
