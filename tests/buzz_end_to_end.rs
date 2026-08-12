#[path = "support/buzz_acp.rs"]
mod support;

use std::fs;
use std::path::Path;

use libtest_mimic::{Arguments, Failed, Trial};
use serde_json::json;
use support::{Client, Layout, PRIVATE_KEY, TestResult, dispatch_fixture, fixture, prompt_frame};

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(status) = dispatch_fixture(&arguments) {
        std::process::exit(status);
    }
    libtest_mimic::run(
        &Arguments::from_args(),
        vec![Trial::test(
            "Buzz to Carl to Codex approvals bypass restart and cancellation are deterministic",
            || end_to_end().map_err(|error| Failed::from(error.to_string())),
        )],
    )
    .exit();
}

fn end_to_end() -> TestResult {
    let layout = Layout::new("end-to-end")?;
    let mut client = Client::spawn(&layout, false)?;
    let session = initialize_session(&mut client, &layout, 1, 2)?;

    client.send(&prompt_frame(10, &session, "approval scenario", 'a'))?;
    assert_eq!(
        client.read_id(10)?["result"]["stopReason"],
        "waiting_for_approval"
    );
    let first_code = latest_approval_code(&layout)?;
    client.send(&prompt_frame(
        11,
        &session,
        &format!("/approve {first_code}"),
        'c',
    ))?;
    assert_eq!(
        client.read_id(11)?["result"]["stopReason"],
        "waiting_for_approval"
    );
    let second_code = latest_approval_code(&layout)?;
    assert_ne!(first_code, second_code);
    client.send(&prompt_frame(
        12,
        &session,
        &format!("/deny {second_code}"),
        'd',
    ))?;
    assert_eq!(client.read_id(12)?["result"]["stopReason"], "end_turn");
    client.send(&prompt_frame(
        13,
        &session,
        &format!("/deny {second_code}"),
        'e',
    ))?;
    assert_eq!(client.read_id(13)?["error"]["code"], -32000);
    let first = client.finish()?;
    assert_eq!(
        fs::read_to_string(layout.workspace.join("target.txt"))?,
        "fixed\n"
    );
    assert_eq!(layout.action_count("approved-command")?, 0);

    let mut bypass = Client::spawn(&layout, true)?;
    let bypass_session = initialize_session(&mut bypass, &layout, 101, 102)?;
    bypass.send(&prompt_frame(20, &bypass_session, "bypass scenario", 'f'))?;
    let bypass_result = bypass.read_id(20)?;
    assert_eq!(
        bypass_result["result"]["stopReason"], "end_turn",
        "{bypass_result}"
    );
    bypass.send(&prompt_frame(21, &bypass_session, "wait for cancel", '1'))?;
    layout.wait_for_provider_method("turn/start", 3)?;
    bypass.send(&json!({
        "jsonrpc":"2.0","id":22,"method":"_session/steering","params":{
            "sessionId":bypass_session,
            "prompt":[{"type":"text","text":"finish with verification evidence"}]
        }
    }))?;
    assert_eq!(bypass.read_id(22)?["result"]["outcome"], "injected");
    bypass.send(&json!({
        "jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":bypass_session}
    }))?;
    assert_eq!(bypass.read_id(21)?["result"]["stopReason"], "cancelled");
    let second = bypass.finish()?;

    let publications = layout.publisher_records()?;
    assert_eq!(publications.len(), 6);
    assert!(
        publications
            .last()
            .and_then(|record| record["content"].as_str())
            .is_some_and(|content| content.to_lowercase().contains("verification"))
    );
    assert_eq!(
        fs::read_to_string(layout.workspace.join("target.txt"))?,
        "fixed\n"
    );
    assert_eq!(layout.action_count("approved-command")?, 1);

    let mut captured = Vec::new();
    captured.extend(first.stdout);
    captured.extend(first.stderr);
    captured.extend(second.stdout);
    captured.extend(second.stderr);
    collect_bytes(&layout.data, &mut captured)?;
    assert!(
        !captured
            .windows(PRIVATE_KEY.len())
            .any(|window| window == PRIVATE_KEY.as_bytes())
    );
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
    let created = client.read_id(session_id)?;
    Ok(created["result"]["sessionId"]
        .as_str()
        .ok_or_else(|| format!("session ID missing: {created}"))?
        .to_owned())
}

fn latest_approval_code(layout: &Layout) -> TestResult<String> {
    let records = layout.publisher_records()?;
    let content = records
        .last()
        .and_then(|record| record["content"].as_str())
        .ok_or("approval publication missing")?;
    content
        .split("/approve ")
        .nth(1)
        .and_then(|suffix| suffix.split_whitespace().next())
        .map(str::to_owned)
        .ok_or_else(|| "approval code missing".into())
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
