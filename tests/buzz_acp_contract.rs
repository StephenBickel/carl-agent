#[path = "support/buzz_acp.rs"]
mod support;

use libtest_mimic::{Arguments, Failed, Trial};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::{Client, Layout, TestResult, dispatch_fixture, fixture, prompt_frame_for_channel};

const SOURCE: &str = "block/buzz@44456e200e3ca6a5d2882b58b447b80474041347";

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(status) = dispatch_fixture(&arguments) {
        std::process::exit(status);
    }
    libtest_mimic::run(
        &Arguments::from_args(),
        vec![
            trial(
                "pinned Buzz fixture bytes retain provenance",
                fixture_hashes,
            ),
            trial(
                "real Carl process conforms at the Buzz ACP boundary",
                process_boundary_conforms,
            ),
        ],
    )
    .exit();
}

fn trial(name: &'static str, test: fn() -> TestResult) -> Trial {
    Trial::test(name, move || {
        test().map_err(|error| Failed::from(error.to_string()))
    })
}

fn fixture_hashes() -> TestResult {
    assert_eq!(
        SOURCE,
        "block/buzz@44456e200e3ca6a5d2882b58b447b80474041347"
    );
    let fixtures = [
        (
            include_bytes!("fixtures/buzz/44456e2/initialize.json").as_slice(),
            "a7d047b09b7d09cb5605f2f3577bcd728195c1ca846388d36adfd7ad4af8e77a",
        ),
        (
            include_bytes!("fixtures/buzz/44456e2/session_new.json").as_slice(),
            "5f91e4366930ef1d60261cbe975bceb9ae80eb45770a4ea64d6c820c9845f321",
        ),
        (
            include_bytes!("fixtures/buzz/44456e2/prompt.json").as_slice(),
            "baf0e14be1906d98c335230e532a7dbe664764e3f83eb0f8657c9434f9b749c5",
        ),
        (
            include_bytes!("fixtures/buzz/44456e2/slash_prompt.json").as_slice(),
            "a17af9df5ebbf402b23097304ec0205bec0a407602aa3b4422ec4ad7b0b04eca",
        ),
        (
            include_bytes!("fixtures/buzz/44456e2/cancel.json").as_slice(),
            "4bcc773ac41139ea207551c349d91f86709dc003e81d2af9c9e91b6ceb74b1d9",
        ),
        (
            include_bytes!("fixtures/buzz/44456e2/steer.json").as_slice(),
            "f1d60a4591ca6c532572a9b66e1c86c6b2c800b842d70315178673637970fe38",
        ),
    ];
    for (bytes, expected) in fixtures {
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected);
        let _: Value = serde_json::from_slice(bytes)?;
    }
    Ok(())
}

fn process_boundary_conforms() -> TestResult {
    let layout = Layout::new("contract")?;
    let mut client = Client::spawn(&layout, false)?;
    client.send_partial(&fixture("initialize", &layout.workspace, None)?)?;
    assert_eq!(client.read_id(0)?["result"]["protocolVersion"], 2);

    client.send_partial(&fixture("session_new", &layout.workspace, None)?)?;
    let created = client.read_id(1)?;
    let session = created["result"]["sessionId"]
        .as_str()
        .ok_or_else(|| format!("first session missing: {created}"))?
        .to_owned();
    assert_eq!(created["result"]["configOptions"][0]["configId"], "model");

    let mut second = fixture("session_new", &layout.workspace, None)?;
    second["id"] = json!(20);
    client.send(&second)?;
    let second_session = client.read_id(20)?["result"]["sessionId"]
        .as_str()
        .ok_or("second session missing")?
        .to_owned();
    assert_ne!(session, second_session);

    for (id, config_id, value) in [
        (21, "model", "unknown-model"),
        (22, "thought_level", "ultra"),
    ] {
        client.send(&json!({
            "jsonrpc":"2.0","id":id,"method":"session/set_config_option","params":{
                "sessionId":session,"configId":config_id,"value":value
            }
        }))?;
        assert_eq!(client.read_id(id)?["error"]["code"], -32602);
    }
    client.send(&json!({
        "jsonrpc":"2.0","id":23,"method":"session/set_config_option","params":{
            "sessionId":session,"configId":"thought_level","value":"medium"
        }
    }))?;
    assert_eq!(
        client.read_id(23)?["result"]["configOptions"][1]["currentValue"],
        "medium"
    );
    client.send(&json!({"jsonrpc":"2.0","id":24,"method":"future/method","params":{}}))?;
    assert_eq!(client.read_id(24)?["error"]["code"], -32601);

    client.send_partial(&fixture("prompt", &layout.workspace, Some(&session))?)?;
    assert_eq!(client.read_id(2)?["result"]["stopReason"], "end_turn");

    client.send(&prompt_frame_for_channel(
        30,
        &second_session,
        "wait for cancel",
        'd',
        "22222222-2222-4222-8222-222222222222",
    ))?;
    layout.wait_for_provider_method("turn/start", 2)?;
    let mut steer = fixture("steer", &layout.workspace, Some(&second_session))?;
    steer["id"] = json!(31);
    client.send_partial(&steer)?;
    let steered = client.read_id(31)?;
    assert_eq!(steered["result"]["outcome"], "injected", "{steered}");
    client.send(&fixture(
        "cancel",
        &layout.workspace,
        Some(&second_session),
    )?)?;
    assert_eq!(client.read_id(30)?["result"]["stopReason"], "cancelled");

    let captured = client.finish()?;
    for line in captured
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let frame: Value = serde_json::from_slice(line)?;
        assert_eq!(frame["jsonrpc"], "2.0");
    }
    assert!(
        !captured
            .stdout
            .windows(support::PRIVATE_KEY.len())
            .any(|window| { window == support::PRIVATE_KEY.as_bytes() })
    );
    assert!(captured.stderr.is_empty());
    let messages = layout.publisher_records()?;
    assert_eq!(messages.len(), 1);
    assert!(
        messages[0]["content"]
            .as_str()
            .is_some_and(|content| content.contains("verification"))
    );
    assert!(
        messages
            .iter()
            .all(|message| message["environment_isolated"] == true)
    );
    Ok(())
}
