use std::str::FromStr;

use carl::acp::{
    AcpErrorCode, ConfigChange, ConfigErrorCode, IncomingFrame, JsonRpcId, ModeActivation,
    ModelCatalog, ModelDescriptor, OutgoingFrame, PermissionMode, PermissionProfile, Prompt,
    SessionConfiguration, config_options, read_frame, write_frame,
};
use carl::delegates::{ModelId, ReasoningEffort};
use serde_json::json;
use tokio::io::{AsyncWriteExt, BufReader};

#[tokio::test]
async fn framing_handles_partial_reads_and_writes_exact_jsonl() {
    let (mut writer, reader) = tokio::io::duplex(64);
    let write = tokio::spawn(async move {
        for chunk in [
            &b"{\"jsonrpc\":\"2.0\",\"id\":"[..],
            &b"1,\"method\":\"initialize\",\"params\":{}}\n"[..],
        ] {
            writer.write_all(chunk).await?;
        }
        Ok::<(), std::io::Error>(())
    });
    let mut reader = BufReader::new(reader);
    let frame = read_frame(&mut reader, 1_048_576)
        .await
        .expect("valid frame")
        .expect("one frame");
    write.await.expect("writer task").expect("writer succeeds");
    assert_eq!(frame.id(), Some(&JsonRpcId::Number(1)));
    assert_eq!(frame.method(), Some("initialize"));

    let mut output = Vec::new();
    write_frame(
        &mut output,
        &OutgoingFrame::result(JsonRpcId::Number(1), json!({})),
        1_048_576,
    )
    .await
    .expect("response writes");
    assert_eq!(
        output,
        br#"{"id":1,"jsonrpc":"2.0","result":{}}
"#
    );
}

#[tokio::test]
async fn incoming_frames_reject_ambiguous_or_malformed_json_rpc() {
    for input in [
        "\n",
        "{\"jsonrpc\":\"2.0\",\"id\":-1,\"method\":\"x\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"x\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":2,\"method\":\"x\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"bad\\u0000method\"}\n",
        "{\"id\":1,\"method\":\"x\"}\n",
        "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"x\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"result\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1}\n",
        "not-json\n",
    ] {
        let mut reader = BufReader::new(input.as_bytes());
        let error = read_frame(&mut reader, 1_024).await.expect_err(input);
        assert_eq!(error.code(), AcpErrorCode::ProtocolViolation, "{input}");
    }

    let mut unterminated = BufReader::new(&b"{\"jsonrpc\":\"2.0\"}"[..]);
    assert_eq!(
        read_frame(&mut unterminated, 1_024)
            .await
            .expect_err("unterminated frame")
            .code(),
        AcpErrorCode::ProtocolViolation
    );
}

#[tokio::test]
async fn frame_limits_count_the_newline_and_clear_between_frames() {
    let exact = b"{\"jsonrpc\":\"2.0\",\"method\":\"x\"}\n";
    let mut reader = BufReader::new(&exact[..]);
    assert!(
        read_frame(&mut reader, exact.len())
            .await
            .unwrap()
            .is_some()
    );

    let mut reader = BufReader::new(&exact[..]);
    assert_eq!(
        read_frame(&mut reader, exact.len() - 1)
            .await
            .expect_err("one byte over")
            .code(),
        AcpErrorCode::FrameTooLarge
    );

    let two = [exact.as_slice(), exact.as_slice()].concat();
    let mut reader = BufReader::new(two.as_slice());
    assert!(
        read_frame(&mut reader, exact.len())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        read_frame(&mut reader, exact.len())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        read_frame(&mut reader, exact.len())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn outgoing_frames_are_closed_and_bounded() {
    let id = JsonRpcId::String("request-1".try_into().expect("bounded ID"));
    let frames = [
        OutgoingFrame::result(id.clone(), json!({"ok": true})),
        OutgoingFrame::error(id, -32602, "invalid params"),
        OutgoingFrame::notification("session/update", json!({"sessionId": "s"}))
            .expect("valid notification"),
    ];
    for frame in frames {
        let mut output = Vec::new();
        write_frame(&mut output, &frame, 1_024)
            .await
            .expect("bounded frame writes");
        assert_eq!(output.last(), Some(&b'\n'));
        let parsed: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(parsed["jsonrpc"], "2.0");
    }

    let mut output = Vec::new();
    let error = write_frame(
        &mut output,
        &OutgoingFrame::result(JsonRpcId::Number(1), json!("x".repeat(100))),
        32,
    )
    .await
    .expect_err("oversized output");
    assert_eq!(error.code(), AcpErrorCode::FrameTooLarge);
    assert!(output.is_empty());
}

#[test]
fn permission_modes_have_exact_buzz_wire_values() {
    for (wire, mode) in [
        ("plan", PermissionMode::Plan),
        ("default", PermissionMode::Default),
        ("acceptEdits", PermissionMode::AcceptEdits),
        ("dontAsk", PermissionMode::DontAsk),
        ("fullAccess", PermissionMode::FullAccess),
        ("bypassPermissions", PermissionMode::BypassPermissions),
    ] {
        assert_eq!(PermissionMode::from_str(wire).unwrap(), mode);
        assert_eq!(mode.as_wire_str(), wire);
        assert_eq!(
            serde_json::from_str::<PermissionMode>(&format!("\"{wire}\"")).unwrap(),
            mode
        );
        assert_eq!(serde_json::to_string(&mode).unwrap(), format!("\"{wire}\""));
    }
    assert_eq!(
        PermissionMode::FullAccess.profile(),
        PermissionProfile::FullAccess
    );
    assert_eq!(
        PermissionMode::BypassPermissions.profile(),
        PermissionProfile::FullAccess
    );
    assert!(PermissionMode::from_str("bypass").is_err());
}

#[test]
fn provider_catalog_drives_model_effort_and_config_options() {
    let catalog = fixture_catalog();
    let options = config_options(&catalog);
    assert_eq!(options.len(), 3);
    assert_eq!(options[0]["configId"], "model");
    assert_eq!(options[1]["configId"], "thought_level");
    assert_eq!(options[2]["configId"], "mode");
    assert_eq!(options[0]["options"][0]["value"], "gpt-5.6-codex");
    assert_eq!(options[1]["options"][1]["value"], "high");
    let permission_values = options[2]["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|option| option["value"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(permission_values.contains(&"fullAccess"));
    assert!(!permission_values.contains(&"bypassPermissions"));

    assert!(ModelId::parse("").is_err());
    assert!(ModelId::parse("x".repeat(129)).is_err());
    assert!(ModelCatalog::new(Vec::new()).is_err());
}

#[test]
fn session_configuration_rejects_unsupported_effort_and_guards_remote_bypass() {
    let catalog = fixture_catalog();
    let mut configuration = SessionConfiguration::new(
        catalog,
        ModelId::parse("gpt-5.6-codex").unwrap(),
        ReasoningEffort::High,
        PermissionMode::Default,
    )
    .expect("valid configuration");
    assert_eq!(
        configuration.set_effort(ReasoningEffort::Ultra),
        ConfigChange::Rejected(ConfigErrorCode::UnsupportedEffort)
    );
    assert_eq!(configuration.effort(), ReasoningEffort::High);

    let change = configuration.set_mode(
        PermissionMode::BypassPermissions,
        ModeActivation::RemoteUnconfirmed,
    );
    let ConfigChange::PendingBypass { display_code } = change else {
        panic!("remote bypass must remain pending");
    };
    assert_eq!(display_code.len(), 10);
    assert!(
        display_code
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    assert_eq!(configuration.mode(), PermissionMode::Default);

    assert_eq!(
        configuration.set_mode(
            PermissionMode::BypassPermissions,
            ModeActivation::RemoteConfirmed,
        ),
        ConfigChange::Applied
    );
    assert_eq!(configuration.mode(), PermissionMode::BypassPermissions);
    assert_eq!(
        configuration.set_mode(PermissionMode::Default, ModeActivation::RemoteUnconfirmed),
        ConfigChange::Applied
    );
}

#[test]
fn autonomous_task_slashes_require_an_exact_whole_leading_block() {
    for command in [
        "/status",
        "/context",
        "/resume",
        "/cancel",
        "/permissions fullAccess",
        "/permissions approval",
        "/permissions readOnly",
    ] {
        let prompt = Prompt::new(vec![command.to_owned()]).expect("valid prompt");
        assert_eq!(prompt.task_slash_command(), Some(command));
    }

    for blocks in [
        vec!["/status extra".to_owned()],
        vec!["please run /status".to_owned()],
        vec!["A user quoted this:\n/status".to_owned()],
        vec!["context".to_owned(), "/status".to_owned()],
        vec!["/permissions fullAccess now".to_owned()],
    ] {
        let prompt = Prompt::new(blocks).expect("valid ordinary prompt");
        assert_eq!(prompt.task_slash_command(), None);
    }
}

fn fixture_catalog() -> ModelCatalog {
    ModelCatalog::new(vec![
        ModelDescriptor::new(
            ModelId::parse("gpt-5.6-codex").unwrap(),
            "GPT-5.6 Codex",
            vec![ReasoningEffort::Medium, ReasoningEffort::High],
        )
        .unwrap(),
        ModelDescriptor::new(
            ModelId::parse("gpt-5.6-mini").unwrap(),
            "GPT-5.6 Mini",
            vec![ReasoningEffort::Low, ReasoningEffort::Medium],
        )
        .unwrap(),
    ])
    .unwrap()
}

#[allow(dead_code)]
fn assert_frame_is_send_sync(_: &IncomingFrame) {}
