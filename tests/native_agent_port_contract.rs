use std::error::Error;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::providers::catalog::{ProviderCatalog, ProviderKind, ProviderModel};
use carl::providers::scripted::ScriptedProvider;
use carl::runtime::agent_port::{
    AgentEvent, AgentPort, EffectDecision, StartAgentContext, StartAgentEpoch,
};
use carl::runtime::native_port::NativeAgentPort;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
static SERIAL: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
async fn read_tools_loop_back_into_the_provider_and_complete_one_epoch() -> TestResult {
    let fixture = Fixture::new()?;
    fs::write(fixture.path.join("README.md"), "# Carl\n")?;
    let provider = Arc::new(ScriptedProvider::from_json(&script(
        "read_file",
        r#"{"path":"README.md"}"#,
    ))?);
    let mut port = NativeAgentPort::new(provider.clone(), catalog());
    let context_id = port
        .start_context(StartAgentContext {
            cwd: fixture.path.clone(),
            model: model(),
            permission_mode: PermissionMode::FullAccess,
        })
        .await?;
    assert!(matches!(
        port.next_event().await?,
        AgentEvent::ContextStarted { .. }
    ));
    let epoch_id = port
        .start_epoch(StartAgentEpoch {
            context_id: context_id.clone(),
            input: "Read README.md".to_owned(),
            model: model(),
            effort: ReasoningEffort::High,
            permission_mode: PermissionMode::FullAccess,
        })
        .await?;
    let mut completed = false;
    for _ in 0..10 {
        if let AgentEvent::EpochCompleted {
            epoch_id: observed,
            status,
            ..
        } = port.next_event().await?
        {
            assert_eq!(observed, epoch_id);
            assert_eq!(status, "completed");
            completed = true;
            break;
        }
    }
    assert!(completed);
    let requests = provider.recorded_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].messages.iter().any(|message| {
        message.content.iter().any(|content| matches!(content, carl::providers::MessageContent::ToolResult { output, .. } if output["text"] == "# Carl\n"))
    }));
    Ok(())
}

#[tokio::test]
async fn consequential_tools_pause_for_durable_effect_decisions_and_execute_once() -> TestResult {
    let fixture = Fixture::new()?;
    fs::write(fixture.path.join("src.txt"), "before\n")?;
    let provider = Arc::new(ScriptedProvider::from_json(&script(
        "apply_patch",
        r#"{"changes":[{"path":"src.txt","find":"before","replace":"after"}]}"#,
    ))?);
    let mut port = NativeAgentPort::new(provider, catalog());
    let context_id = port
        .start_context(StartAgentContext {
            cwd: fixture.path.clone(),
            model: model(),
            permission_mode: PermissionMode::FullAccess,
        })
        .await?;
    let _ = port.next_event().await?;
    port.start_epoch(StartAgentEpoch {
        context_id,
        input: "Fix it".to_owned(),
        model: model(),
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::FullAccess,
    })
    .await?;
    let request = loop {
        if let AgentEvent::EffectRequested(request) = port.next_event().await? {
            break request;
        }
    };
    assert_eq!(
        fs::read_to_string(fixture.path.join("src.txt"))?,
        "before\n"
    );
    port.resolve_effect(&request.request_id, EffectDecision::Allow)
        .await?;
    assert_eq!(fs::read_to_string(fixture.path.join("src.txt"))?, "after\n");
    let mut completed = false;
    for _ in 0..10 {
        if matches!(port.next_event().await?, AgentEvent::EpochCompleted { .. }) {
            completed = true;
            break;
        }
    }
    assert!(completed);
    assert!(
        port.resolve_effect(&request.request_id, EffectDecision::Allow)
            .await
            .is_err()
    );
    Ok(())
}

fn script(tool: &str, arguments: &str) -> String {
    format!(
        r#"{{
      "schema_version":1,
      "capabilities":{{"streaming":true,"structured_tool_calls":true,"parallel_tool_calls":true,"usage_reporting":true,"context_window":131072}},
      "responses":[
        {{"events":[
          {{"type":"tool_call","tool_call_id":"11111111-1111-4111-8111-111111111111","provider_call_id":"call_1","name":"{tool}","arguments":{arguments}}},
          {{"type":"usage","input_tokens":10,"output_tokens":4}},
          {{"type":"finish","reason":"tool_calls"}}
        ]}},
        {{"events":[
          {{"type":"text_delta","text":"done"}},
          {{"type":"usage","input_tokens":20,"output_tokens":5}},
          {{"type":"finish","reason":"stop"}}
        ]}}
      ]
    }}"#
    )
}

fn model() -> ModelId {
    ModelId::parse("fixture-coder").unwrap()
}

fn catalog() -> ProviderCatalog {
    let model = ProviderModel::new(
        model(),
        "Fixture Coder".to_owned(),
        131_072,
        vec![ReasoningEffort::High],
        ReasoningEffort::High,
        true,
        true,
        true,
    )
    .unwrap();
    ProviderCatalog::new(
        ProviderKind::OpenAiApi,
        vec![model.clone()],
        model.id().clone(),
    )
    .unwrap()
}

struct Fixture {
    path: std::path::PathBuf,
}
impl Fixture {
    fn new() -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "carl-native-port-{}-{nonce}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self {
            path: fs::canonicalize(path)?,
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
