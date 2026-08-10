use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use carl::acp::{BuzzContext, BuzzError};
use carl::buzz_mcp::{BuzzToolBackend, run_stdio};
use serde_json::{Value, json};
use tokio::io::BufReader;

#[tokio::test]
async fn mcp_lists_only_two_closed_tools_and_dispatches_literal_content()
-> Result<(), Box<dyn std::error::Error>> {
    let input = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call","params":{
                "name":"send_message",
                "arguments":{
                    "channel_id":"123e4567-e89b-12d3-a456-426614174000",
                    "reply_to":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "actor_hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "content":"literal; $(touch never)"
                }
            }
        }),
    ]
    .into_iter()
    .map(|value| format!("{value}\n"))
    .collect::<String>();
    let backend = RecordingBackend::default();
    let mut reader = BufReader::new(input.as_bytes());
    let mut output = Vec::new();
    run_stdio(&mut reader, &mut output, &backend)
        .await
        .expect("MCP session succeeds");

    let responses = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(responses.len(), 3);
    assert_eq!(
        responses[0]["result"]["serverInfo"]["name"],
        "carl-buzz-mcp"
    );
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "send_message");
    assert_eq!(tools[1]["name"], "send_diff");
    for tool in tools {
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    }
    assert_eq!(responses[2]["result"]["isError"], false);
    assert_eq!(
        backend.calls.lock().unwrap().as_slice(),
        &["message:literal; $(touch never)".to_owned()]
    );
    Ok(())
}

#[tokio::test]
async fn mcp_rejects_unknown_fields_methods_and_invalid_transport_ids()
-> Result<(), Box<dyn std::error::Error>> {
    let input = [
        json!({"jsonrpc":"2.0","id":1,"method":"unknown","params":{}}),
        json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call","params":{
                "name":"send_message",
                "arguments":{
                    "channel_id":"123e4567-e89b-12d3-a456-426614174000",
                    "reply_to":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "actor_hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "content":"hello",
                    "BUZZ_PRIVATE_KEY":"must-not-be-accepted"
                }
            }
        }),
    ]
    .into_iter()
    .map(|value| format!("{value}\n"))
    .collect::<String>();
    let backend = RecordingBackend::default();
    let mut reader = BufReader::new(input.as_bytes());
    let mut output = Vec::new();
    run_stdio(&mut reader, &mut output, &backend).await?;
    let responses = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(responses[0]["error"]["code"], -32601);
    assert_eq!(responses[1]["error"]["code"], -32602);
    assert!(backend.calls.lock().unwrap().is_empty());
    Ok(())
}

#[derive(Default)]
struct RecordingBackend {
    calls: Mutex<Vec<String>>,
}

impl BuzzToolBackend for RecordingBackend {
    fn send_message<'a>(
        &'a self,
        _context: &'a BuzzContext,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BuzzError>> + Send + 'a>> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push(format!("message:{content}"));
            Ok(())
        })
    }

    fn send_diff<'a>(
        &'a self,
        _context: &'a BuzzContext,
        diff: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BuzzError>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(format!("diff:{diff}"));
            Ok(())
        })
    }
}
