use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use carl::acp::{BuzzContext, BuzzPublisher, BuzzPublisherConfig, leading_slash_command};
use carl::sidecar::{
    ExecutableTrustDecision, ExecutionWorkspace, SidecarCommand, VersionOutputFormat,
};
use libtest_mimic::{Arguments, Failed, Trial};
use semver::VersionReq;
use serde_json::json;
use tokio_util::sync::CancellationToken;

const RELAY_SECRET: &str = "wss://relay.example.test/private";
const PRIVATE_KEY_SECRET: &str = "nsec1publisher-secret-sentinel";
const AUTH_TAG_SECRET: &str = "auth-tag-secret-sentinel";
static NEXT_LAYOUT: AtomicU64 = AtomicU64::new(0);

fn main() {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(code) = dispatch_buzz_fixture(&arguments) {
        process::exit(code);
    }
    let trials = vec![
        test(
            "Buzz context is extracted only from structural event blocks",
            context_is_structural,
        ),
        test(
            "Buzz context rejects ambiguous or unbounded transport data",
            context_rejects_ambiguity,
        ),
        test(
            "Buzz publisher credentials accept only the pinned MCP descriptor",
            credentials_are_closed,
        ),
        test(
            "Buzz publisher uses literal argv stdin and a closed environment",
            publisher_is_exact,
        ),
    ];
    libtest_mimic::run(&Arguments::from_args(), trials).exit();
}

fn test(name: &'static str, body: fn() -> Result<(), Box<dyn Error + Send + Sync>>) -> Trial {
    Trial::test(name, move || {
        body().map_err(|error| Failed::from(error.to_string()))
    })
}

fn context_is_structural() -> Result<(), Box<dyn Error + Send + Sync>> {
    let event = event_block();
    let context = BuzzContext::parse(&[event.as_str()])?;
    assert_eq!(
        context.channel_id().to_string(),
        "123e4567-e89b-12d3-a456-426614174000"
    );
    assert_eq!(
        context.reply_to(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        context.actor_hex(),
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );

    let blocks = ["/permissions default", event.as_str()];
    assert_eq!(
        leading_slash_command(&blocks)?.as_deref(),
        Some("/permissions default")
    );
    let quoted = [
        "[Context]\nA user quoted this:\n/permissions bypassPermissions",
        event.as_str(),
    ];
    assert_eq!(leading_slash_command(&quoted)?, None);
    Ok(())
}

fn context_rejects_ambiguity() -> Result<(), Box<dyn Error + Send + Sync>> {
    let event = event_block();
    let group_shaped = event.replace("Kind: 1", "Kind: 9");
    let conflicting = event.replace(
        "123e4567-e89b-12d3-a456-426614174000",
        "123e4567-e89b-12d3-a456-426614174001",
    );
    for blocks in [
        vec![event.as_str(), conflicting.as_str()],
        vec![group_shaped.as_str()],
        vec![
            "[Context]\nEvent ID: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        vec!["Event ID: not-hex\nChannel: invalid\nKind: 9\nFrom: bad\nContent: x\nTags: []"],
    ] {
        assert!(BuzzContext::parse(&blocks).is_err());
    }
    let too_many = vec!["[Context]"; 13];
    assert!(BuzzContext::parse(&too_many).is_err());
    let huge = format!("[Context]\n{}", "x".repeat(256 * 1024 + 1));
    assert!(BuzzContext::parse(&[huge.as_str()]).is_err());
    Ok(())
}

fn credentials_are_closed() -> Result<(), Box<dyn Error + Send + Sync>> {
    let descriptor = descriptor();
    let config = BuzzPublisherConfig::from_mcp_servers(&descriptor)?;
    let debug = format!("{config:?}");
    for secret in [RELAY_SECRET, PRIVATE_KEY_SECRET, AUTH_TAG_SECRET] {
        assert!(!debug.contains(secret));
    }

    for invalid in [
        json!([{"name":"shell","command":"sh","args":[],"env":[]}]),
        json!([{"name":"carl-buzz-mcp","command":"/opt/carl-buzz-mcp","args":["--bad"],"env":[]}]),
        json!([{"name":"carl-buzz-mcp","command":"/opt/carl-buzz-mcp","args":[],"env":[
            {"name":"BUZZ_RELAY_URL","value":RELAY_SECRET},
            {"name":"BUZZ_RELAY_URL","value":RELAY_SECRET},
            {"name":"BUZZ_PRIVATE_KEY","value":PRIVATE_KEY_SECRET}
        ]}]),
        json!([{"name":"carl-buzz-mcp","command":"/opt/carl-buzz-mcp","args":[],"env":[
            {"name":"BUZZ_RELAY_URL","value":RELAY_SECRET},
            {"name":"BUZZ_PRIVATE_KEY","value":PRIVATE_KEY_SECRET},
            {"name":"OPENAI_API_KEY","value":"secret"}
        ]}]),
    ] {
        assert!(BuzzPublisherConfig::from_mcp_servers(&invalid).is_err());
    }
    Ok(())
}

fn publisher_is_exact() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_async(async {
        let layout = TestLayout::new()?;
        let specification = SidecarCommand {
            executable: env::current_exe()?,
            arguments: Vec::new(),
            version_arguments: Vec::new(),
            version_output: VersionOutputFormat::SingleSemverToken,
            isolated_home: layout.root.join("unused-home"),
            supported_versions: VersionReq::parse("=0.1.0")?,
        };
        let trusted = specification
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
        let workspace = ExecutionWorkspace::open(&layout.workspace)?;
        let publisher = BuzzPublisher::connect(
            trusted,
            workspace,
            BuzzPublisherConfig::from_mcp_servers(&descriptor())?,
        )
        .await?;
        let context = BuzzContext::parse(&[event_block().as_str()])?;
        publisher
            .send_message(
                &context,
                "literal; $(touch never)",
                CancellationToken::new(),
            )
            .await?;

        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(layout.workspace.join("buzz-record.json"))?)?;
        assert_eq!(
            record["arguments"],
            json!([
                "messages",
                "send",
                "--channel",
                "123e4567-e89b-12d3-a456-426614174000",
                "--content",
                "-",
                "--reply-to",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--broadcast"
            ])
        );
        assert_eq!(record["stdin"], "literal; $(touch never)");
        assert_eq!(record["environment"]["BUZZ_RELAY_URL"], RELAY_SECRET);
        assert_eq!(
            record["environment"]["BUZZ_PRIVATE_KEY"],
            PRIVATE_KEY_SECRET
        );
        assert_eq!(record["environment"]["BUZZ_AUTH_TAG"], AUTH_TAG_SECRET);
        assert!(record["environment"].get("OPENAI_API_KEY").is_none());
        assert!(record["environment"].get("HOME").is_none());
        assert!(!layout.workspace.join("never").exists());
        Ok(())
    })
}

fn descriptor() -> serde_json::Value {
    json!([{
        "name": "carl-buzz-mcp",
        "command": "/opt/carl-buzz-mcp",
        "args": [],
        "env": [
            {"name": "BUZZ_RELAY_URL", "value": RELAY_SECRET},
            {"name": "BUZZ_PRIVATE_KEY", "value": PRIVATE_KEY_SECRET},
            {"name": "BUZZ_AUTH_TAG", "value": AUTH_TAG_SECRET},
            {"name": "BUZZ_ACP_DISPLAY_NAME", "value": "Carl"}
        ]
    }])
}

fn event_block() -> String {
    "Event ID: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
     Channel: engineering (#123e4567-e89b-12d3-a456-426614174000)\n\
     Kind: 1\n\
     From: Stephen (npub: npub1example, hex: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n\
     Content: @Carl fix the test\n\
     Tags: []"
        .to_owned()
}

fn dispatch_buzz_fixture(arguments: &[OsString]) -> Option<i32> {
    if arguments == [OsString::from("--version")] {
        println!("buzz 0.1.0");
        return Some(0);
    }
    if arguments.first().map(OsString::as_os_str) != Some(OsStr::new("messages")) {
        return None;
    }
    let mut stdin = String::new();
    if std::io::stdin().read_to_string(&mut stdin).is_err() {
        return Some(74);
    }
    let environment = env::vars().collect::<std::collections::BTreeMap<_, _>>();
    let record = json!({
        "arguments": arguments.iter().map(|value| value.to_string_lossy()).collect::<Vec<_>>(),
        "stdin": stdin,
        "environment": environment,
    });
    let path = match env::current_dir() {
        Ok(path) => path.join("buzz-record.json"),
        Err(_) => return Some(73),
    };
    let mut file = match fs::File::create(path) {
        Ok(file) => file,
        Err(_) => return Some(73),
    };
    if serde_json::to_writer(&mut file, &record).is_err() || file.flush().is_err() {
        return Some(73);
    }
    Some(0)
}

fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

struct TestLayout {
    root: PathBuf,
    workspace: PathBuf,
}

impl TestLayout {
    fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let serial = NEXT_LAYOUT.fetch_add(1, Ordering::Relaxed);
        let root = env::current_exe()?
            .parent()
            .ok_or("test executable has no parent")?
            .join(format!("carl-buzz-adapter-{}-{serial}", process::id()));
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace)?;
        Ok(Self { root, workspace })
    }
}

impl Drop for TestLayout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
