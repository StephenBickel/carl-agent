use std::error::Error;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use carl::acp::PermissionMode;
use carl::tools::{NativeToolErrorCode, NativeToolRuntime, ToolEffectKind};
use serde_json::json;
use tokio_util::sync::CancellationToken;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
static FIXTURE_SERIAL: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
async fn definitions_and_read_only_tools_are_bounded_and_workspace_relative() -> TestResult {
    let fixture = Fixture::new()?;
    fs::write(fixture.path.join("README.md"), "alpha\nbeta\nalpha\n")?;
    fs::create_dir(fixture.path.join("src"))?;
    fs::write(fixture.path.join("src/lib.rs"), "pub fn alpha() {}\n")?;
    let runtime = NativeToolRuntime::new(&fixture.path, PermissionMode::FullAccess)?;
    assert_eq!(runtime.definitions().len(), 5);
    assert_eq!(
        runtime
            .definitions()
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        [
            "read_file",
            "list_directory",
            "search_text",
            "apply_patch",
            "run_command"
        ]
    );

    let read = runtime.prepare(
        "read_file",
        json!({"path":"README.md","start_line":2,"end_line":3}),
    )?;
    assert_eq!(read.effect_kind(), ToolEffectKind::Read);
    assert_eq!(
        read.execute(CancellationToken::new()).await?["text"],
        "beta\nalpha\n"
    );

    let list = runtime.prepare("list_directory", json!({"path":"."}))?;
    assert_eq!(
        list.execute(CancellationToken::new()).await?["entries"],
        json!([
            {"path":"README.md","kind":"file"},{"path":"src","kind":"directory"}
        ])
    );

    let search = runtime.prepare("search_text", json!({"query":"alpha","path":"."}))?;
    let result = search.execute(CancellationToken::new()).await?;
    assert_eq!(result["matches"].as_array().unwrap().len(), 3);
    Ok(())
}

#[tokio::test]
async fn structured_patch_and_argv_command_execute_without_a_shell() -> TestResult {
    let fixture = Fixture::new()?;
    fs::write(fixture.path.join("one.txt"), "old one\n")?;
    fs::write(fixture.path.join("two.txt"), "old two\n")?;
    let runtime = NativeToolRuntime::new(&fixture.path, PermissionMode::FullAccess)?;
    let patch = runtime.prepare(
        "apply_patch",
        json!({"changes":[
            {"path":"one.txt","find":"old one","replace":"new one"},
            {"path":"two.txt","find":"old two","replace":"new two"}
        ]}),
    )?;
    assert_eq!(patch.effect_kind(), ToolEffectKind::Write);
    assert_eq!(
        patch.execute(CancellationToken::new()).await?["changed_files"],
        2
    );
    assert_eq!(
        fs::read_to_string(fixture.path.join("one.txt"))?,
        "new one\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.path.join("two.txt"))?,
        "new two\n"
    );

    let command = runtime.prepare(
        "run_command",
        json!({"argv":["/bin/sh","-c","printf should-not-run"],"timeout_seconds":5}),
    );
    assert_eq!(
        command.unwrap_err().code(),
        NativeToolErrorCode::InvalidArguments
    );
    let command = runtime.prepare(
        "run_command",
        json!({"argv":["/usr/bin/printf","hello %s","Carl"],"timeout_seconds":5}),
    )?;
    assert_eq!(command.effect_kind(), ToolEffectKind::Command);
    let output = command.execute(CancellationToken::new()).await?;
    assert_eq!(output["exit_code"], 0);
    assert_eq!(output["stdout"], "hello Carl");
    Ok(())
}

#[tokio::test]
async fn unsafe_paths_secrets_cancellation_and_stale_preparation_fail_closed() -> TestResult {
    let fixture = Fixture::new()?;
    fs::write(fixture.path.join("safe.txt"), "safe\n")?;
    fs::write(
        fixture.path.join("secret.txt"),
        "sk-proj-fixture-secret-1234567890\n",
    )?;
    let runtime = NativeToolRuntime::new(&fixture.path, PermissionMode::FullAccess)?;
    for path in ["/etc/passwd", "../outside", ".git/config"] {
        assert_eq!(
            runtime
                .prepare("read_file", json!({"path":path}))
                .unwrap_err()
                .code(),
            NativeToolErrorCode::UnsafePath
        );
    }
    assert_eq!(
        runtime
            .prepare("read_file", json!({"path":"secret.txt"}))?
            .execute(CancellationToken::new())
            .await
            .unwrap_err()
            .code(),
        NativeToolErrorCode::SecretDetected
    );
    let stale = runtime.prepare("read_file", json!({"path":"safe.txt"}))?;
    fs::write(fixture.path.join("safe.txt"), "changed\n")?;
    assert_eq!(
        stale
            .execute(CancellationToken::new())
            .await
            .unwrap_err()
            .code(),
        NativeToolErrorCode::WorkspaceChanged
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        runtime
            .prepare("list_directory", json!({"path":"."}))?
            .execute(cancelled)
            .await
            .unwrap_err()
            .code(),
        NativeToolErrorCode::Cancelled
    );
    Ok(())
}

struct Fixture {
    path: std::path::PathBuf,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let serial = FIXTURE_SERIAL.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "carl-native-tools-{}-{nonce}-{serial}",
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
