use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use libtest_mimic::{Arguments, Failed, Trial};
use serde_json::{Value, json};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(status) = dispatch_fixture(&arguments) {
        std::process::exit(status);
    }
    libtest_mimic::run(
        &Arguments::from_args(),
        vec![
            trial(
                "argv-zero exposes only Buzz publication tools as JSON",
                argv_zero_alias_exposes_only_buzz_publication_tools_as_json,
            ),
            trial(
                "ACP rejects key and filesystem setup hazards before stdout",
                acp_rejects_api_key_relative_paths_and_unsafe_roots_before_stdout,
            ),
            trial(
                "ACP isolates Codex and enforces one data-root owner",
                acp_isolates_codex_and_enforces_one_owner,
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

fn argv_zero_alias_exposes_only_buzz_publication_tools_as_json() -> TestResult {
    let layout = Layout::new()?;
    let alias = layout.alias()?;
    let input = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ]
    .into_iter()
    .map(|value| format!("{value}\n"))
    .collect::<String>();
    let mut child = Command::new(alias)
        .current_dir(&layout.workspace)
        .env_clear()
        .env("CARL_DATA_DIR", &layout.data)
        .env(
            "CARL_BUZZ_EXECUTABLE",
            fs::canonicalize(std::env::current_exe()?)?,
        )
        .env("BUZZ_RELAY_URL", "ws://127.0.0.1:7777")
        .env("BUZZ_PRIVATE_KEY", "private-test-value")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(input.as_bytes())?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let frames = String::from_utf8(output.stdout)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(frames.len(), 2);
    let tools = frames[1]["result"]["tools"]
        .as_array()
        .ok_or("tools missing")?;
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "send_message");
    assert_eq!(tools[1]["name"], "send_diff");
    assert!(frames.iter().all(|frame| frame["jsonrpc"] == "2.0"));
    Ok(())
}

fn acp_rejects_api_key_relative_paths_and_unsafe_roots_before_stdout() -> TestResult {
    let layout = Layout::new()?;
    let binary = assert_cmd::cargo::cargo_bin!("carl");
    for environment in [
        vec![
            ("CARL_DATA_DIR", "relative"),
            ("CARL_CODEX_EXECUTABLE", "codex"),
        ],
        vec![
            ("CARL_DATA_DIR", layout.data_str()),
            ("OPENAI_API_KEY", "forbidden"),
        ],
        vec![
            ("CARL_DATA_DIR", layout.data_str()),
            ("CARL_CODEX_EXECUTABLE", "relative"),
        ],
    ] {
        let mut command = Command::new(binary);
        command
            .current_dir(&layout.workspace)
            .env_clear()
            .arg("acp");
        for (name, value) in environment {
            command.env(name, value);
        }
        let output = command.output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&layout.data, fs::Permissions::from_mode(0o755))?;
        let output = Command::new(binary)
            .current_dir(&layout.workspace)
            .env_clear()
            .env("CARL_DATA_DIR", &layout.data)
            .arg("acp")
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    Ok(())
}

fn acp_isolates_codex_and_enforces_one_owner() -> TestResult {
    let layout = Layout::new()?;
    let binary = assert_cmd::cargo::cargo_bin!("carl");
    let provider = fs::canonicalize(std::env::current_exe()?)?;
    let mut first = Command::new(binary)
        .current_dir(&layout.workspace)
        .env_clear()
        .env("CARL_DATA_DIR", fs::canonicalize(&layout.data)?)
        .env("CARL_CODEX_EXECUTABLE", provider)
        .env("BUZZ_PRIVATE_KEY", "must-not-reach-codex")
        .env("BUZZ_RELAY_URL", "wss://must-not-reach-codex.invalid")
        .arg("acp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let marker = layout.data.join("providers/codex/environment-check");
    for _ in 0..200 {
        if marker.exists() {
            break;
        }
        if first.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !marker.exists() {
        drop(first.stdin.take());
        let output = first.wait_with_output()?;
        return Err(format!(
            "first ACP process exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    assert_eq!(fs::read_to_string(&marker)?, "isolated\n");

    let second = Command::new(binary)
        .current_dir(&layout.workspace)
        .env_clear()
        .env("CARL_DATA_DIR", fs::canonicalize(&layout.data)?)
        .env(
            "CARL_CODEX_EXECUTABLE",
            fs::canonicalize(std::env::current_exe()?)?,
        )
        .arg("acp")
        .output()?;
    assert_eq!(second.status.code(), Some(1));
    assert!(second.stdout.is_empty());

    drop(first.stdin.take());
    let output = first.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    Ok(())
}

fn dispatch_fixture(arguments: &[OsString]) -> Option<i32> {
    if arguments == [OsString::from("--version")] {
        if std::env::var_os("CODEX_HOME").is_some() {
            println!("codex-cli 0.146.0");
        } else {
            println!("buzz 0.1.0");
        }
        return Some(0);
    }
    let expected = [
        "app-server",
        "--strict-config",
        "-c",
        "cli_auth_credentials_store=\"keyring\"",
        "--listen",
        "stdio://",
    ];
    arguments
        .iter()
        .map(OsString::as_os_str)
        .eq(expected.iter().map(OsStr::new))
        .then(app_server_fixture)
}

fn app_server_fixture() -> i32 {
    let Some(home) = std::env::var_os("CODEX_HOME").map(PathBuf::from) else {
        return 73;
    };
    let leaked = std::env::vars_os().any(|(name, _)| {
        name == "OPENAI_API_KEY"
            || name == "CODEX_API_KEY"
            || name.to_string_lossy().starts_with("BUZZ_")
    });
    if fs::write(
        home.join("environment-check"),
        if leaked { "leaked\n" } else { "isolated\n" },
    )
    .is_err()
    {
        return 73;
    }
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else {
            return 74;
        };
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            return 65;
        };
        let method = request.get("method").and_then(Value::as_str);
        let result = match method {
            Some("initialized") => continue,
            Some("initialize") => json!({
                "userAgent":"codex_cli_rs/0.146.0", "codexHome":home,
                "platformFamily":"unix", "platformOs":"fixture"
            }),
            Some("model/list") => json!({
                "data":[{
                    "id":"gpt-5.6-codex", "model":"gpt-5.6-codex",
                    "displayName":"GPT-5.6 Codex", "description":"fixture",
                    "isDefault":true, "hidden":false, "defaultReasoningEffort":"high",
                    "supportedReasoningEfforts":[{
                        "reasoningEffort":"high", "description":"High"
                    }]
                }],
                "nextCursor":null
            }),
            _ => return 65,
        };
        if writeln!(
            std::io::stdout().lock(),
            "{}",
            json!({"id":request.get("id"),"result":result})
        )
        .and_then(|()| std::io::stdout().flush())
        .is_err()
        {
            return 74;
        }
    }
    0
}

struct Layout {
    root: PathBuf,
    data: PathBuf,
    workspace: PathBuf,
}

impl Layout {
    fn new() -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!("carl-acp-cli-{}", Uuid::new_v4()));
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
            data,
            workspace,
        })
    }

    fn data_str(&self) -> &str {
        self.data.to_str().expect("test path is UTF-8")
    }

    fn alias(&self) -> TestResult<PathBuf> {
        let source = assert_cmd::cargo::cargo_bin!("carl");
        let name = if cfg!(windows) {
            "carl-buzz-mcp.exe"
        } else {
            "carl-buzz-mcp"
        };
        let alias = self.root.join(name);
        #[cfg(unix)]
        std::os::unix::fs::symlink(source, &alias)?;
        #[cfg(windows)]
        fs::copy(source, &alias)?;
        Ok(alias)
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
