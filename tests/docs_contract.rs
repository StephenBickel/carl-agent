use std::{collections::BTreeSet, fs, path::PathBuf, process::Command};

use carl::cli::Cli;
use clap::{CommandFactory, Parser, error::ErrorKind};

const PUBLIC_DOCS: &[&str] = &[
    "CARL.md",
    "README.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "docs/architecture.md",
    "docs/security.md",
    "docs/configuration.md",
    "docs/buzz.md",
    "docs/long-horizon-tasks.md",
    "docs/benchmarks.md",
    "docs/memory.md",
    "docs/telegram.md",
    "docs/adr/0001-event-sourced-runtime.md",
    "docs/adr/0002-single-process-v1.md",
    "docs/adr/0003-no-undocumented-oauth.md",
    "docs/adr/0004-subscription-authentication-through-provider-sidecars.md",
    "docs/adr/0005-local-curated-memory.md",
    "docs/superpowers/specs/2026-07-23-carl-top-tier-harness-design.md",
];

const AUTH_COMMANDS: &[&str] = &[
    "carl auth status",
    "carl auth login openai",
    "carl auth login openai --device",
    "carl auth logout openai",
    "carl auth login grok",
    "carl auth login grok --device",
    "carl auth logout grok",
];

const BUZZ_SETTINGS: &[&str] = &[
    "export BUZZ_ACP_AGENT_COMMAND=carl",
    "export BUZZ_ACP_AGENT_ARGS=acp",
    "export BUZZ_ACP_MCP_COMMAND=carl-buzz-mcp",
    "export BUZZ_ACP_AGENTS=1",
    "export BUZZ_ACP_RESPOND_TO=owner-only",
    "export BUZZ_ACP_PERMISSION_MODE=default",
];

const ACTIVE_IDENTITY_SURFACES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "README.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "docs/architecture.md",
    "docs/security.md",
    "docs/configuration.md",
    "docs/memory.md",
    "docs/telegram.md",
    "docs/adr/0002-single-process-v1.md",
    "docs/adr/0003-no-undocumented-oauth.md",
    "docs/adr/0004-subscription-authentication-through-provider-sidecars.md",
    "docs/adr/0005-local-curated-memory.md",
    "src/cli.rs",
    "src/error.rs",
    "src/main.rs",
    "src/memory/mod.rs",
    "src/runtime/budget.rs",
    "src/storage/repository.rs",
    "src/storage/schema.rs",
    "tests/cli_contract.rs",
    "tests/docs_contract.rs",
    "tests/domain_contract.rs",
    "tests/identity_contract.rs",
    "tests/memory_cli_contract.rs",
    "tests/memory_contract.rs",
    "tests/provider_contract.rs",
    "tests/storage_contract.rs",
    "tests/workflow_contract.rs",
    "tests/fixtures/provider/tool_then_answer.json",
];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_readme() -> String {
    read_document("README.md")
}

fn read_document(relative_path: &str) -> String {
    let path = repository_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn normalized_document(relative_path: &str) -> String {
    read_document(relative_path)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn assert_document_contains(relative_path: &str, required_statements: &[&str]) {
    let normalized = normalized_document(relative_path);

    for required_statement in required_statements {
        assert!(
            normalized.contains(required_statement),
            "{relative_path} is missing critical statement fragment: {required_statement:?}"
        );
    }
}

#[test]
fn public_project_documents_exist() {
    for relative_path in PUBLIC_DOCS {
        let path = repository_root().join(relative_path);
        assert!(
            path.is_file(),
            "required public document is missing: {}",
            path.display()
        );
    }
}

#[test]
fn readme_local_links_resolve_to_files() {
    let readme = read_readme();
    let mut local_link_count = 0;

    for raw_target in markdown_link_targets(&readme) {
        let target = raw_target.trim().trim_matches(['<', '>']);
        if target.is_empty()
            || target.starts_with('#')
            || target.starts_with("http://")
            || target.starts_with("https://")
            || target.starts_with("mailto:")
        {
            continue;
        }

        local_link_count += 1;
        let path_without_anchor = target
            .split_once('#')
            .map_or(target, |(path, _anchor)| path);
        let path = repository_root().join(path_without_anchor);
        assert!(
            path.is_file(),
            "README local link does not resolve: {target} ({})",
            path.display()
        );
    }

    assert!(
        local_link_count > 0,
        "README must link to at least one local project document"
    );
}

#[test]
fn fenced_carl_commands_match_the_clap_command_tree() {
    let readme = read_readme();
    validate_fenced_carl_commands(&readme).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn fenced_carl_command_checker_rejects_unknown_option_only_invocations() {
    let markdown = "```sh\ncarl --bogus\n```";

    let error = validate_fenced_carl_commands(markdown)
        .expect_err("the docs checker must reject an unknown root option");

    assert!(error.contains("--bogus"));
}

#[test]
fn all_documented_auth_invocations_match_the_clap_command_tree() {
    for invocation in AUTH_COMMANDS {
        Cli::try_parse_from(invocation.split_whitespace()).unwrap_or_else(|error| {
            panic!("documented auth invocation must parse: `{invocation}`: {error}")
        });
    }
}

#[test]
fn readme_includes_all_seven_auth_invocations() {
    let readme = read_readme();
    let fenced_commands: BTreeSet<_> = fenced_carl_commands(&readme).into_iter().collect();

    for invocation in AUTH_COMMANDS {
        assert!(
            fenced_commands.contains(invocation),
            "README is missing fenced auth invocation: `{invocation}`"
        );
    }
}

#[test]
fn readme_and_buzz_guide_publish_the_safe_operational_settings() {
    for relative_path in ["README.md", "docs/buzz.md"] {
        let document = read_document(relative_path);
        for setting in BUZZ_SETTINGS {
            assert!(
                document.lines().any(|line| line == *setting),
                "{relative_path} is missing exact Buzz setting: `{setting}`"
            );
        }
    }

    assert_document_contains(
        "docs/buzz.md",
        &[
            "`carl auth login openai`",
            "there is no api-key fallback",
            "`/approve <code>`",
            "`/deny <code>`",
            "local bypass",
            "remote bypass",
            "single-process v1",
            "`44456e200e3ca6a5d2882b58b447b80474041347`",
            "credential isolation",
            "steering",
            "cancellation",
            "`carl_buzz_executable`",
            "node scripts/live-codex-acp-smoke.mjs",
        ],
    );
    assert!(
        repository_root()
            .join("scripts/live-codex-acp-smoke.mjs")
            .is_file(),
        "the documented opt-in live smoke script must exist"
    );
}

#[test]
fn long_horizon_runner_self_test_enforces_the_offline_contract() {
    let script = repository_root().join("scripts/live-codex-long-horizon.mjs");
    assert!(script.is_file(), "the opt-in endurance runner must exist");

    let mut command = Command::new("node");
    command
        .arg(&script)
        .arg("--self-test")
        .current_dir(repository_root())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    #[cfg(windows)]
    for key in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    let output = command
        .output()
        .expect("the offline endurance self-test must start");
    assert!(
        output.status.success(),
        "offline endurance self-test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "successful self-test must be quiet"
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("self-test stdout must be UTF-8"),
        "{\"schema_version\":1,\"passed\":true,\"checks\":7}\n"
    );

    let source = read_document("scripts/live-codex-long-horizon.mjs");
    for required in [
        "CARL_DATA_DIR=/absolute/private/root",
        "CARL_CODEX_EXECUTABLE=/absolute/path/to/codex",
        "CARL_BIN=/absolute/path/to/release/carl",
        "CARL_LIVE_MODEL=gpt-5.6-terra",
        "CARL_LIVE_EFFORT=low",
        "CARL_LIVE_DURATION_HOURS=2",
        "node scripts/live-codex-long-horizon.mjs",
        "--self-test",
        "thirty independent paired runs",
        "no result artifact",
    ] {
        assert!(
            source.contains(required),
            "endurance runner is missing pinned contract text: {required:?}"
        );
    }
}

#[test]
fn long_horizon_runtime_guarantees_and_benchmark_limits_are_documented() {
    assert_document_contains(
        "README.md",
        &[
            "owner-selected full access is accepted risk",
            "[long-horizon task guide](docs/long-horizon-tasks.md)",
            "[benchmark methodology](docs/benchmarks.md)",
        ],
    );
    assert_document_contains(
        "SECURITY.md",
        &[
            "owner-default full access",
            "pre-dispatch mediation",
            "untrusted remote requests remain denied",
            "same-user processes",
            "not a complete security sandbox",
        ],
    );
    assert_document_contains(
        "docs/security.md",
        &[
            "accepted risk",
            "pre-dispatch mediation invariant",
            "same-user process",
            "not a complete security sandbox",
        ],
    );
    assert_document_contains(
        "docs/architecture.md",
        &[
            "canonical checkpoint",
            "context compaction",
            "provider context replacement",
            "unresolved `started` operation",
        ],
    );
    assert_document_contains(
        "docs/configuration.md",
        &[
            "`--max-wall-time-seconds`",
            "`--max-provider-requests`",
            "`--max-tool-calls`",
            "`--soft-epoch-seconds`",
            "`--soft-epoch-tool-calls`",
        ],
    );
    assert_document_contains(
        "docs/buzz.md",
        &[
            "`/status`",
            "`/metrics`",
            "`/resume`",
            "`/steer`",
            "`/cancel`",
        ],
    );
    assert_document_contains(
        "docs/long-horizon-tasks.md",
        &[
            "`session/load`",
            "`_task/status`",
            "`_task/metrics`",
            "`_task/resume`",
            "`_session/steering`",
            "`session/cancel`",
            "`latest_checkpoint`",
            "compaction thresholds",
            "provider context replacement",
            "unresolved `started` operation",
        ],
    );
    assert_document_contains(
        "docs/benchmarks.md",
        &[
            "deterministic ten-case repository matrix",
            "100-epoch",
            "sanitized metadata",
            "at least thirty independent paired runs",
            "do not claim superiority",
            "completion rate",
            "interventions",
            "safety violations",
        ],
    );
}

fn validate_fenced_carl_commands(markdown: &str) -> Result<(), String> {
    let mut command = Cli::command();
    let clap_commands: BTreeSet<_> = command
        .get_subcommands()
        .map(|subcommand| subcommand.get_name().to_owned())
        .collect();
    let help = command.render_long_help().to_string();
    let documented_commands = fenced_carl_commands(markdown);

    if documented_commands.is_empty() {
        return Err("README must include at least one fenced carl command".to_owned());
    }

    for documented in documented_commands {
        let arguments: Vec<_> = documented.split_whitespace().collect();
        if arguments.first() != Some(&"carl") {
            return Err(format!(
                "fenced command does not begin with `carl`: `{documented}`"
            ));
        }

        match Cli::try_parse_from(arguments.iter().copied()) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::DisplayHelp => {}
            Err(error) => {
                return Err(format!(
                    "README documents invalid carl invocation `{documented}`: {error}"
                ));
            }
        }

        let documented_top_level = arguments
            .iter()
            .skip(1)
            .find_map(|argument| clap_commands.get(*argument));
        if let Some(name) = documented_top_level
            && !help
                .lines()
                .any(|line| line.split_whitespace().next() == Some(name.as_str()))
        {
            return Err(format!(
                "carl --help does not expose documented command `{name}`"
            ));
        }
    }

    Ok(())
}

#[test]
fn readme_states_the_current_status_and_security_boundaries() {
    assert_document_contains(
        "README.md",
        &[
            "pre-alpha",
            "usable acp coding path",
            "api-key access and consumer subscription access are separate products and billing paths",
            "openai platform api key",
            "xai api key",
            "chatgpt, supergrok, or eligible x subscription",
            "codex cli `0.146.0`",
            "grok build `0.2.111`",
            "carl never installs or updates provider executables",
            "`carl_data_dir`",
            "`carl_codex_executable`",
            "`carl_grok_executable`",
            "`carl_buzz_executable`",
            "`$carl_data_dir/providers/codex`",
            "`$carl_data_dir/providers/grok`",
            "codex owns `$codex_home/auth.json`",
            "explicit `file` mode",
            "never opens or reads the file",
            "grok owns `$grok_home/auth.json`",
            "foreground-only mutations",
            "there is no api-key fallback",
            "undocumented oauth",
            "not a complete security sandbox",
            "native openai responses and openrouter are also supported",
            "carl-owned coding tools",
            "native interactive terminal ui",
            "running `carl` (or the explicit `carl tui` alias)",
            "telegram gateway",
            "`serve`, `acp`, `auth`, `memory`, `maintenance`, and the direct codex baseline have implemented behavior",
            "`pair`, `doctor`, and `sessions` remain inert cli shells",
        ],
    );

    assert!(
        !normalized_document("README.md")
            .contains("`serve`, `pair`, `doctor`, and `sessions` return not-implemented errors"),
        "README must not describe the implemented service as a placeholder"
    );
}

#[test]
fn configuration_documents_the_implemented_auth_boundary() {
    assert_document_contains(
        "docs/configuration.md",
        &[
            "accepts exactly four non-secret carl process variables",
            "`carl_data_dir`",
            "required absolute path to a pre-existing, trusted carl data directory",
            "`carl_codex_executable`",
            "`carl_grok_executable`",
            "`carl_buzz_executable`",
            "`$carl_data_dir/providers/codex`",
            "`$carl_data_dir/providers/grok`",
            "there is no arbitrary provider-home override",
            "codex cli `0.146.0`",
            "grok build `0.2.111`",
            "version matching is compatibility evidence, not publisher attestation",
            "one operating-system-backed exclusive lock",
            "a crashed owner does not leave a stale logical lock",
            "it is not a cross-process lock",
            "api keys have their own provider access and billing",
            "`carl acp` is the implemented subscription-backed execution path",
            "no general profile configuration is accepted today",
        ],
    );
}

#[test]
fn architecture_separates_authentication_from_execution() {
    assert_document_contains(
        "docs/architecture.md",
        &[
            "isolated provider homes",
            "provider-owned authentication brokers",
            "composition for the seven `auth` commands",
            "authentication status performs only provider-owned local handshakes",
            "bounded model and reasoning settings",
            "codex app-server",
            "`carl acp`",
            "subscription-backed coding path",
            "buzz acp frontend",
            "one exclusive os lock per canonical data root",
        ],
    );
}

#[test]
fn memory_docs_state_the_local_curated_boundary_and_controls() {
    assert_document_contains(
        "README.md",
        &[
            "memory is enabled by default",
            "without an embedding model, network call, account, or paid service",
            "capture is explicit rather than ambient",
            "scope-isolated",
            "hard-delete live memory content",
            "live model prompts do not yet consume this memory",
        ],
    );
    assert_document_contains(
        "docs/memory.md",
        &[
            "global, current-workspace, and session-scoped",
            "secret and high-confidence prompt-injection rejection before persistence",
            "disabling is not deletion",
            "stable `semantic_ranker_unavailable` warning",
            "without keeping content-bearing tombstones",
            "exports, backups, filesystem snapshots",
        ],
    );
    assert_document_contains(
        "docs/adr/0005-local-curated-memory.md",
        &[
            "working context",
            "session history",
            "curated semantic memory",
            "curated episodic memory",
            "proposed content is never retrieved before owner approval",
            "at most eight records and 8 kib of rendered memory-source data",
            "exact owner/agent partition",
            "episodes expire after 90 days by default",
            "migration 0006",
            "optional semantic failure",
        ],
    );
}

#[test]
fn security_documents_credential_foreground_and_process_boundaries() {
    assert_document_contains(
        "docs/security.md",
        &[
            "carl never receives, reads, copies, logs, persists, or forwards subscription bearer or refresh tokens",
            "codex owns chatgpt subscription tokens in `$codex_home/auth.json`",
            "explicit `file` mode instead of `auto`",
            "regular, non-linked, owner-only file",
            "logging out through carl removes only carl's isolated codex session",
            "grok owns `$grok_home/auth.json`",
            "it never opens or reads the file",
            "does not suppress trusted root-owned `/etc/grok` policy",
            "grok login and logout additionally require a crate-private foreground capability",
            "a status-only grok broker cannot upgrade itself or mutate authentication",
            "stdout is reserved for one deterministic safe json value",
            "provider-owned terminal output go only to the verified local stderr terminal",
            "version matching is compatibility evidence, not publisher attestation",
            "task 4's provider-home mutex remains in-process only",
            "process groups on unix and job objects on windows",
            "authentication state does not prove current subscription or model entitlement",
            "buzz credentials are never forwarded to codex",
        ],
    );
}

#[test]
fn changelog_records_auth_without_claiming_delegate_execution() {
    assert_document_contains(
        "CHANGELOG.md",
        &[
            "isolated provider sidecar supervision",
            "codex-owned chatgpt subscription authentication",
            "grok-owned supergrok or eligible x subscription authentication",
            "seven `carl auth` status/login/logout commands",
            "deterministic safe json status",
            "inert, library-level subscription-backed codex exec adapter",
            "subscription-backed codex app-server execution through `carl acp`",
        ],
    );
}

#[test]
fn documents_the_inert_external_agent_safety_foundation() {
    assert_document_contains(
        "README.md",
        &[
            "external-agent requests default to exact owner approval",
            "denies writable live-workspace access",
            "actor/session/turn/request-bound",
            "single-use",
            "capability-relative",
            "secret-filtered",
            "the acp path is cli-reachable",
            "stale-safe promotion and run-engine orchestration remain unavailable",
            "independent bounded verification",
        ],
    );
    assert_document_contains(
        "docs/architecture.md",
        &[
            "`policy`: normalized external-agent capability requests",
            "`security`: a non-retaining high-confidence secret filter",
            "`staging`: bounded, capability-relative construction",
            "exact replacement proposal",
            "independent verification",
            "stale-safe promotion",
        ],
    );
    assert_document_contains(
        "docs/security.md",
        &[
            "safe external-agent requests require approval by default",
            "writable live-workspace access",
            "single exact request digest",
            "atomically consumed at most once",
            "high-confidence secret finding rejects the entire stage",
            "every later read reopens the named object",
            "structural changes, protected paths, redirects, hard links",
            "verification reconstructs a new owner-private candidate",
            "promotion is not implemented",
        ],
    );
    assert_document_contains(
        "CHANGELOG.md",
        &[
            "normalized external-agent policy",
            "expiring single-use approvals",
            "non-retaining secret detection",
            "capability-built sanitized staging",
            "content-addressed baseline and proposal artifacts",
            "the acp path is cli-reachable",
        ],
    );
}

#[test]
fn active_product_surfaces_do_not_use_the_retired_brand() {
    let retired_brand = ["arc", "wren"].concat();

    for relative_path in ACTIVE_IDENTITY_SURFACES {
        let path = repository_root().join(relative_path);
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let normalized = contents.to_lowercase();

        assert!(
            !normalized.contains(&retired_brand),
            "active product surface contains retired brand: {}",
            path.display()
        );
    }
}

#[test]
fn readme_points_to_the_carl_design_and_public_contract() {
    let readme = read_readme();
    let carl_design = fs::read_to_string(
        repository_root().join("docs/superpowers/specs/2026-07-23-carl-top-tier-harness-design.md"),
    )
    .expect("Carl design should be readable");

    assert!(readme.contains("[public operating contract](CARL.md)"));
    assert!(readme.contains("docs/superpowers/specs/2026-07-23-carl-top-tier-harness-design.md"));
    assert!(
        carl_design
            .lines()
            .any(|line| line == "Status: approved for implementation")
    );
}

#[test]
fn readme_documents_subscription_tui() {
    let readme = read_readme().to_lowercase();
    for required in [
        "carl tui",
        "carl_data_dir",
        "openai subscription",
        "full access",
        "/sessions",
        "/compact",
        "/resume",
        "/model",
        "/effort",
        "/permissions",
    ] {
        assert!(readme.contains(required), "README missing `{required}`");
    }
    assert!(!readme.contains("tui interaction, the telegram gateway"));
    assert!(!readme.contains("- [ ] interactive local tui"));
}

fn markdown_link_targets(markdown: &str) -> Vec<&str> {
    markdown
        .match_indices("](")
        .filter_map(|(index, _)| {
            let remainder = &markdown[index + 2..];
            let end = remainder.find(')')?;
            Some(&remainder[..end])
        })
        .collect()
}

fn fenced_carl_commands(markdown: &str) -> Vec<&str> {
    let mut in_fence = false;
    let mut commands = Vec::new();

    for line in markdown.lines() {
        let line = line.trim();
        if line.starts_with("```") || line.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            continue;
        }

        let line = line.strip_prefix("$ ").unwrap_or(line);
        if line == "carl" || line.starts_with("carl ") {
            commands.push(line);
        }
    }

    commands
}
