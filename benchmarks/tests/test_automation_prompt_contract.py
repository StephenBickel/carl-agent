from __future__ import annotations

import hashlib
import json
import re
import shlex
import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PORTFOLIO_PATH = REPOSITORY_ROOT / "docs" / "automation-prompts" / "carl-autonomous-improvement.md"
LIVE_MANIFEST_PATH = PORTFOLIO_PATH.with_name("carl-autonomous-improvement-live-manifest.json")
SUPERVISOR_TRIGGER_PATH = (
    "/Users/openclaw/.codex/automations/.shared-private/carl-autonomy-supervisor-triggers.sqlite3"
)
IMPROVEMENT_WORKFLOW_PATH = REPOSITORY_ROOT / ".github/workflows/autonomous-improvement.yml"
SOAK_WORKFLOW_PATH = REPOSITORY_ROOT / ".github/workflows/autonomous-soak.yml"
COORDINATOR_WORKFLOW_PATH = REPOSITORY_ROOT / ".github/workflows/autonomy-coordinator.yml"
ACTIONLINT_CONFIG_PATH = REPOSITORY_ROOT / ".github/actionlint.yaml"


@dataclass(frozen=True)
class PromptSnapshot:
    metadata: dict[str, object]
    prompt: str

    def contains(self, *phrases: str) -> bool:
        normalized = " ".join(self.prompt.lower().split())
        return all(phrase.lower() in normalized for phrase in phrases)

    @property
    def allows_experimental_push_without_protected_validation(self) -> bool:
        return self.contains(
            "push exactly one immutable `experimental/<experiment-id>` branch "
            "without human approval",
            "protected production validation is not required for experimental publication",
        )

    @property
    def requires_implementation_and_retest(self) -> bool:
        return self.contains(
            "write a failing test",
            "implement the smallest general product change",
            "retest the exact candidate",
        )

    @property
    def allows_pr_and_auto_merge_without_human_approval(self) -> bool:
        return self.contains(
            "open or reconcile the protected pull request to `main`",
            "enable auto-merge without human approval",
        )

    @property
    def forbids_idle_narrative(self) -> bool:
        return self.contains(
            "when no consequential state is active and health is green, emit only `idle: healthy`",
            "do not write an idle narrative",
        )

    @property
    def requires_changed_recovery_action(self) -> bool:
        return self.contains(
            "every recovery attempt must record a materially changed action",
            "a repeated diagnosis without a changed action is a failed supervisor run",
        )

    @property
    def critical_after_two_zero_candidate_cycles(self) -> bool:
        return self.contains(
            "critical after two consecutive completed builder cycles with zero "
            "experimental candidates",
        )


@dataclass(frozen=True)
class WorkflowStep:
    job: str
    name: str
    identifier: str | None
    environment: dict[str, str]
    run: str


def _parse_workflow_steps(document: str) -> list[WorkflowStep]:
    """Parse the jobs/steps YAML structure used by the two protected workflows."""
    steps: list[WorkflowStep] = []
    lines = document.splitlines()
    in_jobs = False
    job = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        if line == "jobs:":
            in_jobs = True
            index += 1
            continue
        if not in_jobs:
            index += 1
            continue
        job_match = re.fullmatch(r"  ([a-z][a-z0-9_-]*):", line)
        if job_match:
            job = job_match.group(1)
            index += 1
            continue
        name_match = re.fullmatch(r"      - name: (.+)", line)
        if not name_match:
            index += 1
            continue
        name = name_match.group(1)
        identifier: str | None = None
        environment: dict[str, str] = {}
        run = ""
        index += 1
        while index < len(lines) and not re.fullmatch(r"      - name: .+", lines[index]):
            if re.fullmatch(r"  [a-z][a-z0-9_-]*:", lines[index]):
                break
            identifier_match = re.fullmatch(r"        id: ([a-zA-Z0-9_-]+)", lines[index])
            if identifier_match:
                identifier = identifier_match.group(1)
            if lines[index] == "        env:":
                index += 1
                while index < len(lines):
                    env_match = re.fullmatch(r"          ([A-Z][A-Z0-9_]*): (.+)", lines[index])
                    if env_match is None:
                        break
                    environment[env_match.group(1)] = env_match.group(2)
                    index += 1
                continue
            if lines[index] == "        run: |":
                block: list[str] = []
                index += 1
                while index < len(lines) and (
                    not lines[index].strip() or lines[index].startswith("          ")
                ):
                    block.append(lines[index][10:] if lines[index] else "")
                    index += 1
                run = "\n".join(block)
                continue
            index += 1
        steps.append(WorkflowStep(job, name, identifier, environment, run))
    return steps


def _assert_immutable_consumer_contract(document: str, *, mode: str) -> None:
    specs = {
        "improvement": (
            "pair",
            "Run the protected-parent harness against both exact binaries",
            "python -m carl_bench.cloud_harness",
            "application/vnd.carl.improvement-task-set+json",
        ),
        "soak": (
            "health",
            "Run repository health probes without workflow commands or credentials",
            "python -m carl_bench.immutable_inputs soak-health",
            "application/vnd.carl.soak-task-set+tar",
        ),
    }
    consumer_id, consumer_name, command, task_media_type = specs[mode]
    steps = _parse_workflow_steps(document)
    matches = [
        step
        for step in steps
        if step.identifier == consumer_id and step.name == consumer_name and command in step.run
    ]
    assert len(matches) == 1, (mode, consumer_id)
    consumer = matches[0]
    consumer_tokens = [token for token in shlex.split(consumer.run, posix=True) if token != "\n"]
    command_tokens = {
        "improvement": ("-m", "carl_bench.cloud_harness"),
        "soak": ("-m", "carl_bench.immutable_inputs", "soak-health"),
    }[mode]
    command_starts = [
        index
        for index in range(len(consumer_tokens) - len(command_tokens) + 1)
        if tuple(consumer_tokens[index : index + len(command_tokens)]) == command_tokens
    ]
    assert len(command_starts) == 1, (mode, "consumer command")
    consumer_index = steps.index(consumer)
    resolvers = [
        step
        for step in steps[:consumer_index]
        if step.job == consumer.job
        and "python -m carl_bench.immutable_inputs resolve-set" in step.run
    ]
    assert len(resolvers) == 1, (mode, consumer.job, "preceding resolver")
    resolver = resolvers[0]
    assert resolver.identifier == "immutable_inputs", (mode, consumer.job)
    assert f"--mode {mode}" in resolver.run
    assert f"--task-media-type {task_media_type}" in resolver.run
    assert "--registry trusted-source/benchmarks/immutable-inputs/registry.json" in resolver.run
    assert "--root trusted-source/benchmarks/immutable-inputs" in resolver.run
    assert set(re.findall(r"--([a-z-]+)-digest\b", resolver.run)) == {
        "experiment",
        "task-set",
        "metric-pack",
        "policy",
    }

    required = {
        "EXPERIMENT_INPUT": ("experiment", "experiment-digest"),
        "TASK_SET_INPUT": ("task-set", "task-set-digest"),
        "METRIC_PACK_INPUT": ("metric-pack", "metric-pack-digest"),
        "POLICY_INPUT": ("policy", "policy-digest"),
    }
    expected_environment = {
        variable: f"${{{{ steps.{resolver.identifier}.outputs.{kind.replace('-', '_')} }}}}"
        for variable, (kind, _) in required.items()
    }
    assert {
        name: value for name, value in consumer.environment.items() if name.endswith("_INPUT")
    } == expected_environment
    for variable, (kind, digest_argument) in required.items():
        digest_variable = kind.replace("-", "_").upper() + "_DIGEST"
        output_name = kind.replace("-", "_")
        assert f'--{digest_argument} "${digest_variable}"' in resolver.run
        assert f'{output_name}=%s\\n\' "$resolved/{kind}"' in resolver.run
        assert consumer.environment.get(variable) == (
            f"${{{{ steps.{resolver.identifier}.outputs.{output_name} }}}}"
        )
        option = f"--{kind}"
        option_indices = [index for index, token in enumerate(consumer_tokens) if token == option]
        assert len(option_indices) == 1, (mode, option)
        assert consumer_tokens[option_indices[0] + 1] == f"${variable}", (mode, option)

    expected_variable_uses = {variable: 1 for variable in required}
    if mode == "soak":
        expected_variable_uses["TASK_SET_INPUT"] = 2
    for variable, expected_uses in expected_variable_uses.items():
        assert consumer_tokens.count(f"${variable}") == expected_uses, (mode, variable)

    assert not any(name.endswith("_DIGEST") for name in consumer.environment)
    assert " resolve-set " not in consumer.run
    assert "trusted-source/benchmarks/immutable-inputs" not in consumer.run
    assert "$RUNNER_TEMP/immutable-inputs" not in consumer.run
    assert not re.search(r"(?:public|private)/[^\s]*", consumer.run)
    assert not re.search(r"[^\s]*(?:DIGEST|digest)[^\s]*/", consumer.run)


def _remove_named_step(document: str, name: str) -> str:
    lines = document.splitlines(keepends=True)
    start = next(index for index, line in enumerate(lines) if line == f"      - name: {name}\n")
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("      - name:")
        ),
        len(lines),
    )
    return "".join((*lines[:start], *lines[end:]))


def _load_portfolio() -> dict[str, PromptSnapshot]:
    document = PORTFOLIO_PATH.read_text(encoding="utf-8")
    sections = re.split(r"(?m)^## Automation: ", document)[1:]
    snapshots: dict[str, PromptSnapshot] = {}

    for section in sections:
        heading, body = section.split("\n", 1)
        metadata_match = re.search(r"```toml automation\n(?P<value>.*?)\n```", body, re.DOTALL)
        prompt_match = re.search(r"```text prompt\n(?P<value>.*?)\n```", body, re.DOTALL)
        assert metadata_match is not None, f"missing automation metadata for {heading}"
        assert prompt_match is not None, f"missing canonical prompt for {heading}"

        metadata = tomllib.loads(metadata_match.group("value"))
        automation_id = str(metadata["id"])
        assert automation_id not in snapshots, f"duplicate automation id {automation_id}"
        snapshots[automation_id] = PromptSnapshot(
            metadata=metadata,
            prompt=prompt_match.group("value").strip(),
        )

    return snapshots


def test_portfolio_defines_the_six_nonoverlapping_automation_roles() -> None:
    portfolio = _load_portfolio()

    assert set(portfolio) == {
        "daily-carl-self-improvement-graph",
        "daily-carl-production-review",
        "carl-promotion-and-rollback-watchdog",
        "daily-carl-autonomy-outcome-monitor",
        "carl-autonomy-loop-supervisor",
        "weekly-carl-feature-and-autonomy-report",
    }

    for ownership_key, expected_owner in {
        "mutation_owner": "daily-carl-self-improvement-graph",
        "disposition_owner": "daily-carl-production-review",
        "promotion_owner": "daily-carl-production-review",
    }.items():
        owners = {
            automation_id
            for automation_id, snapshot in portfolio.items()
            if snapshot.metadata.get(ownership_key) is True
        }
        assert owners == {expected_owner}


def test_builder_implements_retests_and_can_publish_experimental_work() -> None:
    builder = _load_portfolio()["daily-carl-self-improvement-graph"]

    assert builder.allows_experimental_push_without_protected_validation
    assert builder.requires_implementation_and_retest
    assert builder.contains(
        "retry or rework a nonterminal failure instead of ending with a report-only failure",
        "held-out or adversarial transfer check",
        "benchmark-only score gains are not capability evidence",
    )


def test_promoter_owns_independent_disposition_and_protected_auto_merge() -> None:
    promoter = _load_portfolio()["daily-carl-production-review"]

    assert promoter.allows_pr_and_auto_merge_without_human_approval
    assert promoter.contains(
        "assign exactly one independent disposition",
        "retry or rework a repairable failure",
        "required checks and branch protection",
    )


def test_watchdog_is_compact_when_idle_and_recovers_active_work() -> None:
    watchdog = _load_portfolio()["carl-promotion-and-rollback-watchdog"]

    assert watchdog.forbids_idle_narrative
    assert watchdog.contains(
        "reconcile active experiments, reviews, promotions, soaks, reverts, leases, and retries",
        "three materially different recovery attempts",
    )
    assert watchdog.contains(
        "commissioning and live acp gates apply only to forward evidence acceptance, "
        "disposition, and promotion",
        "never block rollback or exact revert reconciliation",
        "hard production rollback remains bounded to two hours",
    )


def test_supervisor_changes_recovery_action_and_noops_only_when_healthy() -> None:
    supervisor = _load_portfolio()["carl-autonomy-loop-supervisor"]

    assert supervisor.requires_changed_recovery_action
    assert supervisor.contains(
        "no-op only when commissioning is complete, no critical condition exists, "
        "and the loop is advancing",
        "redispatch the exact next safe node",
    )


def test_recovery_roles_share_one_durable_supervisor_trigger_contract() -> None:
    portfolio = _load_portfolio()

    for automation_id in {
        "carl-promotion-and-rollback-watchdog",
        "daily-carl-autonomy-outcome-monitor",
        "carl-autonomy-loop-supervisor",
    }:
        snapshot = portfolio[automation_id]
        assert SUPERVISOR_TRIGGER_PATH in snapshot.prompt, automation_id
        assert snapshot.contains(
            "supervisortrigger v1",
            "trigger_id",
            "exact evidence_digest",
            "unsafe_boundary",
            "attempt_history",
            "next_safe_node_key",
            "created_at",
            "next supervisor inspection occurs within six hours",
            "hard production rollback remains bounded to two hours",
        ), automation_id

    watchdog = portfolio["carl-promotion-and-rollback-watchdog"]
    monitor = portfolio["daily-carl-autonomy-outcome-monitor"]
    supervisor = portfolio["carl-autonomy-loop-supervisor"]
    assert watchdog.contains("append the trigger idempotently")
    assert monitor.contains("append the trigger idempotently")
    assert supervisor.contains(
        "enumerate unresolved triggers oldest-first",
        "atomically claim the trigger",
        "record one materially changed recovery action",
        "atomically resolve it as `resolved` or `rejected`",
        "exact recovery action, evidence digest, result digest, and resolved_at",
    )


def test_outcome_monitor_escalates_zero_candidate_throughput() -> None:
    outcome_monitor = _load_portfolio()["daily-carl-autonomy-outcome-monitor"]

    assert outcome_monitor.critical_after_two_zero_candidate_cycles
    assert outcome_monitor.contains(
        "watchdog run count is not throughput",
        "report-only runs",
        "retained learning",
    )


def test_schedules_models_and_reasoning_are_exact() -> None:
    portfolio = _load_portfolio()
    expected = {
        "daily-carl-self-improvement-graph": (
            "RRULE:FREQ=DAILY;BYHOUR=0;BYMINUTE=0",
            "gpt-5.6-sol",
            "high",
        ),
        "daily-carl-production-review": (
            "RRULE:FREQ=HOURLY;INTERVAL=6;BYMINUTE=15",
            "gpt-5.6-sol",
            "high",
        ),
        "carl-promotion-and-rollback-watchdog": (
            "RRULE:FREQ=HOURLY;INTERVAL=2;BYMINUTE=30",
            "gpt-5.6-luna",
            "medium",
        ),
        "daily-carl-autonomy-outcome-monitor": (
            "RRULE:FREQ=DAILY;BYHOUR=8;BYMINUTE=0",
            "gpt-5.6-luna",
            "medium",
        ),
        "carl-autonomy-loop-supervisor": (
            "RRULE:FREQ=HOURLY;INTERVAL=6;BYMINUTE=45",
            "gpt-5.6-sol",
            "ultra",
        ),
        "weekly-carl-feature-and-autonomy-report": (
            "RRULE:FREQ=WEEKLY;BYDAY=MO;BYHOUR=9;BYMINUTE=0",
            "gpt-5.6-terra",
            "medium",
        ),
    }

    assert {
        automation_id: (
            snapshot.metadata["rrule"],
            snapshot.metadata["model"],
            snapshot.metadata["reasoning_effort"],
        )
        for automation_id, snapshot in portfolio.items()
    } == expected


def test_every_automation_is_a_thin_fail_closed_local_controller() -> None:
    portfolio = _load_portfolio()

    for automation_id, snapshot in portfolio.items():
        assert snapshot.metadata["execution_environment"] == "local", automation_id
        assert snapshot.metadata["controller_mode"] == "thin_local", automation_id
        assert snapshot.metadata["heavy_execution"] == "github_hosted", automation_id
        assert snapshot.metadata["local_heavy_fallback"] is False, automation_id
        assert snapshot.contains(
            "never silently fall back to heavy local execution",
            "fail closed if either a trusted signed commissioning receipt or live acp "
            "capability evidence is missing",
        ), automation_id


def test_only_operational_roles_may_dispatch_heavy_workflows() -> None:
    portfolio = _load_portfolio()
    dispatch_phrase = (
        "dispatch heavy builds, tests, evaluations, and soak probes to github-hosted workflows"
    )

    for automation_id in {
        "daily-carl-self-improvement-graph",
        "daily-carl-production-review",
        "carl-promotion-and-rollback-watchdog",
        "carl-autonomy-loop-supervisor",
    }:
        assert portfolio[automation_id].contains(dispatch_phrase), automation_id

    for automation_id in {
        "daily-carl-autonomy-outcome-monitor",
        "weekly-carl-feature-and-autonomy-report",
    }:
        observer = portfolio[automation_id]
        assert not observer.contains(dispatch_phrase), automation_id
        assert observer.contains(
            "do not dispatch heavy workflows",
            "reconcile already-produced signed evidence",
            "append",
            "supervisortrigger v1",
            "trigger_id",
            "exact evidence_digest",
            "unsafe_boundary",
            "attempt_history",
            "next_safe_node_key",
            "created_at",
        ), automation_id


def test_no_automation_has_forbidden_production_authority() -> None:
    portfolio = _load_portfolio()

    for automation_id, snapshot in portfolio.items():
        assert snapshot.metadata["direct_main_push"] is False, automation_id
        assert snapshot.metadata["force_push"] is False, automation_id
        assert snapshot.metadata["deploy"] is False, automation_id
        assert snapshot.metadata["release"] is False, automation_id
        assert snapshot.contains(
            "never directly push `main`, force-push, deploy, or release",
        ), automation_id


def test_sanitized_live_manifest_matches_the_complete_canonical_portfolio() -> None:
    portfolio = _load_portfolio()
    manifest = json.loads(LIVE_MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 1
    assert manifest["source"] == "sanitized_live_definition_export"
    entries = {entry["id"]: entry for entry in manifest["automations"]}
    assert len(manifest["automations"]) == 6
    assert set(entries) == set(portfolio)

    for automation_id, snapshot in portfolio.items():
        entry = entries[automation_id]
        assert entry["status"] == "ACTIVE"
        assert entry["configuration"] == snapshot.metadata
        assert entry["prompt_sha256"] == hashlib.sha256(snapshot.prompt.encode("utf-8")).hexdigest()


def test_scheduled_cloud_coordinator_is_single_node_default_branch_only_and_state_scoped() -> None:
    document = COORDINATOR_WORKFLOW_PATH.read_text(encoding="utf-8")
    manifest = json.loads(LIVE_MANIFEST_PATH.read_text(encoding="utf-8"))

    assert 'cron: "0 */2 * * *"' in document
    assert "workflow_dispatch:" in document
    assert (
        "if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
        in document
    )
    assert (
        "group: carl-autonomy-coordinator-${{ github.event.repository.default_branch }}" in document
    )
    assert "cancel-in-progress: false" in document
    assert "permissions:\n  contents: read" in document

    jobs = _workflow_job_blocks(document)
    assert set(jobs) == {"coordinate"}
    coordinate = jobs["coordinate"]
    assert _job_environment(coordinate) == "carl-autonomy-coordinator"
    assert _job_permissions(coordinate) == {"contents": "read", "id-token": "write"}
    assert "runs-on: [self-hosted, linux, x64, carl-autonomy-cloud]" in coordinate
    assert "timeout-minutes: 10" in coordinate
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in coordinate
    assert "astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990" in coordinate
    assert "persist-credentials: false" in coordinate
    assert "ref: ${{ github.sha }}" in coordinate
    assert coordinate.count("carl-bench cloud coordinate") == 1
    assert "uv run --offline --project benchmarks --locked python - <<'PY'" in coordinate
    assert 'MAX_COORDINATOR_RESULT_BYTES: "1048576"' in coordinate
    assert "canonical_json_bytes" in coordinate
    assert coordinate.count("printf '%s\\n' \"$RESULT\"") == 1

    forbidden = (
        "actions/upload-artifact@",
        "actions/download-artifact@",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "secrets.",
        "candidate",
        "publisher",
        "promoter",
        "subject",
        "model",
    )
    assert not any(value in document for value in forbidden)
    assert manifest["cloud_workflows"] == [
        {
            "configuration": {
                "default_branch_only": True,
                "durable_state": "postgresql_and_protected_object_storage",
                "identity": "coordinator",
                "maximum_consequential_nodes_per_run": 1,
                "no_idle_narrative_ledger_event": True,
                "oidc_state_role_only": True,
                "runner_label": "carl-autonomy-cloud",
                "schedule": "0 */2 * * *",
                "workflow_dispatch": True,
            },
            "id": "autonomy-coordinator",
            "status": "PENDING_COMMISSIONING",
            "workflow_path": ".github/workflows/autonomy-coordinator.yml",
        }
    ]
    assert ACTIONLINT_CONFIG_PATH.read_text(encoding="utf-8") == (
        "self-hosted-runner:\n  labels:\n    - carl-autonomy-cloud\n"
    )


def test_autonomous_workflows_resolve_inputs_only_through_the_versioned_registry() -> None:
    improvement = IMPROVEMENT_WORKFLOW_PATH.read_text(encoding="utf-8")
    soak = SOAK_WORKFLOW_PATH.read_text(encoding="utf-8")
    _assert_immutable_consumer_contract(improvement, mode="improvement")
    _assert_immutable_consumer_contract(soak, mode="soak")
    for workflow in (improvement, soak):
        assert not re.search(r"benchmarks/immutable-inputs/(?:public|private)/", workflow)
        assert "private/sha256" not in workflow
        assert "set -x" not in workflow
    assert "application/vnd.carl.improvement-task-set+json" in improvement
    assert "application/vnd.carl.soak-task-set+tar" in soak
    for check_variable in ("benchmark_smoke", "python_contracts", "rust_contracts"):
        assert f"{check_variable}=false" in soak
        assert f"{check_variable}=true" in soak


def test_workflow_contract_rejects_consumer_path_or_resolver_bypass_mutations() -> None:
    improvement = IMPROVEMENT_WORKFLOW_PATH.read_text(encoding="utf-8")
    soak = SOAK_WORKFLOW_PATH.read_text(encoding="utf-8")

    changed_output = improvement.replace(
        "${{ steps.immutable_inputs.outputs.policy }}",
        "${{ steps.untrusted.outputs.policy }}",
        1,
    )
    assert changed_output != improvement
    with pytest.raises(AssertionError):
        _assert_immutable_consumer_contract(changed_output, mode="improvement")

    direct_path = soak.replace('"$POLICY_INPUT"', '"$RUNNER_TEMP/other/policy"', 1)
    assert direct_path != soak
    with pytest.raises(AssertionError):
        _assert_immutable_consumer_contract(direct_path, mode="soak")

    without_resolver = _remove_named_step(soak, "Verify immutable inputs outside subject authority")
    with pytest.raises(AssertionError):
        _assert_immutable_consumer_contract(without_resolver, mode="soak")


def test_workflow_contract_binds_each_consumer_option_to_its_resolved_output() -> None:
    improvement = IMPROVEMENT_WORKFLOW_PATH.read_text(encoding="utf-8")
    soak = SOAK_WORKFLOW_PATH.read_text(encoding="utf-8")

    alternate_with_noop = improvement.replace(
        '--policy "$POLICY_INPUT" \\\n',
        '--policy /tmp/alternate \\\n              "$POLICY_INPUT" \\\n',
        1,
    )
    assert alternate_with_noop != improvement
    with pytest.raises(AssertionError):
        _assert_immutable_consumer_contract(alternate_with_noop, mode="improvement")

    aliased_output = soak.replace(
        "POLICY_INPUT: ${{ steps.immutable_inputs.outputs.policy }}",
        "POLICY_INPUT: ${{ steps.immutable_inputs.outputs.metric_pack }}",
        1,
    )
    assert aliased_output != soak
    with pytest.raises(AssertionError):
        _assert_immutable_consumer_contract(aliased_output, mode="soak")

    duplicate_option = soak.replace(
        '--policy "$POLICY_INPUT" \\\n',
        '--policy "$POLICY_INPUT" --policy "$POLICY_INPUT" \\\n',
        1,
    )
    assert duplicate_option != soak
    with pytest.raises(AssertionError):
        _assert_immutable_consumer_contract(duplicate_option, mode="soak")


def _workflow_job_blocks(document: str) -> dict[str, str]:
    jobs = document.split("\njobs:\n", 1)[1]
    matches = list(re.finditer(r"(?m)^  ([a-z][a-z0-9_-]*):\n", jobs))
    return {
        match.group(1): jobs[match.start() : matches[index + 1].start()]
        if index + 1 < len(matches)
        else jobs[match.start() :]
        for index, match in enumerate(matches)
    }


def _job_environment(block: str) -> str:
    match = re.search(r"(?m)^    environment: ([a-z0-9-]+)$", block)
    assert match is not None
    return match.group(1)


def _job_permissions(block: str) -> dict[str, str]:
    match = re.search(r"(?m)^    permissions:\n(?P<body>(?:      [a-z-]+: [a-z]+\n)+)", block)
    assert match is not None
    return dict(re.findall(r"(?m)^      ([a-z-]+): ([a-z]+)$", match.group("body")))


def _assert_soak_health_probes_use_protected_revision(document: str) -> None:
    steps = _parse_workflow_steps(document)
    health_steps = [
        step for step in steps if step.job == "evaluate" and step.identifier == "health"
    ]
    assert len(health_steps) == 1
    health = health_steps[0].run

    assert 'rust_probe_root="$RUNNER_TEMP/rust-probe"' in health
    assert 'python_probe_root="$RUNNER_TEMP/python-probe"' in health
    assert 'trusted_benchmark_root="$RUNNER_TEMP/trusted-benchmark-probe"' in health
    assert 'rm -rf -- "$rust_probe_root/.cargo" "$rust_probe_root/tests"' in health
    assert 'rm -f -- "$rust_probe_root/build.rs"' in health
    assert 'cp -- trusted-source/Cargo.toml trusted-source/Cargo.lock "$rust_probe_root/"' in health
    assert 'cp -R -- trusted-source/tests "$rust_probe_root/tests"' in health
    assert 'cp -R -- trusted-source/benchmarks "$python_probe_root"' in health
    assert (
        'cp -R -- subject-merge/benchmarks/src/carl_bench "$python_probe_root/src/carl_bench"'
    ) in health
    assert 'cp -R -- trusted-source/benchmarks "$trusted_benchmark_root"' in health
    assert 'cd "$RUST_PROBE_ROOT"; cargo +1.97.0 test --locked' in health
    assert 'uv sync --project "$PYTHON_PROBE_ROOT" --python 3.12 --locked' in health
    assert '--confcutdir "$PYTHON_PROBE_ROOT/tests"' in health
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1" in health
    assert health.count('PYTHONPATH="$TRUSTED_BENCHMARK_ROOT/src"') == 3

    assert 'cd "$SUBJECT_ROOT"; cargo +1.97.0 test' not in health
    assert "uv sync --project benchmarks" not in health
    assert "./scripts/benchmark-smoke.sh" not in health


def test_soak_health_probes_use_only_protected_revision_targets_and_hooks() -> None:
    _assert_soak_health_probes_use_protected_revision(
        SOAK_WORKFLOW_PATH.read_text(encoding="utf-8")
    )


def test_soak_health_probe_contract_rejects_candidate_controlled_hook_mutations() -> None:
    soak = SOAK_WORKFLOW_PATH.read_text(encoding="utf-8")
    mutations = {
        "candidate Rust manifest": soak.replace(
            'cp -- trusted-source/Cargo.toml trusted-source/Cargo.lock "$rust_probe_root/"',
            ": # keep candidate Cargo manifest",
            1,
        ),
        "candidate Rust targets": soak.replace(
            'cp -R -- trusted-source/tests "$rust_probe_root/tests"',
            ": # keep candidate Rust targets",
            1,
        ),
        "candidate Cargo hooks": soak.replace(
            'rm -rf -- "$rust_probe_root/.cargo" "$rust_probe_root/tests"',
            'rm -rf -- "$rust_probe_root/tests"',
            1,
        ),
        "candidate pytest project": soak.replace(
            'uv sync --project "$PYTHON_PROBE_ROOT" --python 3.12 --locked',
            "uv sync --project benchmarks --python 3.12 --locked",
            1,
        ),
        "candidate pytest hooks": soak.replace(
            '--confcutdir "$PYTHON_PROBE_ROOT/tests"',
            '--rootdir "$SUBJECT_ROOT"',
            1,
        ),
        "candidate benchmark runner": soak.replace(
            'PYTHONPATH="$TRUSTED_BENCHMARK_ROOT/src"',
            'PYTHONPATH="$SUBJECT_ROOT/benchmarks/src"',
            1,
        ),
    }
    for mutation, mutated in mutations.items():
        assert mutated != soak, mutation
        with pytest.raises(AssertionError):
            _assert_soak_health_probes_use_protected_revision(mutated)


def _assert_complete_signed_soak_chain(document: str) -> None:
    jobs = _workflow_job_blocks(document)
    live_soak = jobs["live_soak"]
    evidence = jobs["evidence"]

    for block in (live_soak, evidence):
        assert "carl.soak-observation.chain-receipt.v2" in block
        assert '"observation_chain"' in block
        assert '"previous_receipt_digest"' in block
        assert "EXPECTED_CHAIN_LENGTH = 5" in block
        assert "CADENCE_MIN = timedelta(hours=6)" in block
        assert "CADENCE_MAX = timedelta(hours=6, minutes=30)" in block
        assert "SOAK_MAX = timedelta(hours=26)" in block
        assert "validate_observation_chain" in block
        assert 'item["sequence"] != index' in block
        assert 'item["active_merge_commit"] != payload["active_merge_commit"]' in block
        assert 'item["previous_observation_digest"] != previous_digest' in block
        assert "observation_digest in seen_digests" in block
        assert "interval < CADENCE_MIN or interval > CADENCE_MAX" in block
        assert 'chain[0]["observed_at"] != payload["merged_at"]' in block

    assert "now > merged_at + SOAK_MAX" in live_soak
    assert 'payload["previous_receipt_digest"] != context["previous_receipt_digest"]' in live_soak
    assert 'current_chain[:-1] != context["previous_observation_chain"]' in live_soak
    assert 'len(current_chain) != len(context["previous_observation_chain"]) + 1' in live_soak
    assert "accept_ready = len(current_chain) == EXPECTED_CHAIN_LENGTH" in live_soak
    assert "accept_ready = observed_at >= merged_at + timedelta(hours=24)" not in live_soak
    assert 'payload["observation_chain"][-1]["observed_at"]' in evidence
    assert 'os.environ["ACCEPT_READY"] != str(chain_complete).lower()' in evidence


def test_soak_acceptance_requires_complete_exact_six_hour_signed_chain() -> None:
    _assert_complete_signed_soak_chain(SOAK_WORKFLOW_PATH.read_text(encoding="utf-8"))


def test_soak_chain_contract_rejects_gap_replay_and_rebinding_mutations() -> None:
    soak = SOAK_WORKFLOW_PATH.read_text(encoding="utf-8")
    mutations = {
        "24-hour cadence gap": soak.replace(
            "CADENCE_MAX = timedelta(hours=6, minutes=30)",
            "CADENCE_MAX = timedelta(hours=26)",
        ),
        "receipt replay": soak.replace(
            'payload["previous_receipt_digest"] != context["previous_receipt_digest"]',
            "False",
            1,
        ),
        "chain prefix splice": soak.replace(
            'current_chain[:-1] != context["previous_observation_chain"]',
            "False",
            1,
        ),
        "duplicate observation": soak.replace(
            "observation_digest in seen_digests",
            "False",
        ),
        "merge rebinding": soak.replace(
            'item["active_merge_commit"] != payload["active_merge_commit"]',
            "False",
        ),
        "stale acceptance": soak.replace(
            "now > merged_at + SOAK_MAX",
            "False",
        ),
    }
    for mutation, mutated in mutations.items():
        assert mutated != soak, mutation
        with pytest.raises(AssertionError):
            _assert_complete_signed_soak_chain(mutated)


def test_protected_workflows_separate_cloud_authorities_and_close_permissions() -> None:
    improvement = _workflow_job_blocks(IMPROVEMENT_WORKFLOW_PATH.read_text(encoding="utf-8"))
    soak = _workflow_job_blocks(SOAK_WORKFLOW_PATH.read_text(encoding="utf-8"))

    expected_improvement = {
        "commission": ("carl-autonomy-builder", {"contents": "read"}),
        "evaluate": ("carl-autonomy-subject", {"contents": "read"}),
        "publish_private_inputs": (
            "carl-autonomy-validator",
            {"contents": "read", "id-token": "write"},
        ),
        "live_validation": (
            "carl-autonomy-validator",
            {"contents": "read", "id-token": "write"},
        ),
        "evidence": (
            "carl-autonomy-observer",
            {"actions": "read", "contents": "read", "id-token": "write"},
        ),
        "promotion_handoff": (
            "carl-autonomy-promoter",
            {"actions": "read", "contents": "read"},
        ),
    }
    expected_soak = {
        "commission": ("carl-autonomy-soak", {"contents": "read"}),
        "evaluate": ("carl-autonomy-subject", {"contents": "read"}),
        "live_soak": (
            "carl-autonomy-soak",
            {"contents": "read", "id-token": "write"},
        ),
        "evidence": (
            "carl-autonomy-observer",
            {"actions": "read", "contents": "read", "id-token": "write"},
        ),
        "rollback_handoff": ("carl-autonomy-promoter", {"contents": "read"}),
    }
    for jobs, expected in ((improvement, expected_improvement), (soak, expected_soak)):
        assert set(jobs) == set(expected)
        for job, (environment, permissions) in expected.items():
            assert _job_environment(jobs[job]) == environment
            assert _job_permissions(jobs[job]) == permissions
        oidc_jobs = {job for job, block in jobs.items() if "id-token: write" in block}
        assert oidc_jobs == {
            job for job, (_, permissions) in expected.items() if "id-token" in permissions
        }


def test_improvement_workflow_uses_protected_live_observe_archive_ingest_chain() -> None:
    document = IMPROVEMENT_WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs = _workflow_job_blocks(document)

    assert 'publish-input "$PROTECTED_NODE" register_hypothesis' in jobs["publish_private_inputs"]
    assert 'commission-live "$PROTECTED_NODE" observe_validation' in jobs["live_validation"]
    handoff = jobs["evidence"]
    for node in (
        "observe_validation",
        "archive_validation",
        "ingest_validation",
        "record_disposition",
    ):
        assert f"PROTECTED_NODE={node}" in handoff
    assert handoff.count("run_node observe ") == 2
    assert handoff.count("run_node ingest ") == 2
    assert 'coordinate "$PROTECTED_NODE" observe_required_checks' in jobs["promotion_handoff"]
    assert "GITHUB_TOKEN" not in jobs["promotion_handoff"]
    assert "live_acp_credential_missing" not in document
    assert 'get("eligible") is not False' not in document
    assert "PAIRED_RESULT_PAYLOAD_B64" not in document
    assert "OPENAI_API_KEY" not in jobs["evaluate"]
    assert "secrets." not in jobs["evaluate"]
    assert "id-token: write" not in jobs["evaluate"]


def test_soak_workflow_is_six_hour_exact_merge_bound_and_protected() -> None:
    document = SOAK_WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs = _workflow_job_blocks(document)

    assert 'SOAK_CADENCE_HOURS: "6"' in document
    assert 'test "$SOAK_CADENCE_HOURS" = "6"' in jobs["commission"]
    assert "rev-list --parents -n 1" in jobs["commission"]
    assert 'test "${MERGE_TOPOLOGY[1]}" = "$PARENT_COMMIT"' in jobs["commission"]
    assert "commission-live observe_soak accept_soak" in jobs["live_soak"]
    handoff = jobs["evidence"]
    assert "PROTECTED_NODE=accept_soak" in handoff
    assert "archive sign and ingest" in handoff
    assert 'health "$PROTECTED_NODE" supervisor_reconciled' in jobs["rollback_handoff"]
    assert "GITHUB_TOKEN" not in jobs["rollback_handoff"]
    assert "github.sha" not in jobs["live_soak"]
    assert "inputs.candidate_commit" in jobs["live_soak"]


def test_each_protected_workflow_uses_bounded_private_objects_and_public_receipts() -> None:
    for path, outcome_prefix, receipt_prefix, upload_count, download_count in (
        (
            IMPROVEMENT_WORKFLOW_PATH,
            "protected-improvement-outcome",
            "autonomous-improvement-evidence",
            2,
            2,
        ),
        (
            SOAK_WORKFLOW_PATH,
            "protected-soak-health",
            "autonomous-soak-observation",
            3,
            2,
        ),
    ):
        document = path.read_text(encoding="utf-8")
        assert document.count("actions/upload-artifact@") == upload_count
        assert document.count("actions/download-artifact@") == download_count
        assert f"name: {outcome_prefix}-${{{{ inputs.request_digest }}}}" in document
        assert f"name: {receipt_prefix}-${{{{ inputs.request_digest }}}}" in document
        assert "retention-days: 1" in document
        assert "MAX_PUBLIC_HANDOFF_BYTES: 1048576" in document
        assert '"provider"' not in document
        assert '"model"' not in document
        assert "secret" not in "\n".join(
            line.lower() for line in document.splitlines() if "cloud-handoff" in line
        )


def test_evaluator_outputs_cross_only_the_protected_object_and_receipt_chain() -> None:
    improvement = _workflow_job_blocks(IMPROVEMENT_WORKFLOW_PATH.read_text(encoding="utf-8"))
    soak = _workflow_job_blocks(SOAK_WORKFLOW_PATH.read_text(encoding="utf-8"))

    improvement_evaluate = improvement["evaluate"]
    improvement_evidence = improvement["evidence"]
    promotion = improvement["promotion_handoff"]
    assert "paired-result.json" in improvement_evaluate
    assert "protected-improvement-outcome-${{ inputs.request_digest }}" in improvement_evaluate
    assert "paired_result_digest" in improvement_evaluate
    assert "actions/upload-artifact@" in improvement_evaluate
    assert "actions/download-artifact@" in improvement_evidence
    assert "EXPECTED_OUTCOME_DIGEST: ${{ needs.evaluate.outputs.paired_result_digest }}" in (
        improvement_evidence
    )
    assert 'value["contract_eligible"] is not True' in improvement_evidence
    assert 'value["candidate"]["commit"] != os.environ["CANDIDATE_COMMIT"]' in (
        improvement_evidence
    )
    assert "protected_receipt_digest" in improvement_evidence
    assert (
        "EXPECTED_IMPROVEMENT_RECEIPT: ${{ needs.evidence.outputs.protected_receipt_digest }}"
    ) in promotion
    assert "EXPECTED_OUTCOME_DIGEST" in promotion
    assert "actions/download-artifact@" in promotion
    assert "autonomous-improvement-evidence-${{ inputs.request_digest }}" in promotion
    assert "verify_exact_improvement_handoff" in promotion
    assert 'handoff["candidate_commit"] != os.environ["CANDIDATE_COMMIT"]' in promotion
    assert 'handoff["outcome_digest"] != outcome_digest' in promotion
    assert 'handoff["protected_receipt_digest"] != expected_receipt' in promotion

    soak_evaluate = soak["evaluate"]
    soak_evidence = soak["evidence"]
    assert "health-result.json" in soak_evaluate
    assert "protected-soak-health-${{ inputs.request_digest }}" in soak_evaluate
    assert "health_result_digest" in soak_evaluate
    assert "actions/upload-artifact@" in soak_evaluate
    assert "actions/download-artifact@" in soak_evidence
    assert "EXPECTED_OUTCOME_DIGEST: ${{ needs.evaluate.outputs.health_result_digest }}" in (
        soak_evidence
    )
    assert 'value["healthy"] is not True' in soak_evidence
    assert "protected_receipt_digest" in soak_evidence
    assert "accept_soak" in soak_evidence
    assert "EXPECTED_HEALTH_RECEIPT" in soak_evidence
    assert "protected-soak-receipt-${{ inputs.request_digest }}" in soak["live_soak"]
    assert "protected-soak-receipt-${{ inputs.request_digest }}" in soak_evidence
    assert "verify_exact_health_receipt" in soak_evidence
    assert 'payload["health_receipt_digest"] != os.environ["EXPECTED_OUTCOME_DIGEST"]' in (
        soak_evidence
    )


def test_every_protected_stage_uses_exact_fail_closed_response_contract() -> None:
    for path in (IMPROVEMENT_WORKFLOW_PATH, SOAK_WORKFLOW_PATH):
        document = path.read_text(encoding="utf-8")
        assert "carl.coordinator.ipc.response.v1" in document
        assert 'set(value) != {"domain", "error_code", "request_digest", "result",' in document
        assert 'value["status"] != "completed"' in document
        assert 'value["request_digest"] != expected_ipc_digest' in document
        assert 'result["node"] != expected_node' in document
        assert 'if action == "complete_command"' in document
        assert 'result["reason"] != "observed_effect_completion_required"' in document
        assert "expected_successor" in document
        assert "workflow_stage_response_invalid" in document
        assert "persist_exact_node_freeze" in document
        assert "reject_request_freeze" in document
        assert "carl.workflow-stage-freeze.v1" in document
        assert "/var/lib/carl/protected-workflow-freezes" in document
        assert "os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW" in document
        assert "while written < len(raw)" in document
        assert '"node": expected_node' in document
        assert '"request_digest": workflow_request_digest' in document
        assert '"successor": expected_successor' in document
        assert "except Exception:" in document
        assert "expected_remote_effect" in document
        assert 'result["result_digest"] is not None' in document
        assert 'result["effect_key"] != command_value["effect_key"]' in document
        assert "not in (None, sys.argv[2])" not in document
        assert "if action == 'frozen'" not in document
    improvement_jobs = _workflow_job_blocks(IMPROVEMENT_WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert (
        'expected_successor != "register_hypothesis"' in improvement_jobs["publish_private_inputs"]
    )
    assert 'expected_successor != "observe_validation"' in improvement_jobs["live_validation"]


def test_soak_acceptance_uses_signed_durable_cadence_and_trusted_time() -> None:
    soak = SOAK_WORKFLOW_PATH.read_text(encoding="utf-8")
    jobs = _workflow_job_blocks(soak)
    live_soak = jobs["live_soak"]
    evidence = jobs["evidence"]

    assert "load_previous_signed_soak_receipt" in live_soak
    assert "verify_previous_signed_soak_receipt" in live_soak
    assert "PREVIOUS_SOAK_RECEIPT_PATH: /var/lib/carl/soak/previous-signed-receipt.json" in (
        live_soak
    )
    assert "/run/carl/soak/previous-signed-receipt.json" not in live_soak
    assert "trusted_current_time" in live_soak
    assert "previous_observed_at" in live_soak
    assert "timedelta(hours=6)" in live_soak
    assert "timedelta(hours=26)" in live_soak
    assert "soak_observation_too_early" in live_soak
    assert "soak_observation_stale_critical" in live_soak
    assert "active_merge_commit" in live_soak
    assert 'payload["active_merge_commit"] != os.environ["CANDIDATE_COMMIT"]' in live_soak
    assert 'payload["request_digest"] != os.environ["REQUEST_DIGEST"]' in live_soak
    assert 'payload["merged_at"] != context["merged_at"]' in live_soak
    assert 'payload["previous_receipt_digest"] != context["previous_receipt_digest"]' in live_soak
    assert 'current_chain[:-1] != context["previous_observation_chain"]' in live_soak
    assert "accept_ready = len(current_chain) == EXPECTED_CHAIN_LENGTH" in live_soak
    assert "accept_soak" in evidence
    assert "EXPECTED_HEALTH_RECEIPT" in evidence
    assert "verify_exact_health_receipt" in evidence
