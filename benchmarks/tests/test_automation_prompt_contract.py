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
