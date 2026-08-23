from __future__ import annotations

import importlib
from dataclasses import replace
from pathlib import Path

import pytest
from test_experiment import manifest as experiment_manifest

from carl_bench.artifacts import ArtifactRef
from carl_bench.candidate import DeterministicCheckResult, SealedCandidate
from carl_bench.cloud_coordinator import ImmutableInputBinding
from carl_bench.experimental_publication import ExperimentalPublicationDecision
from carl_bench.openai_gateway import OpenAIModelRequest, OpenAIModelResult, OpenAIUsage

PARENT = "1" * 40
COORDINATOR_MANIFEST = "2" * 64


def _api(name: str):
    module = importlib.import_module("carl_bench.product_builder")
    return getattr(module, name)


def _hypothesis(
    hypothesis_id: str,
    *,
    family: str = "conversation-recovery",
    category: str = "product",
    priority: int = 10,
    work_marker: str = "3",
):
    return _api("ProductHypothesis")(
        hypothesis_id=hypothesis_id,
        capability_family=family,
        category=category,
        user_visible_behavior=f"Users can complete {hypothesis_id} without losing progress.",
        work_digest=work_marker * 64,
        parent_commit=PARENT,
        priority=priority,
    )


def _inputs(*, private: bool = True) -> tuple[ImmutableInputBinding, ...]:
    public = ImmutableInputBinding(
        digest="4" * 64,
        media_type="application/vnd.carl.experiment+json",
        media_version=1,
        size_bytes=512,
        visibility="public",
        resolved_digest="4" * 64,
    )
    if not private:
        return (public,)
    held_out = ImmutableInputBinding(
        digest="5" * 64,
        media_type="application/vnd.carl.improvement-task-set+json",
        media_version=1,
        size_bytes=4096,
        visibility="private",
        resolved_digest="5" * 64,
    )
    return (public, held_out)


def _snapshot(
    *,
    previous_hypotheses: tuple[str, ...] = (),
    previous_work: tuple[str, ...] = (),
    cooldowns: tuple[tuple[str, int], ...] = (),
    immutable_inputs: tuple[ImmutableInputBinding, ...] | None = None,
):
    return _api("BuilderSnapshot")(
        schema_version=1,
        repository="openclaw/carl",
        exact_parent_commit=PARENT,
        coordinator_manifest_digest=COORDINATOR_MANIFEST,
        cycle=12,
        previous_hypothesis_digests=previous_hypotheses,
        previous_work_digests=previous_work,
        capability_family_cooldowns=cooldowns,
        immutable_inputs=_inputs() if immutable_inputs is None else immutable_inputs,
    )


def _limits():
    return _api("BuilderLimits")(
        allowed_paths=("src/runtime", "tests/runtime"),
        forbidden_paths=("benchmarks", ".github", "src/promotion.rs"),
        allowed_tools=("apply_patch", "cargo", "git", "rg"),
        max_changed_paths=8,
        max_patch_bytes=131_072,
        max_elapsed_seconds=1800,
        max_cost_microdollars=2_000_000,
    )


def _manifest(hypothesis) -> object:
    return replace(
        experiment_manifest(),
        experiment_id=f"exp-{hypothesis.hypothesis_id}",
        parent_commit=PARENT,
        hypothesis=hypothesis.user_visible_behavior,
        target_surface=("src/runtime", "tests/runtime"),
        forbidden_surface=("benchmarks", ".github", "src/promotion.rs"),
    )


def _attempt(
    attempt: int = 1,
    *,
    action_marker: str = "6",
    patch_marker: str = "7",
    path: str = "src/runtime/recovery.rs",
    tool: str = "apply_patch",
    red_at: str = "2026-08-23T12:00:00Z",
    patch_at: str = "2026-08-23T12:01:00Z",
    elapsed_seconds: int = 300,
    cost_microdollars: int = 250_000,
):
    return _api("BuildAttemptEvidence")(
        schema_version=1,
        attempt=attempt,
        action_digest=action_marker * 64,
        patch_digest=patch_marker * 64,
        failing_test_id="restart-preserves-progress",
        red_exit_code=1,
        red_output_digest="8" * 64,
        red_observed_at=red_at,
        patch_applied_at=patch_at,
        changed_paths=(path,),
        tools=(tool,),
        patch_bytes=4096,
        elapsed_seconds=elapsed_seconds,
        cost_microdollars=cost_microdollars,
        finding_digest=None if attempt == 1 else "9" * 64,
    )


def _artifact(kind: str, marker: str) -> ArtifactRef:
    return ArtifactRef(
        schema_version=1,
        digest=marker * 64,
        byte_size=32,
        media_type="application/json",
        evidence_kind=kind,
    )


def _candidate(registration) -> SealedCandidate:
    return SealedCandidate(
        schema_version=1,
        experiment_id=registration.experiment_id,
        manifest_digest=registration.manifest_digest,
        parent_commit=PARENT,
        candidate_commit="a" * 40,
        branch=f"codex/experiment-{registration.experiment_id}-0123456789",
        diff_artifact=_artifact("candidate_diff", "b"),
        report_artifact=_artifact("implementation_report", "c"),
        changed_paths_artifact=_artifact("changed_paths", "d"),
        changed_path_count=2,
        checks=(
            DeterministicCheckResult(
                check_id="repository-gates",
                status="passed",
                exit_code=0,
                elapsed_ms=500,
                output_artifact=_artifact("check_output", "e"),
            ),
        ),
    )


class RecordingRegistrar:
    def __init__(self, events: list[str], *, accepted: bool = True) -> None:
        self.events = events
        self.accepted = accepted
        self.registration = None

    def register(self, registration) -> bool:
        self.events.append("preregister")
        self.registration = registration
        return self.accepted


class RecordingGateway:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.request: OpenAIModelRequest | None = None

    def evaluate(self, request: OpenAIModelRequest) -> OpenAIModelResult:
        self.events.append("model")
        self.request = request
        return OpenAIModelResult(
            response_id="resp_builder_001",
            model="gpt-5.6",
            status="completed",
            usage=OpenAIUsage(100, 0, 50, 10, 150),
            latency_ms=250,
            request_digest=request.request_digest,
            output_digest="f" * 64,
            output_text='{"patch":"bounded"}',
        )


class RecordingSandbox:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.environment: dict[str, str] | None = None

    def execute(self, *, invocation, limits, environment, prior_attempts):
        del limits, prior_attempts
        self.events.append("sandbox")
        self.environment = environment
        return _api("CandidateSandboxResult")(
            attempt=_attempt(),
            candidate_packet=_candidate(invocation.registration),
            disposition=None,
            evidence_digest=None,
            next_hypothesis=None,
        )


class RecordingPacketStore:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def persist(self, *, registration, packet) -> bool:
        self.events.append("packet-store")
        return packet.experiment_id == registration.experiment_id


def _register(hypothesis=None):
    selected = hypothesis or _hypothesis("recovery-001")
    selection = _api("select_hypothesis")(_snapshot(), (selected,))
    events: list[str] = []
    invocation = _api("preregister_and_call_model")(
        selection=selection,
        manifest=_manifest(selected),
        snapshot=_snapshot(),
        limits=_limits(),
        registrar=RecordingRegistrar(events),
        gateway=RecordingGateway(events),
        prompt="Implement the preregistered behavior with a failing test first.",
        attempt=1,
    )
    return invocation.registration


def test_product_builder_module_exists() -> None:
    module_path = Path(__file__).resolve().parents[1] / "src/carl_bench/product_builder.py"
    assert module_path.is_file()


def test_selection_rejects_durable_duplicate_hypothesis_and_work() -> None:
    repeated_hypothesis = _hypothesis("recovery-001", work_marker="3")
    repeated_work = _hypothesis("recovery-002", family="tool-replay", work_marker="7")
    fresh = _hypothesis("recovery-003", family="session-replay", work_marker="8")
    snapshot = _snapshot(
        previous_hypotheses=(repeated_hypothesis.digest,),
        previous_work=(repeated_work.work_digest,),
    )

    selection = _api("select_hypothesis")(
        snapshot,
        (repeated_hypothesis, repeated_work, fresh),
    )

    assert selection.selected == fresh
    assert selection.rejected == (
        ("recovery-001", "hypothesis_already_attempted"),
        ("recovery-002", "work_already_attempted"),
    )
    assert selection.next_safe_node == "register_hypothesis:recovery-003"


def test_selection_prefers_product_over_higher_priority_infrastructure() -> None:
    infrastructure = _hypothesis(
        "faster-ci",
        family="factory-throughput",
        category="infrastructure",
        priority=100,
        work_marker="6",
    )
    product = _hypothesis("recovery-001", priority=1)

    selection = _api("select_hypothesis")(_snapshot(), (infrastructure, product))

    assert selection.selected == product
    assert ("faster-ci", "product_capability_available") in selection.rejected


def test_selection_enforces_capability_family_cooldown_boundary() -> None:
    cooling = _hypothesis("recovery-001")
    available = _hypothesis("tool-001", family="tool-use", work_marker="7")

    selection = _api("select_hypothesis")(
        _snapshot(cooldowns=(("conversation-recovery", 12),)),
        (cooling, available),
    )

    assert selection.selected == available
    assert ("recovery-001", "capability_family_cooling_down") in selection.rejected


def test_selection_fails_closed_when_no_distinct_safe_node_exists() -> None:
    repeated = _hypothesis("recovery-001")

    with pytest.raises(_api("BuilderError"), match="^builder_no_distinct_safe_node$"):
        _api("select_hypothesis")(
            _snapshot(previous_work=(repeated.work_digest,)),
            (repeated,),
        )


def test_preregistration_precedes_model_call_and_binds_parent_private_inputs() -> None:
    hypothesis = _hypothesis("recovery-001")
    snapshot = _snapshot()
    selection = _api("select_hypothesis")(snapshot, (hypothesis,))
    events: list[str] = []
    registrar = RecordingRegistrar(events)
    gateway = RecordingGateway(events)

    invocation = _api("preregister_and_call_model")(
        selection=selection,
        manifest=_manifest(hypothesis),
        snapshot=snapshot,
        limits=_limits(),
        registrar=registrar,
        gateway=gateway,
        prompt="Implement the preregistered behavior with a failing test first.",
        attempt=1,
    )

    assert events == ["preregister", "model"]
    assert registrar.registration == invocation.registration
    assert invocation.registration.parent_commit == PARENT
    assert invocation.registration.private_input_digests == ("5" * 64,)
    assert invocation.registration.coordinator_manifest_digest == COORDINATOR_MANIFEST
    assert gateway.request == invocation.request
    assert invocation.request.subject == "candidate"
    assert invocation.request.execution_context_digest == invocation.registration.digest


def test_preregistration_failure_or_parent_input_drift_prevents_model_call() -> None:
    hypothesis = _hypothesis("recovery-001")
    selection = _api("select_hypothesis")(_snapshot(), (hypothesis,))
    events: list[str] = []
    gateway = RecordingGateway(events)

    with pytest.raises(_api("BuilderError"), match="^builder_preregistration_rejected$"):
        _api("preregister_and_call_model")(
            selection=selection,
            manifest=_manifest(hypothesis),
            snapshot=_snapshot(),
            limits=_limits(),
            registrar=RecordingRegistrar(events, accepted=False),
            gateway=gateway,
            prompt="Implement with a failing test first.",
            attempt=1,
        )
    assert events == ["preregister"]

    for drifted in (
        _snapshot(immutable_inputs=_inputs(private=False)),
        replace(_snapshot(), exact_parent_commit="0" * 40),
    ):
        events.clear()
        with pytest.raises(_api("BuilderError")):
            _api("preregister_and_call_model")(
                selection=selection,
                manifest=_manifest(hypothesis),
                snapshot=drifted,
                limits=_limits(),
                registrar=RecordingRegistrar(events),
                gateway=gateway,
                prompt="Implement with a failing test first.",
                attempt=1,
            )
        assert "model" not in events


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        ({"path": "benchmarks/tasks/private.py"}, "builder_patch_path_forbidden"),
        ({"path": "docs/unplanned.md"}, "builder_patch_path_outside_scope"),
        ({"tool": "curl"}, "builder_tool_forbidden"),
        ({"red_at": "2026-08-23T12:02:00Z"}, "builder_red_evidence_order_invalid"),
        ({"elapsed_seconds": 1801}, "builder_elapsed_budget_exceeded"),
        ({"cost_microdollars": 2_000_001}, "builder_cost_budget_exceeded"),
    ),
)
def test_attempt_validation_catches_scope_tool_red_order_and_budget_mutations(
    mutation: dict[str, object], code: str
) -> None:
    with pytest.raises(_api("BuilderError"), match=f"^{code}$"):
        _api("validate_attempts")(_limits(), (_attempt(**mutation),))


def test_attempt_validation_requires_failing_test_first_and_two_changed_repairs_maximum() -> None:
    initial = _attempt()
    repair_one = _attempt(attempt=2, action_marker="a", patch_marker="b")
    repair_two = _attempt(attempt=3, action_marker="c", patch_marker="d")

    assert _api("validate_attempts")(_limits(), (initial, repair_one, repair_two)) == (
        initial,
        repair_one,
        repair_two,
    )

    unchanged = replace(repair_one, action_digest=initial.action_digest)
    with pytest.raises(_api("BuilderError"), match="^builder_unchanged_retry_forbidden$"):
        _api("validate_attempts")(_limits(), (initial, unchanged))

    fourth = replace(repair_two, attempt=4, action_digest="e" * 64, patch_digest="f" * 64)
    with pytest.raises(_api("BuilderError"), match="^builder_repair_budget_exceeded$"):
        _api("validate_attempts")(_limits(), (initial, repair_one, repair_two, fourth))


def test_attempt_validation_enforces_cumulative_time_cost_and_changed_patch() -> None:
    initial = _attempt(elapsed_seconds=1000, cost_microdollars=1_000_000)
    repair = _attempt(
        attempt=2,
        action_marker="a",
        patch_marker="b",
        elapsed_seconds=900,
        cost_microdollars=1_100_000,
    )
    with pytest.raises(_api("BuilderError"), match="^builder_elapsed_budget_exceeded$"):
        _api("validate_attempts")(_limits(), (initial, repair))

    same_patch = replace(repair, elapsed_seconds=100, cost_microdollars=100, patch_digest="7" * 64)
    with pytest.raises(_api("BuilderError"), match="^builder_unchanged_retry_forbidden$"):
        _api("validate_attempts")(_limits(), (initial, same_patch))


def test_candidate_environment_is_allowlisted_and_contains_no_service_credentials(
    tmp_path: Path,
) -> None:
    environment = _api("credential_free_candidate_environment")(
        {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "CI": "true",
            "OPENAI_API_KEY": "provider-secret",
            "GITHUB_TOKEN": "github-secret",
            "AWS_ACCESS_KEY_ID": "cloud-secret",
            "CARL_GITHUB_APP_PRIVATE_KEY": "app-secret",
            "PYTHONPATH": "/attacker/path",
        },
        sandbox_home=tmp_path,
    )

    assert environment == {
        "CI": "true",
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    assert not any(
        marker in key.casefold()
        for key in environment
        for marker in ("auth", "credential", "key", "secret", "token")
    )


def test_complete_candidate_packet_is_exact_and_routes_to_experimental_publication() -> None:
    registration = _register()
    packet = _candidate(registration)

    terminal = _api("complete_candidate_packet")(registration, packet)

    assert terminal.outcome == "candidate_packet"
    assert terminal.candidate_packet_digest == packet.digest
    assert terminal.live_validated is False
    assert terminal.production_eligible is False
    assert terminal.next_safe_node == "publish_experimental"

    with pytest.raises(_api("BuilderError"), match="^builder_candidate_packet_mismatch$"):
        _api("complete_candidate_packet")(
            registration,
            replace(packet, parent_commit="0" * 40),
        )


def test_immutable_experimental_publication_never_claims_live_validation() -> None:
    registration = _register()
    packet = _candidate(registration)
    publication = ExperimentalPublicationDecision(
        outcome="push_branch",
        ref=f"refs/heads/experimental/{packet.experiment_id}",
        candidate_commit=packet.candidate_commit,
        candidate_tree="f" * 40,
        candidate_packet_digest=packet.digest,
    )

    terminal = _api("complete_experimental_publication")(registration, packet, publication)

    assert terminal.outcome == "experimental_publication"
    assert terminal.experimental_ref == publication.ref
    assert terminal.live_validated is False
    assert terminal.production_eligible is False
    assert terminal.next_safe_node == "dispatch_validation"

    drifted = replace(publication, candidate_commit="0" * 40)
    with pytest.raises(_api("BuilderError"), match="^builder_publication_mismatch$"):
        _api("complete_experimental_publication")(registration, packet, drifted)


def test_changed_repair_request_is_terminal_and_unchanged_retry_fails_closed() -> None:
    registration = _register()
    initial = _attempt()
    changed = _attempt(attempt=2, action_marker="a", patch_marker="b")

    terminal = _api("request_changed_repair")(registration, (initial,), changed)

    assert terminal.outcome == "repair_request"
    assert terminal.repair_request.attempt == 2
    assert terminal.next_safe_node == f"repair:{registration.experiment_id}:2"

    with pytest.raises(_api("BuilderError"), match="^builder_unchanged_retry_forbidden$"):
        _api("request_changed_repair")(
            registration,
            (initial,),
            replace(changed, action_digest=initial.action_digest),
        )


@pytest.mark.parametrize("disposition", ("rejected", "inconclusive"))
def test_rejection_and_inconclusive_retain_learning_with_distinct_next_node(
    disposition: str,
) -> None:
    current = _hypothesis("recovery-001")
    next_hypothesis = _hypothesis("tool-001", family="tool-use", work_marker="7")
    registration = _register(current)

    terminal = _api("retain_builder_learning")(
        registration=registration,
        current=current,
        disposition=disposition,
        evidence_digest="f" * 64,
        next_hypothesis=next_hypothesis,
    )

    assert terminal.outcome == "retained_learning"
    assert terminal.retained_learning.disposition == disposition
    assert terminal.next_safe_node == "register_hypothesis:tool-001"
    assert terminal.live_validated is False
    assert terminal.production_eligible is False

    with pytest.raises(_api("BuilderError"), match="^builder_next_safe_node_not_distinct$"):
        _api("retain_builder_learning")(
            registration=registration,
            current=current,
            disposition=disposition,
            evidence_digest="f" * 64,
            next_hypothesis=replace(current, work_digest="9" * 64),
        )


def test_terminal_result_has_no_report_only_outcome() -> None:
    assert (
        frozenset(
            {"candidate_packet", "experimental_publication", "repair_request", "retained_learning"}
        )
        == _api("BuilderTerminalResult").OUTCOMES
    )


def test_stateful_builder_owns_the_complete_protected_product_run(tmp_path: Path) -> None:
    hypothesis = _hypothesis("recovery-001")
    events: list[str] = []
    sandbox = RecordingSandbox(events)
    builder = _api("AutonomousProductBuilder")(
        registrar=RecordingRegistrar(events),
        gateway=RecordingGateway(events),
        sandbox=sandbox,
        packet_store=RecordingPacketStore(events),
    )

    terminal = builder.run(
        snapshot=_snapshot(),
        hypotheses=(hypothesis,),
        manifest=_manifest(hypothesis),
        limits=_limits(),
        prompt="Implement the preregistered behavior with a failing test first.",
        attempt=1,
        prior_attempts=(),
        source_environment={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "OPENAI_API_KEY": "controller-only",
            "GITHUB_TOKEN": "controller-only",
        },
        sandbox_home=tmp_path,
    )

    assert events == ["preregister", "model", "sandbox", "packet-store"]
    assert terminal.outcome == "candidate_packet"
    assert terminal.next_safe_node == "publish_experimental"
    assert terminal.live_validated is False
    assert terminal.production_eligible is False
    assert sandbox.environment == {
        "CI": "true",
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }


def test_attempt_budgets_are_cumulative_across_patch_bytes_and_path_union() -> None:
    initial = replace(
        _attempt(),
        patch_bytes=70_000,
        changed_paths=("src/runtime/recovery.rs",),
    )
    repair = replace(
        _attempt(attempt=2, action_marker="a", patch_marker="b"),
        patch_bytes=70_000,
        changed_paths=("tests/runtime/recovery.rs",),
    )

    with pytest.raises(_api("BuilderError"), match="^builder_patch_budget_exceeded$"):
        _api("validate_attempts")(_limits(), (initial, repair))

    one_path = replace(_limits(), max_changed_paths=1, max_patch_bytes=200_000)
    with pytest.raises(_api("BuilderError"), match="^builder_changed_path_budget_exceeded$"):
        _api("validate_attempts")(one_path, (initial, repair))


def test_first_failure_requests_repair_one_and_exhaustion_retains_learning() -> None:
    current = _hypothesis("recovery-001")
    next_hypothesis = _hypothesis("tool-001", family="tool-use", work_marker="7")
    registration = _register(current)

    repair = _api("terminalize_unsuccessful_attempt")(
        registration=registration,
        current=current,
        limits=_limits(),
        attempts=(_attempt(),),
        finding_digest="a" * 64,
        disposition="repairable",
        next_hypothesis=next_hypothesis,
    )
    assert repair.outcome == "repair_request"
    assert repair.repair_request.repair_number == 1
    assert repair.repair_request.next_attempt == 2

    exhausted = _api("terminalize_unsuccessful_attempt")(
        registration=registration,
        current=current,
        limits=_limits(),
        attempts=(
            _attempt(),
            _attempt(attempt=2, action_marker="a", patch_marker="b"),
            _attempt(attempt=3, action_marker="c", patch_marker="d"),
        ),
        finding_digest="e" * 64,
        disposition="repairable",
        next_hypothesis=next_hypothesis,
    )
    assert exhausted.outcome == "retained_learning"
    assert exhausted.next_safe_node == "register_hypothesis:tool-001"


def test_unchanged_repair_retains_learning_instead_of_raising() -> None:
    current = _hypothesis("recovery-001")
    next_hypothesis = _hypothesis("tool-001", family="tool-use", work_marker="7")
    initial = _attempt()
    unchanged = replace(
        _attempt(attempt=2, action_marker="a", patch_marker="b"),
        action_digest=initial.action_digest,
    )

    terminal = _api("terminalize_unsuccessful_attempt")(
        registration=_register(current),
        current=current,
        limits=_limits(),
        attempts=(initial, unchanged),
        finding_digest="e" * 64,
        disposition="rejected",
        next_hypothesis=next_hypothesis,
    )

    assert terminal.outcome == "retained_learning"
    assert terminal.retained_learning.disposition == "rejected"
