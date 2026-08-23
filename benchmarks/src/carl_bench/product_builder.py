"""Fail-closed policy core for Carl's autonomous remote product builder.

The module owns deterministic selection, preregistration ordering, candidate bounds, and terminal
outcome contracts. Provider credentials, durable storage, patch application, Git publication, and
downstream workflow dispatch remain behind their existing protected process boundaries.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import ClassVar, Literal, Protocol

from carl_bench.candidate import SealedCandidate
from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_coordinator import ImmutableInputBinding
from carl_bench.experiment import ExperimentManifest
from carl_bench.experimental_publication import ExperimentalPublicationDecision
from carl_bench.openai_gateway import OpenAIModelRequest, OpenAIModelResult

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_TOOL_RE = re.compile(r"^[a-z][a-z0-9._+-]{0,63}$")
_CREDENTIAL_MARKERS = ("auth", "credential", "key", "password", "secret", "token")


class BuilderError(ValueError):
    """Stable builder failure that never includes prompts, private inputs, or credentials."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise BuilderError(code)
    return value


def _commit(value: object, code: str) -> str:
    if not isinstance(value, str) or _COMMIT_RE.fullmatch(value) is None:
        raise BuilderError(code)
    return value


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise BuilderError(code)
    return value


def _timestamp(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BuilderError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise BuilderError(code) from error
    if parsed.tzinfo != UTC or parsed.microsecond:
        raise BuilderError(code)
    return parsed


def _strict_sorted_unique(values: object, *, code: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or any(not isinstance(value, str) for value in values):
        raise BuilderError(code)
    if values != tuple(sorted(set(values), key=str.encode)):
        raise BuilderError(code)
    return values


def _strict_unique(values: object, *, code: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or any(not isinstance(value, str) for value in values):
        raise BuilderError(code)
    if len(set(values)) != len(values):
        raise BuilderError(code)
    return values


def _path(value: str, code: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > 512
        or "\\" in value
        or PurePosixPath(value).is_absolute()
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise BuilderError(code)
    return value


def _inside(surface: str, path: str) -> bool:
    return path == surface or path.startswith(surface + "/")


@dataclass(frozen=True, slots=True)
class ProductHypothesis:
    hypothesis_id: str
    capability_family: str
    category: Literal["product", "infrastructure"]
    user_visible_behavior: str
    work_digest: str
    parent_commit: str
    priority: int

    def __post_init__(self) -> None:
        _identifier(self.hypothesis_id, "builder_hypothesis_id_invalid")
        _identifier(self.capability_family, "builder_capability_family_invalid")
        if self.category not in {"product", "infrastructure"}:
            raise BuilderError("builder_hypothesis_category_invalid")
        if (
            not isinstance(self.user_visible_behavior, str)
            or not self.user_visible_behavior.strip()
            or len(self.user_visible_behavior.encode("utf-8")) > 4096
            or "\x00" in self.user_visible_behavior
        ):
            raise BuilderError("builder_user_visible_behavior_invalid")
        _digest(self.work_digest, "builder_work_digest_invalid")
        _commit(self.parent_commit, "builder_parent_commit_invalid")
        if (
            isinstance(self.priority, bool)
            or not isinstance(self.priority, int)
            or not 0 <= self.priority <= 1_000_000
        ):
            raise BuilderError("builder_priority_invalid")

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "capability_family": self.capability_family,
            "category": self.category,
            "hypothesis_id": self.hypothesis_id,
            "parent_commit": self.parent_commit,
            "priority": self.priority,
            "user_visible_behavior": self.user_visible_behavior,
            "work_digest": self.work_digest,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class BuilderSnapshot:
    schema_version: int
    repository: str
    exact_parent_commit: str
    coordinator_manifest_digest: str
    cycle: int
    previous_hypothesis_digests: tuple[str, ...]
    previous_work_digests: tuple[str, ...]
    capability_family_cooldowns: tuple[tuple[str, int], ...]
    immutable_inputs: tuple[ImmutableInputBinding, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise BuilderError("builder_snapshot_schema_invalid")
        if (
            not isinstance(self.repository, str)
            or _REPOSITORY_RE.fullmatch(self.repository) is None
        ):
            raise BuilderError("builder_repository_invalid")
        _commit(self.exact_parent_commit, "builder_parent_commit_invalid")
        _digest(self.coordinator_manifest_digest, "builder_coordinator_manifest_invalid")
        if isinstance(self.cycle, bool) or not isinstance(self.cycle, int) or self.cycle < 0:
            raise BuilderError("builder_cycle_invalid")
        _strict_sorted_unique(
            self.previous_hypothesis_digests,
            code="builder_prior_hypotheses_invalid",
        )
        _strict_sorted_unique(self.previous_work_digests, code="builder_prior_work_invalid")
        for value in (*self.previous_hypothesis_digests, *self.previous_work_digests):
            _digest(value, "builder_prior_digest_invalid")
        if not isinstance(self.capability_family_cooldowns, tuple):
            raise BuilderError("builder_cooldowns_invalid")
        cooldown_families: list[str] = []
        for item in self.capability_family_cooldowns:
            if not isinstance(item, tuple) or len(item) != 2:
                raise BuilderError("builder_cooldowns_invalid")
            family, through_cycle = item
            _identifier(family, "builder_capability_family_invalid")
            if (
                isinstance(through_cycle, bool)
                or not isinstance(through_cycle, int)
                or through_cycle < 0
            ):
                raise BuilderError("builder_cooldowns_invalid")
            cooldown_families.append(family)
        if tuple(cooldown_families) != tuple(sorted(set(cooldown_families), key=str.encode)):
            raise BuilderError("builder_cooldowns_invalid")
        if (
            not isinstance(self.immutable_inputs, tuple)
            or not self.immutable_inputs
            or any(type(value) is not ImmutableInputBinding for value in self.immutable_inputs)
        ):
            raise BuilderError("builder_immutable_inputs_invalid")
        digests = tuple(item.digest for item in self.immutable_inputs)
        if digests != tuple(sorted(set(digests), key=str.encode)):
            raise BuilderError("builder_immutable_inputs_invalid")


@dataclass(frozen=True, slots=True)
class BuilderSelection:
    selected: ProductHypothesis
    rejected: tuple[tuple[str, str], ...]
    next_safe_node: str


def select_hypothesis(
    snapshot: BuilderSnapshot,
    hypotheses: tuple[ProductHypothesis, ...],
) -> BuilderSelection:
    """Choose one novel product hypothesis, falling back to infrastructure only when necessary."""
    if type(snapshot) is not BuilderSnapshot or not isinstance(hypotheses, tuple) or not hypotheses:
        raise BuilderError("builder_selection_input_invalid")
    if any(type(item) is not ProductHypothesis for item in hypotheses):
        raise BuilderError("builder_selection_input_invalid")
    hypothesis_ids = tuple(item.hypothesis_id for item in hypotheses)
    if len(set(hypothesis_ids)) != len(hypothesis_ids):
        raise BuilderError("builder_hypothesis_duplicate")
    prior_hypotheses = frozenset(snapshot.previous_hypothesis_digests)
    prior_work = frozenset(snapshot.previous_work_digests)
    cooldowns = dict(snapshot.capability_family_cooldowns)
    rejected: list[tuple[str, str]] = []
    eligible: list[ProductHypothesis] = []
    for item in hypotheses:
        if item.parent_commit != snapshot.exact_parent_commit:
            rejected.append((item.hypothesis_id, "protected_parent_mismatch"))
        elif item.digest in prior_hypotheses:
            rejected.append((item.hypothesis_id, "hypothesis_already_attempted"))
        elif item.work_digest in prior_work:
            rejected.append((item.hypothesis_id, "work_already_attempted"))
        elif cooldowns.get(item.capability_family, -1) >= snapshot.cycle:
            rejected.append((item.hypothesis_id, "capability_family_cooling_down"))
        else:
            eligible.append(item)
    products = [item for item in eligible if item.category == "product"]
    pool = products or eligible
    if not pool:
        raise BuilderError("builder_no_distinct_safe_node")
    selected = min(pool, key=lambda item: (-item.priority, item.hypothesis_id.encode("utf-8")))
    for item in eligible:
        if item == selected:
            continue
        reason = (
            "product_capability_available"
            if item.category == "infrastructure" and products
            else "lower_priority_hypothesis"
        )
        rejected.append((item.hypothesis_id, reason))
    order = {item.hypothesis_id: index for index, item in enumerate(hypotheses)}
    rejected.sort(key=lambda item: order[item[0]])
    return BuilderSelection(
        selected=selected,
        rejected=tuple(rejected),
        next_safe_node=f"register_hypothesis:{selected.hypothesis_id}",
    )


@dataclass(frozen=True, slots=True)
class BuilderLimits:
    allowed_paths: tuple[str, ...]
    forbidden_paths: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    max_changed_paths: int
    max_patch_bytes: int
    max_elapsed_seconds: int
    max_cost_microdollars: int

    def __post_init__(self) -> None:
        for name in ("allowed_paths", "forbidden_paths"):
            values = _strict_unique(getattr(self, name), code="builder_path_limits_invalid")
            if not values:
                raise BuilderError("builder_path_limits_invalid")
            for value in values:
                _path(value, "builder_path_limits_invalid")
        for allowed in self.allowed_paths:
            if any(
                _inside(allowed, forbidden) or _inside(forbidden, allowed)
                for forbidden in self.forbidden_paths
            ):
                raise BuilderError("builder_path_limits_overlap")
        tools = _strict_sorted_unique(self.allowed_tools, code="builder_tool_limits_invalid")
        if not tools or any(_TOOL_RE.fullmatch(tool) is None for tool in tools):
            raise BuilderError("builder_tool_limits_invalid")
        maximums = (
            (self.max_changed_paths, 1, 128),
            (self.max_patch_bytes, 1, 1_048_576),
            (self.max_elapsed_seconds, 1, 3600),
            (self.max_cost_microdollars, 1, 10_000_000),
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper
            for value, lower, upper in maximums
        ):
            raise BuilderError("builder_limits_invalid")

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "allowed_paths": list(self.allowed_paths),
            "allowed_tools": list(self.allowed_tools),
            "forbidden_paths": list(self.forbidden_paths),
            "max_changed_paths": self.max_changed_paths,
            "max_cost_microdollars": self.max_cost_microdollars,
            "max_elapsed_seconds": self.max_elapsed_seconds,
            "max_patch_bytes": self.max_patch_bytes,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class BuilderPreregistration:
    schema_version: int
    repository: str
    experiment_id: str
    manifest_digest: str
    hypothesis_digest: str
    work_digest: str
    parent_commit: str
    immutable_inputs_digest: str
    private_input_digests: tuple[str, ...]
    coordinator_manifest_digest: str
    limits_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise BuilderError("builder_preregistration_schema_invalid")
        if (
            not isinstance(self.repository, str)
            or _REPOSITORY_RE.fullmatch(self.repository) is None
        ):
            raise BuilderError("builder_repository_invalid")
        _identifier(self.experiment_id, "builder_experiment_id_invalid")
        for name in (
            "manifest_digest",
            "hypothesis_digest",
            "work_digest",
            "immutable_inputs_digest",
            "coordinator_manifest_digest",
            "limits_digest",
        ):
            _digest(getattr(self, name), f"builder_{name}_invalid")
        _commit(self.parent_commit, "builder_parent_commit_invalid")
        private = _strict_sorted_unique(
            self.private_input_digests,
            code="builder_private_inputs_invalid",
        )
        if not private:
            raise BuilderError("builder_private_inputs_required")
        for value in private:
            _digest(value, "builder_private_inputs_invalid")

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "coordinator_manifest_digest": self.coordinator_manifest_digest,
            "experiment_id": self.experiment_id,
            "hypothesis_digest": self.hypothesis_digest,
            "immutable_inputs_digest": self.immutable_inputs_digest,
            "limits_digest": self.limits_digest,
            "manifest_digest": self.manifest_digest,
            "parent_commit": self.parent_commit,
            "private_input_digests": list(self.private_input_digests),
            "repository": self.repository,
            "schema_version": self.schema_version,
            "work_digest": self.work_digest,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


class BuilderPreregistrar(Protocol):
    def register(self, registration: BuilderPreregistration) -> bool:
        """Durably register the exact build before model execution."""


class BuilderModelGateway(Protocol):
    def evaluate(self, request: OpenAIModelRequest) -> OpenAIModelResult:
        """Invoke the existing controller-owned OpenAI gateway."""


@dataclass(frozen=True, slots=True)
class BuilderModelInvocation:
    registration: BuilderPreregistration
    request: OpenAIModelRequest
    result: OpenAIModelResult


def _immutable_inputs_digest(inputs: tuple[ImmutableInputBinding, ...]) -> str:
    return hashlib.sha256(
        canonical_json_bytes([item.to_canonical_dict() for item in inputs])
    ).hexdigest()


def preregister_and_call_model(
    *,
    selection: BuilderSelection,
    manifest: ExperimentManifest,
    snapshot: BuilderSnapshot,
    limits: BuilderLimits,
    registrar: BuilderPreregistrar,
    gateway: BuilderModelGateway,
    prompt: str,
    attempt: int,
) -> BuilderModelInvocation:
    """Persist an exact registration and only then call the protected model gateway."""
    if (
        type(selection) is not BuilderSelection
        or type(manifest) is not ExperimentManifest
        or type(snapshot) is not BuilderSnapshot
        or type(limits) is not BuilderLimits
        or not callable(getattr(registrar, "register", None))
        or not callable(getattr(gateway, "evaluate", None))
    ):
        raise BuilderError("builder_invocation_invalid")
    selected = selection.selected
    if (
        selected.parent_commit != snapshot.exact_parent_commit
        or manifest.parent_commit != snapshot.exact_parent_commit
        or manifest.hypothesis != selected.user_visible_behavior
        or tuple(manifest.target_surface) != limits.allowed_paths
        or tuple(manifest.forbidden_surface) != limits.forbidden_paths
    ):
        raise BuilderError("builder_protected_parent_or_scope_mismatch")
    private = tuple(
        sorted(
            (item.digest for item in snapshot.immutable_inputs if item.visibility == "private"),
            key=str.encode,
        )
    )
    if not private:
        raise BuilderError("builder_private_inputs_required")
    if (
        isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or not 1 <= attempt <= 3
        or not isinstance(prompt, str)
        or not prompt
        or "\x00" in prompt
        or len(prompt.encode("utf-8")) > 65_536
    ):
        raise BuilderError("builder_model_request_invalid")
    registration = BuilderPreregistration(
        schema_version=1,
        repository=snapshot.repository,
        experiment_id=manifest.experiment_id,
        manifest_digest=manifest.digest,
        hypothesis_digest=selected.digest,
        work_digest=selected.work_digest,
        parent_commit=manifest.parent_commit,
        immutable_inputs_digest=_immutable_inputs_digest(snapshot.immutable_inputs),
        private_input_digests=private,
        coordinator_manifest_digest=snapshot.coordinator_manifest_digest,
        limits_digest=limits.digest,
    )
    try:
        registered = registrar.register(registration)
    except Exception as error:
        raise BuilderError("builder_preregistration_failed") from error
    if registered is not True:
        raise BuilderError("builder_preregistration_rejected")
    seed = int(registration.digest[:8], 16) & 0x7FFF_FFFF
    request = OpenAIModelRequest(
        schema_version=1,
        repository=snapshot.repository,
        experiment_id=manifest.experiment_id,
        subject="candidate",
        task_id=f"product-builder-{attempt}",
        seed=seed,
        attempt=attempt,
        input=prompt,
        execution_context_digest=registration.digest,
    )
    try:
        result = gateway.evaluate(request)
    except Exception as error:
        raise BuilderError("builder_model_call_failed") from error
    if not isinstance(result, OpenAIModelResult) or result.request_digest != request.request_digest:
        raise BuilderError("builder_model_result_invalid")
    return BuilderModelInvocation(registration=registration, request=request, result=result)


@dataclass(frozen=True, slots=True)
class BuildAttemptEvidence:
    schema_version: int
    attempt: int
    action_digest: str
    patch_digest: str
    failing_test_id: str
    red_exit_code: int
    red_output_digest: str
    red_observed_at: str
    patch_applied_at: str
    changed_paths: tuple[str, ...]
    tools: tuple[str, ...]
    patch_bytes: int
    elapsed_seconds: int
    cost_microdollars: int
    finding_digest: str | None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise BuilderError("builder_attempt_schema_invalid")
        if isinstance(self.attempt, bool) or not isinstance(self.attempt, int) or self.attempt < 1:
            raise BuilderError("builder_attempt_invalid")
        _digest(self.action_digest, "builder_action_digest_invalid")
        _digest(self.patch_digest, "builder_patch_digest_invalid")
        _identifier(self.failing_test_id, "builder_failing_test_invalid")
        if (
            isinstance(self.red_exit_code, bool)
            or not isinstance(self.red_exit_code, int)
            or not 1 <= self.red_exit_code <= 255
        ):
            raise BuilderError("builder_red_evidence_invalid")
        _digest(self.red_output_digest, "builder_red_evidence_invalid")
        _timestamp(self.red_observed_at, "builder_red_evidence_invalid")
        _timestamp(self.patch_applied_at, "builder_patch_evidence_invalid")
        paths = _strict_sorted_unique(self.changed_paths, code="builder_changed_paths_invalid")
        if not paths:
            raise BuilderError("builder_changed_paths_invalid")
        for value in paths:
            _path(value, "builder_changed_paths_invalid")
        tools = _strict_sorted_unique(self.tools, code="builder_tools_invalid")
        if not tools or any(_TOOL_RE.fullmatch(tool) is None for tool in tools):
            raise BuilderError("builder_tools_invalid")
        for value, code in (
            (self.patch_bytes, "builder_patch_size_invalid"),
            (self.elapsed_seconds, "builder_elapsed_invalid"),
            (self.cost_microdollars, "builder_cost_invalid"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise BuilderError(code)
        if self.patch_bytes == 0:
            raise BuilderError("builder_patch_size_invalid")
        if self.attempt == 1 and self.finding_digest is not None:
            raise BuilderError("builder_initial_finding_invalid")
        if self.attempt > 1:
            _digest(self.finding_digest, "builder_repair_finding_required")


@dataclass(frozen=True, slots=True)
class CandidateSandboxResult:
    """One bounded candidate execution, expressed as an exclusive terminal payload."""

    attempt: BuildAttemptEvidence
    candidate_packet: SealedCandidate | None
    disposition: Literal["repairable", "rejected", "inconclusive"] | None
    evidence_digest: str | None
    next_hypothesis: ProductHypothesis | None

    def __post_init__(self) -> None:
        if type(self.attempt) is not BuildAttemptEvidence:
            raise BuilderError("builder_sandbox_result_invalid")
        packet_result = (
            type(self.candidate_packet) is SealedCandidate
            and self.disposition is None
            and self.evidence_digest is None
            and self.next_hypothesis is None
        )
        unsuccessful_result = (
            self.candidate_packet is None
            and self.disposition in {"repairable", "rejected", "inconclusive"}
            and isinstance(self.evidence_digest, str)
            and type(self.next_hypothesis) is ProductHypothesis
        )
        if sum((packet_result, unsuccessful_result)) != 1:
            raise BuilderError("builder_sandbox_result_invalid")
        if unsuccessful_result:
            _digest(self.evidence_digest, "builder_learning_evidence_invalid")


class CandidateSandbox(Protocol):
    def execute(
        self,
        *,
        invocation: BuilderModelInvocation,
        limits: BuilderLimits,
        environment: dict[str, str],
        prior_attempts: tuple[BuildAttemptEvidence, ...],
    ) -> CandidateSandboxResult:
        """Execute one bounded, credential-free candidate attempt."""


class CandidatePacketStore(Protocol):
    def persist(
        self,
        *,
        registration: BuilderPreregistration,
        packet: SealedCandidate,
    ) -> bool:
        """Durably persist a complete packet without GitHub publication authority."""


def validate_attempts(
    limits: BuilderLimits,
    attempts: tuple[BuildAttemptEvidence, ...],
) -> tuple[BuildAttemptEvidence, ...]:
    """Validate RED-first evidence and at most two materially changed repairs."""
    if type(limits) is not BuilderLimits or not isinstance(attempts, tuple) or not attempts:
        raise BuilderError("builder_attempts_invalid")
    if any(type(item) is not BuildAttemptEvidence for item in attempts):
        raise BuilderError("builder_attempts_invalid")
    if len(attempts) > 3:
        raise BuilderError("builder_repair_budget_exceeded")
    elapsed = 0
    cost = 0
    patch_bytes = 0
    changed_paths: set[str] = set()
    action_digests: set[str] = set()
    patch_digests: set[str] = set()
    for expected_attempt, item in enumerate(attempts, 1):
        if item.attempt != expected_attempt:
            raise BuilderError("builder_attempt_sequence_invalid")
        if _timestamp(item.red_observed_at, "builder_red_evidence_invalid") >= _timestamp(
            item.patch_applied_at, "builder_patch_evidence_invalid"
        ):
            raise BuilderError("builder_red_evidence_order_invalid")
        if item.action_digest in action_digests or item.patch_digest in patch_digests:
            raise BuilderError("builder_unchanged_retry_forbidden")
        action_digests.add(item.action_digest)
        patch_digests.add(item.patch_digest)
        for path in item.changed_paths:
            if any(_inside(surface, path) for surface in limits.forbidden_paths):
                raise BuilderError("builder_patch_path_forbidden")
            if not any(_inside(surface, path) for surface in limits.allowed_paths):
                raise BuilderError("builder_patch_path_outside_scope")
            changed_paths.add(path)
        if len(changed_paths) > limits.max_changed_paths:
            raise BuilderError("builder_changed_path_budget_exceeded")
        if any(tool not in limits.allowed_tools for tool in item.tools):
            raise BuilderError("builder_tool_forbidden")
        patch_bytes += item.patch_bytes
        if patch_bytes > limits.max_patch_bytes:
            raise BuilderError("builder_patch_budget_exceeded")
        elapsed += item.elapsed_seconds
        cost += item.cost_microdollars
        if elapsed > limits.max_elapsed_seconds:
            raise BuilderError("builder_elapsed_budget_exceeded")
        if cost > limits.max_cost_microdollars:
            raise BuilderError("builder_cost_budget_exceeded")
    return attempts


def credential_free_candidate_environment(
    source: dict[str, str],
    *,
    sandbox_home: Path,
) -> dict[str, str]:
    """Build a fixed allowlisted environment instead of filtering an inherited credential set."""
    if (
        type(source) is not dict
        or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in source.items()
        )
        or not isinstance(sandbox_home, Path)
        or not sandbox_home.is_absolute()
        or sandbox_home.is_symlink()
    ):
        raise BuilderError("builder_candidate_environment_invalid")
    language = source.get("LANG", "C.UTF-8")
    path = source.get("PATH", os.defpath)
    ci = source.get("CI", "true")
    for value in (language, path, ci, os.fspath(sandbox_home)):
        if not value or "\x00" in value or len(value.encode("utf-8")) > 4096:
            raise BuilderError("builder_candidate_environment_invalid")
    environment = {
        "CI": ci,
        "HOME": os.fspath(sandbox_home),
        "LANG": language,
        "LC_ALL": language,
        "PATH": path,
    }
    if any(marker in key.casefold() for key in environment for marker in _CREDENTIAL_MARKERS):
        raise BuilderError("builder_candidate_environment_invalid")
    return environment


@dataclass(frozen=True, slots=True)
class RepairRequest:
    experiment_id: str
    repair_number: int
    next_attempt: int
    finding_digest: str
    changed_action_digest: str
    patch_digest: str

    def __post_init__(self) -> None:
        _identifier(self.experiment_id, "builder_experiment_id_invalid")
        if (
            isinstance(self.repair_number, bool)
            or not isinstance(self.repair_number, int)
            or not 1 <= self.repair_number <= 2
            or self.next_attempt != self.repair_number + 1
        ):
            raise BuilderError("builder_repair_budget_exceeded")
        _digest(self.finding_digest, "builder_repair_finding_required")
        _digest(self.changed_action_digest, "builder_action_digest_invalid")
        _digest(self.patch_digest, "builder_patch_digest_invalid")

    @property
    def attempt(self) -> int:
        """Compatibility alias for the attempt the request authorizes."""
        return self.next_attempt


@dataclass(frozen=True, slots=True)
class RetainedLearning:
    experiment_id: str
    disposition: Literal["rejected", "inconclusive"]
    hypothesis_digest: str
    work_digest: str
    evidence_digest: str
    next_hypothesis_id: str
    next_capability_family: str

    def __post_init__(self) -> None:
        _identifier(self.experiment_id, "builder_experiment_id_invalid")
        if self.disposition not in {"rejected", "inconclusive"}:
            raise BuilderError("builder_learning_disposition_invalid")
        for name in ("hypothesis_digest", "work_digest", "evidence_digest"):
            _digest(getattr(self, name), f"builder_{name}_invalid")
        _identifier(self.next_hypothesis_id, "builder_next_hypothesis_invalid")
        _identifier(self.next_capability_family, "builder_capability_family_invalid")


@dataclass(frozen=True, slots=True)
class BuilderTerminalResult:
    outcome: str
    experiment_id: str
    candidate_packet_digest: str | None
    experimental_ref: str | None
    repair_request: RepairRequest | None
    retained_learning: RetainedLearning | None
    live_validated: bool
    production_eligible: bool
    next_safe_node: str

    OUTCOMES: ClassVar[frozenset[str]] = frozenset(
        {"candidate_packet", "experimental_publication", "repair_request", "retained_learning"}
    )

    def __post_init__(self) -> None:
        if self.outcome not in self.OUTCOMES:
            raise BuilderError("builder_report_only_terminal_forbidden")
        _identifier(self.experiment_id, "builder_experiment_id_invalid")
        if self.live_validated is not False or self.production_eligible is not False:
            raise BuilderError("builder_experimental_claim_invalid")
        if not isinstance(self.next_safe_node, str) or not self.next_safe_node:
            raise BuilderError("builder_next_safe_node_invalid")
        payloads = {
            "candidate_packet": (
                self.candidate_packet_digest is not None
                and self.experimental_ref is None
                and self.repair_request is None
                and self.retained_learning is None
            ),
            "experimental_publication": (
                self.candidate_packet_digest is not None
                and self.experimental_ref is not None
                and self.repair_request is None
                and self.retained_learning is None
            ),
            "repair_request": (
                self.candidate_packet_digest is None
                and self.experimental_ref is None
                and type(self.repair_request) is RepairRequest
                and self.retained_learning is None
            ),
            "retained_learning": (
                self.candidate_packet_digest is None
                and self.experimental_ref is None
                and self.repair_request is None
                and type(self.retained_learning) is RetainedLearning
            ),
        }
        if not payloads[self.outcome]:
            raise BuilderError("builder_terminal_payload_invalid")
        if self.candidate_packet_digest is not None:
            _digest(self.candidate_packet_digest, "builder_candidate_packet_digest_invalid")


def _candidate_matches(
    registration: BuilderPreregistration,
    packet: SealedCandidate,
) -> bool:
    return (
        type(registration) is BuilderPreregistration
        and type(packet) is SealedCandidate
        and packet.experiment_id == registration.experiment_id
        and packet.manifest_digest == registration.manifest_digest
        and packet.parent_commit == registration.parent_commit
        and packet.all_checks_passed
        and packet.changed_path_count > 0
        and bool(packet.checks)
    )


def complete_candidate_packet(
    registration: BuilderPreregistration,
    packet: SealedCandidate,
) -> BuilderTerminalResult:
    if not _candidate_matches(registration, packet):
        raise BuilderError("builder_candidate_packet_mismatch")
    return BuilderTerminalResult(
        outcome="candidate_packet",
        experiment_id=registration.experiment_id,
        candidate_packet_digest=packet.digest,
        experimental_ref=None,
        repair_request=None,
        retained_learning=None,
        live_validated=False,
        production_eligible=False,
        next_safe_node="publish_experimental",
    )


def complete_experimental_publication(
    registration: BuilderPreregistration,
    packet: SealedCandidate,
    publication: ExperimentalPublicationDecision,
) -> BuilderTerminalResult:
    if not _candidate_matches(registration, packet):
        raise BuilderError("builder_candidate_packet_mismatch")
    expected_ref = f"refs/heads/experimental/{registration.experiment_id}"
    if (
        type(publication) is not ExperimentalPublicationDecision
        or publication.outcome not in {"push_branch", "record_existing_exact_branch"}
        or publication.ref != expected_ref
        or publication.candidate_commit != packet.candidate_commit
        or publication.candidate_packet_digest != packet.digest
        or not isinstance(publication.candidate_tree, str)
        or _COMMIT_RE.fullmatch(publication.candidate_tree) is None
    ):
        raise BuilderError("builder_publication_mismatch")
    return BuilderTerminalResult(
        outcome="experimental_publication",
        experiment_id=registration.experiment_id,
        candidate_packet_digest=packet.digest,
        experimental_ref=publication.ref,
        repair_request=None,
        retained_learning=None,
        live_validated=False,
        production_eligible=False,
        next_safe_node="dispatch_validation",
    )


def request_changed_repair(
    registration: BuilderPreregistration,
    prior_attempts: tuple[BuildAttemptEvidence, ...],
    changed_attempt: BuildAttemptEvidence,
) -> BuilderTerminalResult:
    if (
        type(registration) is not BuilderPreregistration
        or not isinstance(prior_attempts, tuple)
        or not prior_attempts
        or any(type(item) is not BuildAttemptEvidence for item in prior_attempts)
        or type(changed_attempt) is not BuildAttemptEvidence
        or changed_attempt.attempt != len(prior_attempts) + 1
        or changed_attempt.attempt > 3
        or changed_attempt.finding_digest is None
    ):
        raise BuilderError("builder_repair_request_invalid")
    if changed_attempt.action_digest in {item.action_digest for item in prior_attempts} or (
        changed_attempt.patch_digest in {item.patch_digest for item in prior_attempts}
    ):
        raise BuilderError("builder_unchanged_retry_forbidden")
    repair = RepairRequest(
        experiment_id=registration.experiment_id,
        repair_number=changed_attempt.attempt - 1,
        next_attempt=changed_attempt.attempt,
        finding_digest=changed_attempt.finding_digest,
        changed_action_digest=changed_attempt.action_digest,
        patch_digest=changed_attempt.patch_digest,
    )
    return BuilderTerminalResult(
        outcome="repair_request",
        experiment_id=registration.experiment_id,
        candidate_packet_digest=None,
        experimental_ref=None,
        repair_request=repair,
        retained_learning=None,
        live_validated=False,
        production_eligible=False,
        next_safe_node=f"repair:{registration.experiment_id}:{changed_attempt.attempt}",
    )


def terminalize_unsuccessful_attempt(
    *,
    registration: BuilderPreregistration,
    current: ProductHypothesis,
    limits: BuilderLimits,
    attempts: tuple[BuildAttemptEvidence, ...],
    finding_digest: str,
    disposition: Literal["repairable", "rejected", "inconclusive"],
    next_hypothesis: ProductHypothesis,
) -> BuilderTerminalResult:
    """Turn repairable, unchanged, or exhausted work into an explicit durable next node."""
    _digest(finding_digest, "builder_repair_finding_required")
    try:
        validate_attempts(limits, attempts)
    except BuilderError as error:
        if error.code != "builder_unchanged_retry_forbidden":
            raise
        retained_disposition: Literal["rejected", "inconclusive"] = (
            "inconclusive" if disposition == "repairable" else disposition
        )
        return retain_builder_learning(
            registration=registration,
            current=current,
            disposition=retained_disposition,
            evidence_digest=finding_digest,
            next_hypothesis=next_hypothesis,
        )
    if len(attempts) >= 3 or disposition != "repairable":
        retained_disposition = "inconclusive" if disposition == "repairable" else disposition
        return retain_builder_learning(
            registration=registration,
            current=current,
            disposition=retained_disposition,
            evidence_digest=finding_digest,
            next_hypothesis=next_hypothesis,
        )
    if not attempts:
        raise BuilderError("builder_attempts_invalid")
    latest = attempts[-1]
    repair_number = len(attempts)
    repair = RepairRequest(
        experiment_id=registration.experiment_id,
        repair_number=repair_number,
        next_attempt=repair_number + 1,
        finding_digest=finding_digest,
        changed_action_digest=latest.action_digest,
        patch_digest=latest.patch_digest,
    )
    return BuilderTerminalResult(
        outcome="repair_request",
        experiment_id=registration.experiment_id,
        candidate_packet_digest=None,
        experimental_ref=None,
        repair_request=repair,
        retained_learning=None,
        live_validated=False,
        production_eligible=False,
        next_safe_node=f"repair:{registration.experiment_id}:{repair.next_attempt}",
    )


def retain_builder_learning(
    *,
    registration: BuilderPreregistration,
    current: ProductHypothesis,
    disposition: Literal["rejected", "inconclusive"],
    evidence_digest: str,
    next_hypothesis: ProductHypothesis,
) -> BuilderTerminalResult:
    if (
        type(registration) is not BuilderPreregistration
        or type(current) is not ProductHypothesis
        or type(next_hypothesis) is not ProductHypothesis
        or registration.hypothesis_digest != current.digest
        or registration.work_digest != current.work_digest
    ):
        raise BuilderError("builder_learning_identity_mismatch")
    _digest(evidence_digest, "builder_learning_evidence_invalid")
    if (
        next_hypothesis.hypothesis_id == current.hypothesis_id
        or next_hypothesis.capability_family == current.capability_family
        or next_hypothesis.digest == current.digest
        or next_hypothesis.work_digest == current.work_digest
    ):
        raise BuilderError("builder_next_safe_node_not_distinct")
    learning = RetainedLearning(
        experiment_id=registration.experiment_id,
        disposition=disposition,
        hypothesis_digest=current.digest,
        work_digest=current.work_digest,
        evidence_digest=evidence_digest,
        next_hypothesis_id=next_hypothesis.hypothesis_id,
        next_capability_family=next_hypothesis.capability_family,
    )
    return BuilderTerminalResult(
        outcome="retained_learning",
        experiment_id=registration.experiment_id,
        candidate_packet_digest=None,
        experimental_ref=None,
        repair_request=None,
        retained_learning=learning,
        live_validated=False,
        production_eligible=False,
        next_safe_node=f"register_hypothesis:{next_hypothesis.hypothesis_id}",
    )


class AutonomousProductBuilder:
    """Own one complete protected build transition from selection to a terminal result."""

    __slots__ = ("_gateway", "_packet_store", "_registrar", "_sandbox")

    def __init__(
        self,
        *,
        registrar: BuilderPreregistrar,
        gateway: BuilderModelGateway,
        sandbox: CandidateSandbox,
        packet_store: CandidatePacketStore,
    ) -> None:
        if (
            not callable(getattr(registrar, "register", None))
            or not callable(getattr(gateway, "evaluate", None))
            or not callable(getattr(sandbox, "execute", None))
            or not callable(getattr(packet_store, "persist", None))
        ):
            raise BuilderError("builder_runtime_boundary_invalid")
        self._registrar = registrar
        self._gateway = gateway
        self._sandbox = sandbox
        self._packet_store = packet_store

    def run(
        self,
        *,
        snapshot: BuilderSnapshot,
        hypotheses: tuple[ProductHypothesis, ...],
        manifest: ExperimentManifest,
        limits: BuilderLimits,
        prompt: str,
        attempt: int,
        prior_attempts: tuple[BuildAttemptEvidence, ...],
        source_environment: dict[str, str],
        sandbox_home: Path,
    ) -> BuilderTerminalResult:
        """Run exactly one preregistered model and sandbox attempt, then terminalize it."""
        if not isinstance(prior_attempts, tuple) or any(
            type(item) is not BuildAttemptEvidence for item in prior_attempts
        ):
            raise BuilderError("builder_attempts_invalid")
        if attempt != len(prior_attempts) + 1 or len(prior_attempts) > 2:
            raise BuilderError("builder_attempt_sequence_invalid")
        if prior_attempts:
            validate_attempts(limits, prior_attempts)
        selection = select_hypothesis(snapshot, hypotheses)
        invocation = preregister_and_call_model(
            selection=selection,
            manifest=manifest,
            snapshot=snapshot,
            limits=limits,
            registrar=self._registrar,
            gateway=self._gateway,
            prompt=prompt,
            attempt=attempt,
        )
        environment = credential_free_candidate_environment(
            source_environment,
            sandbox_home=sandbox_home,
        )
        try:
            result = self._sandbox.execute(
                invocation=invocation,
                limits=limits,
                environment=environment,
                prior_attempts=prior_attempts,
            )
        except Exception as error:
            raise BuilderError("builder_candidate_execution_failed") from error
        if type(result) is not CandidateSandboxResult:
            raise BuilderError("builder_sandbox_result_invalid")
        if result.candidate_packet is not None:
            validate_attempts(limits, (*prior_attempts, result.attempt))
            terminal = complete_candidate_packet(invocation.registration, result.candidate_packet)
            try:
                persisted = self._packet_store.persist(
                    registration=invocation.registration,
                    packet=result.candidate_packet,
                )
            except Exception as error:
                raise BuilderError("builder_candidate_packet_persistence_failed") from error
            if persisted is not True:
                raise BuilderError("builder_candidate_packet_persistence_failed")
            return terminal
        if (
            result.disposition is None
            or result.evidence_digest is None
            or result.next_hypothesis is None
        ):
            raise BuilderError("builder_sandbox_result_invalid")
        return terminalize_unsuccessful_attempt(
            registration=invocation.registration,
            current=selection.selected,
            limits=limits,
            attempts=(*prior_attempts, result.attempt),
            finding_digest=result.evidence_digest,
            disposition=result.disposition,
            next_hypothesis=result.next_hypothesis,
        )


if __name__ == "__main__":
    from carl_bench.product_builder_runtime import main

    raise SystemExit(main())
