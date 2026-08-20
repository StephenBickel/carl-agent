"""Protected-parent harness for bounded, wiring-only Carl capability probes.

The probes in this module are deterministic contract checks.  Until a real,
credential-isolated ACP execution is bound to the result, the public
promotion disposition is always ineligible.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import pwd
import re
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from carl_bench.canonical import canonical_json_bytes

_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MAX_CONTRACT_BYTES = 1_048_576
_MAX_BINARY_BYTES = 512 * 1_048_576
_LIVE_GATE_REASON = "live_acp_credential_missing"


class CloudHarnessError(ValueError):
    """Stable harness failure that does not disclose subject output or paths."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _require_int(value: object, *, code: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise CloudHarnessError(code)
    return value


def _require_bool(value: object, *, code: str) -> bool:
    if not isinstance(value, bool):
        raise CloudHarnessError(code)
    return value


def _regular_file(path: Path, *, code: str, maximum_bytes: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CloudHarnessError(code) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size > maximum_bytes
    ):
        raise CloudHarnessError(code)
    return metadata


def _hash_regular_file(path: Path, *, code: str, maximum_bytes: int) -> str:
    before = _regular_file(path, code=code, maximum_bytes=maximum_bytes)
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(64 * 1024):
                total += len(chunk)
                if total > maximum_bytes:
                    raise CloudHarnessError(code)
                digest.update(chunk)
        after = path.lstat()
    except CloudHarnessError:
        raise
    except OSError as error:
        raise CloudHarnessError(code) from error
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mode)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mode):
        raise CloudHarnessError(code)
    return digest.hexdigest()


def _load_contract(path: Path, *, kind: str) -> tuple[dict[str, Any], str]:
    digest = _hash_regular_file(
        path, code=f"{kind}_contract_invalid", maximum_bytes=_MAX_CONTRACT_BYTES
    )
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CloudHarnessError(f"{kind}_contract_invalid") from error
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise CloudHarnessError(f"{kind}_contract_invalid")
    return value, digest


def _validate_binary(path: Path) -> str:
    metadata = _regular_file(path, code="subject_binary_invalid", maximum_bytes=_MAX_BINARY_BYTES)
    if metadata.st_mode & 0o111 == 0:
        raise CloudHarnessError("subject_binary_invalid")
    return _hash_regular_file(path, code="subject_binary_invalid", maximum_bytes=_MAX_BINARY_BYTES)


@dataclass(frozen=True, slots=True)
class _Probe:
    probe_id: str
    argv: tuple[str, ...]
    expected_exit: int
    stdout_contains: tuple[str, ...]
    stdout_regex: str | None
    timeout_seconds: int


@dataclass(frozen=True, slots=True)
class AttemptObservation:
    attempt: int
    exit_code: int | None
    stdout: str
    stderr: str
    passed: bool
    timed_out: bool
    output_overflow: bool

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "exit_code": self.exit_code,
            "output_overflow": self.output_overflow,
            "passed": self.passed,
            "stderr": self.stderr,
            "stdout": self.stdout,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    probe_id: str
    argv: tuple[str, ...]
    attempts: int
    exit_code: int | None
    stdout: str
    stderr: str
    passed: bool
    timed_out: bool
    output_overflow: bool
    attempt_observations: tuple[AttemptObservation, ...]

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "attempts": self.attempts,
            "attempt_observations": [
                item.to_canonical_dict() for item in self.attempt_observations
            ],
            "exit_code": self.exit_code,
            "output_overflow": self.output_overflow,
            "passed": self.passed,
            "probe_id": self.probe_id,
            "stderr": self.stderr,
            "stdout": self.stdout,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True, slots=True)
class SubjectResult:
    commit: str
    binary_digest: str
    score_basis_points: int
    observations: tuple[ProbeObservation, ...]

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "binary_digest": self.binary_digest,
            "commit": self.commit,
            "observations": [item.to_canonical_dict() for item in self.observations],
            "score_basis_points": self.score_basis_points,
        }


@dataclass(frozen=True, slots=True)
class CloudHarnessResult:
    mode: str
    immutable_inputs: dict[str, str]
    parent: SubjectResult
    candidate: SubjectResult
    gain_basis_points: int
    contract_eligible: bool
    contract_disposition: str
    contract_reasons: tuple[str, ...]
    eligible: bool = False
    disposition: str = "insufficient_evidence"
    reasons: tuple[str, ...] = (_LIVE_GATE_REASON,)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate.to_canonical_dict(),
            "contract_disposition": self.contract_disposition,
            "contract_eligible": self.contract_eligible,
            "contract_reasons": list(self.contract_reasons),
            "disposition": self.disposition,
            "eligible": self.eligible,
            "gain_basis_points": self.gain_basis_points,
            "immutable_inputs": dict(sorted(self.immutable_inputs.items())),
            "kind": "protected_carl_pair_evidence",
            "mode": self.mode,
            "parent": self.parent.to_canonical_dict(),
            "reasons": list(self.reasons),
            "schema_version": 1,
        }


def _parse_contracts(
    *,
    experiment_path: Path,
    task_set_path: Path,
    metric_pack_path: Path,
    policy_path: Path,
) -> tuple[
    dict[str, Any],
    tuple[_Probe, ...],
    int,
    dict[str, int],
    dict[str, Any],
    dict[str, str],
]:
    experiment, experiment_digest = _load_contract(experiment_path, kind="experiment")
    task_set, task_set_digest = _load_contract(task_set_path, kind="task_set")
    metric_pack, metric_pack_digest = _load_contract(metric_pack_path, kind="metric_pack")
    policy, policy_digest = _load_contract(policy_path, kind="policy")

    if task_set.get("adapter") != "trusted-carl-cli-v1":
        raise CloudHarnessError("task_set_adapter_invalid")
    attempts = _require_int(
        task_set.get("attempts"), code="task_set_attempts_invalid", minimum=1, maximum=5
    )
    raw_probes = task_set.get("probes")
    if not isinstance(raw_probes, list) or not 1 <= len(raw_probes) <= 64:
        raise CloudHarnessError("task_set_probes_invalid")
    probes: list[_Probe] = []
    probe_ids: list[str] = []
    for value in raw_probes:
        if not isinstance(value, dict):
            raise CloudHarnessError("task_set_probe_invalid")
        probe_id = value.get("id")
        if not isinstance(probe_id, str) or not _ID_RE.fullmatch(probe_id):
            raise CloudHarnessError("task_set_probe_invalid")
        argv = value.get("argv")
        if (
            not isinstance(argv, list)
            or not 1 <= len(argv) <= 16
            or any(not isinstance(item, str) or len(item.encode("utf-8")) > 256 for item in argv)
        ):
            raise CloudHarnessError("task_set_probe_invalid")
        contains = value.get("stdout_contains", [])
        if not isinstance(contains, list) or any(
            not isinstance(item, str) or len(item.encode("utf-8")) > 512 for item in contains
        ):
            raise CloudHarnessError("task_set_probe_invalid")
        stdout_regex = value.get("stdout_regex")
        if stdout_regex is not None:
            if not isinstance(stdout_regex, str) or len(stdout_regex.encode("utf-8")) > 512:
                raise CloudHarnessError("task_set_probe_invalid")
            try:
                re.compile(stdout_regex)
            except re.error as error:
                raise CloudHarnessError("task_set_probe_invalid") from error
        probes.append(
            _Probe(
                probe_id=probe_id,
                argv=tuple(argv),
                expected_exit=_require_int(
                    value.get("expected_exit"),
                    code="task_set_probe_invalid",
                    minimum=0,
                    maximum=255,
                ),
                stdout_contains=tuple(contains),
                stdout_regex=stdout_regex,
                timeout_seconds=_require_int(
                    value.get("timeout_seconds"),
                    code="task_set_probe_invalid",
                    minimum=1,
                    maximum=30,
                ),
            )
        )
        probe_ids.append(probe_id)
    if len(set(probe_ids)) != len(probe_ids):
        raise CloudHarnessError("task_set_probe_identity_invalid")

    weights = metric_pack.get("probe_weights")
    if metric_pack.get("algorithm") != "weighted-binary-probes-v1" or not isinstance(weights, dict):
        raise CloudHarnessError("metric_pack_invalid")
    if set(weights) != set(probe_ids):
        raise CloudHarnessError("metric_probe_identity_mismatch")
    parsed_weights = {
        key: _require_int(value, code="metric_pack_invalid", minimum=1, maximum=10_000)
        for key, value in weights.items()
    }

    groups: list[set[str]] = []
    for field in ("affected_probe_ids", "guard_probe_ids", "held_out_probe_ids"):
        identifiers = experiment.get(field)
        if (
            not isinstance(identifiers, list)
            or any(not isinstance(item, str) for item in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or not set(identifiers).issubset(probe_ids)
        ):
            raise CloudHarnessError("experiment_probe_identity_mismatch")
        groups.append(set(identifiers))
    overlaps = any(groups[index] & groups[other] for index in range(3) for other in range(index))
    if not groups[0] or overlaps:
        raise CloudHarnessError("experiment_probe_identity_mismatch")
    if not isinstance(experiment.get("experiment_id"), str) or not isinstance(
        experiment.get("objective"), str
    ):
        raise CloudHarnessError("experiment_contract_invalid")

    policy_fields = {
        "maximum_payload_bytes": (4_096, 1_048_576),
        "maximum_probe_output_bytes": (256, 65_536),
        "minimum_gain_basis_points": (0, 10_000),
        "soak_minimum_score_basis_points": (0, 10_000),
    }
    for field, (minimum, maximum) in policy_fields.items():
        _require_int(
            policy.get(field),
            code="policy_contract_invalid",
            minimum=minimum,
            maximum=maximum,
        )
    for field in (
        "require_affected_improvement",
        "require_guard_non_regression",
        "require_held_out_non_regression",
    ):
        _require_bool(policy.get(field), code="policy_contract_invalid")
    required_groups = (
        (0, "require_affected_improvement"),
        (1, "require_guard_non_regression"),
        (2, "require_held_out_non_regression"),
    )
    if any(policy[gate] and not groups[index] for index, gate in required_groups):
        raise CloudHarnessError("experiment_required_probe_group_empty")

    return (
        experiment,
        tuple(probes),
        attempts,
        parsed_weights,
        policy,
        {
            "experiment": experiment_digest,
            "task_set": task_set_digest,
            "metric_pack": metric_pack_digest,
            "policy": policy_digest,
        },
    )


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()


def _bounded_process(
    binary: Path,
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    output_limit: int,
    subject_identity: tuple[int, int] | None,
) -> tuple[int | None, bytes, bytes, bool, bool]:
    demote = None
    if subject_identity is not None:
        uid, gid = subject_identity

        def demote() -> None:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)

    try:
        process = subprocess.Popen(
            [os.fspath(binary), *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            preexec_fn=demote,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CloudHarnessError("subject_binary_execution_failed") from error
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    overflow = False
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            _terminate(process)
        events = selector.select(max(0.0, min(remaining, 0.1)) if not timed_out else 0.1)
        for key, _ in events:
            stream = key.fileobj
            try:
                chunk = os.read(stream.fileno(), 16 * 1024)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(stream)
                continue
            target = streams[stream]
            available = max(0, output_limit - sum(len(value) for value in streams.values()))
            target.extend(chunk[:available])
            if len(chunk) > available:
                overflow = True
                _terminate(process)
        if process.poll() is not None and not events:
            for stream in tuple(streams):
                try:
                    chunk = os.read(stream.fileno(), 16 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    with contextlib.suppress(KeyError):
                        selector.unregister(stream)
                    continue
                target = streams[stream]
                available = max(0, output_limit - sum(len(value) for value in streams.values()))
                target.extend(chunk[:available])
                if len(chunk) > available:
                    overflow = True
        if timed_out or overflow:
            _terminate(process)
    try:
        exit_code = process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        _terminate(process)
        exit_code = process.wait(timeout=1)
    return (
        exit_code,
        bytes(streams[process.stdout]),
        bytes(streams[process.stderr]),
        timed_out,
        overflow,
    )


def _observe(
    binary: Path,
    probe: _Probe,
    *,
    attempts: int,
    output_limit: int,
    subject_identity: tuple[int, int] | None,
) -> ProbeObservation:
    all_passed = True
    any_timeout = False
    any_overflow = False
    final_exit: int | None = None
    final_stdout = b""
    final_stderr = b""
    attempt_observations: list[AttemptObservation] = []
    for attempt in range(1, attempts + 1):
        final_exit, final_stdout, final_stderr, timed_out, overflow = _bounded_process(
            binary,
            probe.argv,
            timeout_seconds=probe.timeout_seconds,
            output_limit=output_limit,
            subject_identity=subject_identity,
        )
        stdout = final_stdout.decode("utf-8", errors="replace")
        passed = (
            not timed_out
            and not overflow
            and final_exit == probe.expected_exit
            and all(value in stdout for value in probe.stdout_contains)
            and (probe.stdout_regex is None or re.search(probe.stdout_regex, stdout) is not None)
        )
        all_passed = all_passed and passed
        any_timeout = any_timeout or timed_out
        any_overflow = any_overflow or overflow
        attempt_observations.append(
            AttemptObservation(
                attempt=attempt,
                exit_code=final_exit,
                stdout=stdout,
                stderr=final_stderr.decode("utf-8", errors="replace"),
                passed=passed,
                timed_out=timed_out,
                output_overflow=overflow,
            )
        )
    return ProbeObservation(
        probe_id=probe.probe_id,
        argv=probe.argv,
        attempts=attempts,
        exit_code=final_exit,
        stdout=final_stdout.decode("utf-8", errors="replace"),
        stderr=final_stderr.decode("utf-8", errors="replace"),
        passed=all_passed,
        timed_out=any_timeout,
        output_overflow=any_overflow,
        attempt_observations=tuple(attempt_observations),
    )


def _score(observations: Sequence[ProbeObservation], weights: dict[str, int]) -> int:
    total = sum(weights.values())
    passed = sum(weights[item.probe_id] for item in observations if item.passed)
    return (passed * 10_000 + total // 2) // total


def _subject(
    binary: Path,
    *,
    commit: str,
    digest: str,
    probes: tuple[_Probe, ...],
    attempts: int,
    output_limit: int,
    weights: dict[str, int],
    subject_identity: tuple[int, int] | None,
) -> SubjectResult:
    observations = tuple(
        _observe(
            binary,
            probe,
            attempts=attempts,
            output_limit=output_limit,
            subject_identity=subject_identity,
        )
        for probe in probes
    )
    if _validate_binary(binary) != digest:
        raise CloudHarnessError("subject_binary_changed")
    return SubjectResult(
        commit=commit,
        binary_digest=digest,
        score_basis_points=_score(observations, weights),
        observations=observations,
    )


def _group_score(subject: SubjectResult, identifiers: set[str], weights: dict[str, int]) -> int:
    selected = tuple(item for item in subject.observations if item.probe_id in identifiers)
    return _score(selected, {key: value for key, value in weights.items() if key in identifiers})


def evaluate_carl_pair(
    *,
    parent_binary: Path,
    candidate_binary: Path,
    parent_commit: str,
    candidate_commit: str,
    experiment_path: Path,
    task_set_path: Path,
    metric_pack_path: Path,
    policy_path: Path,
    mode: str,
    parent_identity: tuple[int, int] | None = None,
    candidate_identity: tuple[int, int] | None = None,
) -> CloudHarnessResult:
    """Run protected probes against exact binaries and emit bounded canonical evidence."""
    if not _COMMIT_RE.fullmatch(parent_commit) or not _COMMIT_RE.fullmatch(candidate_commit):
        raise CloudHarnessError("subject_commit_invalid")
    if mode not in {"improvement", "soak"}:
        raise CloudHarnessError("harness_mode_invalid")
    if (parent_identity is None) != (candidate_identity is None):
        raise CloudHarnessError("subject_identity_invalid")
    if parent_identity is not None and (
        parent_identity == candidate_identity
        or os.geteuid() in {parent_identity[0], candidate_identity[0]}
    ):
        raise CloudHarnessError("subject_identity_not_isolated")
    parent_binary = Path(parent_binary)
    candidate_binary = Path(candidate_binary)
    digests = (_validate_binary(parent_binary), _validate_binary(candidate_binary))
    experiment, probes, attempts, weights, policy, immutable_inputs = _parse_contracts(
        experiment_path=Path(experiment_path),
        task_set_path=Path(task_set_path),
        metric_pack_path=Path(metric_pack_path),
        policy_path=Path(policy_path),
    )
    output_limit = policy["maximum_probe_output_bytes"]
    parent = _subject(
        parent_binary,
        commit=parent_commit,
        digest=digests[0],
        probes=probes,
        attempts=attempts,
        output_limit=output_limit,
        weights=weights,
        subject_identity=parent_identity,
    )
    candidate = _subject(
        candidate_binary,
        commit=candidate_commit,
        digest=digests[1],
        probes=probes,
        attempts=attempts,
        output_limit=output_limit,
        weights=weights,
        subject_identity=candidate_identity,
    )
    gain = candidate.score_basis_points - parent.score_basis_points
    reasons: list[str] = []
    if any(item.output_overflow for item in (*parent.observations, *candidate.observations)):
        reasons.append("probe_output_overflow")
    if any(item.timed_out for item in (*parent.observations, *candidate.observations)):
        reasons.append("probe_timeout")
    if gain < 0:
        reasons.append("aggregate_regression")
    if gain < policy["minimum_gain_basis_points"]:
        reasons.append("minimum_gain_not_met")
    affected = set(experiment["affected_probe_ids"])
    guards = set(experiment["guard_probe_ids"])
    held_out = set(experiment["held_out_probe_ids"])
    if policy["require_affected_improvement"] and _group_score(
        candidate, affected, weights
    ) <= _group_score(parent, affected, weights):
        reasons.append("affected_probe_not_improved")
    if policy["require_guard_non_regression"] and _group_score(
        candidate, guards, weights
    ) < _group_score(parent, guards, weights):
        reasons.append("guard_probe_regression")
    if policy["require_held_out_non_regression"] and _group_score(
        candidate, held_out, weights
    ) < _group_score(parent, held_out, weights):
        reasons.append("held_out_probe_regression")
    reasons = list(dict.fromkeys(reasons))
    result = CloudHarnessResult(
        mode=mode,
        immutable_inputs=immutable_inputs,
        parent=parent,
        candidate=candidate,
        gain_basis_points=gain,
        contract_eligible=not reasons,
        contract_disposition="improvement" if not reasons else "rejected",
        contract_reasons=tuple(reasons),
    )
    if len(canonical_json_bytes(result.to_canonical_dict())) > policy["maximum_payload_bytes"]:
        raise CloudHarnessError("evidence_payload_too_large")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run protected bounded Carl pair probes")
    parser.add_argument("--parent-binary", type=Path, required=True)
    parser.add_argument("--candidate-binary", type=Path, required=True)
    parser.add_argument("--parent-commit", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--experiment", type=Path, required=True)
    parser.add_argument("--task-set", type=Path, required=True)
    parser.add_argument("--metric-pack", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--mode", choices=("improvement", "soak"), required=True)
    parser.add_argument("--parent-uid", required=True)
    parser.add_argument("--candidate-uid", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if os.geteuid() != 0:
        raise CloudHarnessError("protected_harness_identity_required")
    try:
        parent_account = pwd.getpwnam(args.parent_uid)
        candidate_account = pwd.getpwnam(args.candidate_uid)
    except KeyError as error:
        raise CloudHarnessError("subject_identity_invalid") from error
    result = evaluate_carl_pair(
        parent_binary=args.parent_binary,
        candidate_binary=args.candidate_binary,
        parent_commit=args.parent_commit,
        candidate_commit=args.candidate_commit,
        experiment_path=args.experiment,
        task_set_path=args.task_set,
        metric_pack_path=args.metric_pack,
        policy_path=args.policy,
        mode=args.mode,
        parent_identity=(parent_account.pw_uid, parent_account.pw_gid),
        candidate_identity=(candidate_account.pw_uid, candidate_account.pw_gid),
    )
    payload = canonical_json_bytes(result.to_canonical_dict()) + b"\n"
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("xb") as target:
            target.write(payload)
    except OSError as error:
        raise CloudHarnessError("evidence_output_invalid") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
