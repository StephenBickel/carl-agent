"""Controller-owned provenance attestations for promotion benchmark runs."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.models import RunManifest, Scorecard
from carl_bench.report import summarize_run

_DOMAIN = b"carl-bench/run-attestation/v1\x00"
_POLICY_VERSION = "phase3-benchmark-attestation-v1"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_ROLES = frozenset({"baseline", "candidate"})


class RunAttestationError(ValueError):
    """A stable failure for missing, forged, or inconsistent run provenance."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _key_id(key: bytes) -> str:
    return hashlib.sha256(b"carl-bench/attestation-key/v1\x00" + key).hexdigest()


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or not 32 <= len(key) <= 64:
        raise RunAttestationError("attestation_key_invalid")


def _task_identity_values(task_identities: tuple[dict[str, str], ...]) -> list[dict[str, str]]:
    values = [dict(identity) for identity in task_identities]
    expected = {"digest", "task_id", "track"}
    if not values or any(set(value) != expected for value in values):
        raise RunAttestationError("attestation_task_identity_invalid")
    if values != sorted(values, key=lambda value: value["task_id"].encode("utf-8")):
        raise RunAttestationError("attestation_task_identity_order_invalid")
    if len({value["task_id"] for value in values}) != len(values):
        raise RunAttestationError("attestation_task_identity_duplicate")
    return values


@dataclass(frozen=True, slots=True)
class RunAttestation:
    schema_version: int
    key_id: str
    payload: dict[str, Any]
    mac: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise RunAttestationError("attestation_schema_invalid")
        if not isinstance(self.key_id, str) or not _DIGEST_RE.fullmatch(self.key_id):
            raise RunAttestationError("attestation_key_id_invalid")
        if not isinstance(self.payload, dict):
            raise RunAttestationError("attestation_payload_invalid")
        if not isinstance(self.mac, str) or not _DIGEST_RE.fullmatch(self.mac):
            raise RunAttestationError("attestation_mac_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "mac": self.mac,
            "payload": self.payload,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> RunAttestation:
        if not isinstance(value, dict) or set(value) != {
            "key_id",
            "mac",
            "payload",
            "schema_version",
        }:
            raise RunAttestationError("attestation_keys_invalid")
        try:
            return cls(**value)
        except TypeError as error:
            raise RunAttestationError("attestation_invalid") from error


def attest_run(
    *,
    experiment_id: str,
    role: str,
    checkout_tree_digest: str,
    manifest: RunManifest,
    scorecard: Scorecard,
    task_identities: tuple[dict[str, str], ...],
    attempts: int,
    key: bytes,
) -> RunAttestation:
    """Sign only internally constructed run evidence; never arbitrary caller JSON."""
    _validate_key(key)
    if not isinstance(experiment_id, str) or not _ID_RE.fullmatch(experiment_id):
        raise RunAttestationError("attestation_experiment_invalid")
    if role not in _ROLES:
        raise RunAttestationError("attestation_role_invalid")
    if not isinstance(checkout_tree_digest, str) or not _COMMIT_RE.fullmatch(checkout_tree_digest):
        raise RunAttestationError("attestation_tree_invalid")
    if not isinstance(manifest, RunManifest) or not isinstance(scorecard, Scorecard):
        raise RunAttestationError("attestation_run_invalid")
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 10:
        raise RunAttestationError("attestation_attempts_invalid")
    canonical_scorecard = summarize_run(manifest, manifest.trials)
    if scorecard != canonical_scorecard:
        raise RunAttestationError("attestation_scorecard_not_canonical")
    identities = _task_identity_values(task_identities)
    adapter_pairs = {(trial.adapter_id, trial.adapter_version) for trial in manifest.trials}
    if len(adapter_pairs) != 1:
        raise RunAttestationError("attestation_adapter_identity_invalid")
    adapter_id, adapter_version = next(iter(adapter_pairs))
    task_set_digest = _digest(identities)
    payload: dict[str, Any] = {
        "benchmark_config": {
            "adapter_id": adapter_id,
            "adapter_version": adapter_version,
            "attempts": attempts,
            "effort": manifest.effort,
            "league": manifest.league,
            "model": manifest.model,
            "seed": manifest.seed,
            "task_set_digest": task_set_digest,
        },
        "checkout_tree_digest": checkout_tree_digest,
        "experiment_id": experiment_id,
        "policy_version": _POLICY_VERSION,
        "role": role,
        "run_manifest": manifest.to_public_dict(),
        "run_manifest_digest": _digest(manifest.to_public_dict()),
        "schema_version": 1,
        "scorecard": scorecard.to_public_dict(),
        "scorecard_digest": _digest(scorecard.to_public_dict()),
        "subject_commit": manifest.subject_commit,
        "task_identities": identities,
    }
    return RunAttestation(
        schema_version=1,
        key_id=_key_id(key),
        payload=payload,
        mac=hmac.new(key, _DOMAIN + canonical_json_bytes(payload), hashlib.sha256).hexdigest(),
    )


def verify_attested_scorecard(
    value: Any,
    *,
    key: bytes,
    expected_experiment_id: str,
    expected_role: str,
    expected_subject_commit: str,
) -> Scorecard:
    """Verify provenance and reconstruct the scorecard from its signed run manifest."""
    _validate_key(key)
    attestation = RunAttestation.from_canonical_dict(value)
    if not hmac.compare_digest(attestation.key_id, _key_id(key)):
        raise RunAttestationError("attestation_key_id_mismatch")
    expected_mac = hmac.new(
        key, _DOMAIN + canonical_json_bytes(attestation.payload), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(attestation.mac, expected_mac):
        raise RunAttestationError("attestation_mac_mismatch")

    payload = attestation.payload
    if set(payload) != {
        "benchmark_config",
        "checkout_tree_digest",
        "experiment_id",
        "policy_version",
        "role",
        "run_manifest",
        "run_manifest_digest",
        "schema_version",
        "scorecard",
        "scorecard_digest",
        "subject_commit",
        "task_identities",
    }:
        raise RunAttestationError("attestation_payload_keys_invalid")
    if payload["schema_version"] != 1 or payload["policy_version"] != _POLICY_VERSION:
        raise RunAttestationError("attestation_policy_invalid")
    if payload["experiment_id"] != expected_experiment_id:
        raise RunAttestationError("attestation_experiment_mismatch")
    if payload["role"] != expected_role or expected_role not in _ROLES:
        raise RunAttestationError("attestation_role_mismatch")
    if payload["subject_commit"] != expected_subject_commit:
        raise RunAttestationError("attestation_subject_mismatch")
    if not isinstance(payload["checkout_tree_digest"], str) or not _COMMIT_RE.fullmatch(
        payload["checkout_tree_digest"]
    ):
        raise RunAttestationError("attestation_tree_invalid")
    if payload["run_manifest_digest"] != _digest(payload["run_manifest"]):
        raise RunAttestationError("attestation_manifest_digest_mismatch")
    if payload["scorecard_digest"] != _digest(payload["scorecard"]):
        raise RunAttestationError("attestation_scorecard_digest_mismatch")

    from carl_bench.candidate_evidence import (  # Avoid an import cycle at module load.
        CandidateEvidenceError,
        run_manifest_from_public,
        scorecard_from_public,
    )

    try:
        manifest = run_manifest_from_public(payload["run_manifest"])
        scorecard = scorecard_from_public(payload["scorecard"])
    except CandidateEvidenceError as error:
        raise RunAttestationError("attestation_run_invalid") from error
    if manifest.subject_commit != expected_subject_commit:
        raise RunAttestationError("attestation_manifest_subject_mismatch")
    if scorecard.subject_commit != expected_subject_commit:
        raise RunAttestationError("attestation_scorecard_subject_mismatch")
    if scorecard.run_digest != payload["run_manifest_digest"]:
        raise RunAttestationError("attestation_run_digest_mismatch")
    try:
        canonical_scorecard = summarize_run(manifest, manifest.trials)
    except (TypeError, ValueError) as error:
        raise RunAttestationError("attestation_run_invalid") from error
    if scorecard != canonical_scorecard:
        raise RunAttestationError("attestation_scorecard_not_canonical")

    identities_value = payload["task_identities"]
    if not isinstance(identities_value, list):
        raise RunAttestationError("attestation_task_identity_invalid")
    identities = _task_identity_values(tuple(identities_value))
    derived_identities = sorted(
        {(trial.task_id, trial.task_digest, trial.track) for trial in manifest.trials},
        key=lambda value: value[0].encode("utf-8"),
    )
    if identities != [
        {"digest": digest, "task_id": task_id, "track": track}
        for task_id, digest, track in derived_identities
    ]:
        raise RunAttestationError("attestation_task_identity_mismatch")

    config = payload["benchmark_config"]
    if not isinstance(config, dict) or set(config) != {
        "adapter_id",
        "adapter_version",
        "attempts",
        "effort",
        "league",
        "model",
        "seed",
        "task_set_digest",
    }:
        raise RunAttestationError("attestation_config_invalid")
    if config["task_set_digest"] != _digest(identities):
        raise RunAttestationError("attestation_task_set_digest_mismatch")
    pairs = {(trial.adapter_id, trial.adapter_version) for trial in manifest.trials}
    if pairs != {(config["adapter_id"], config["adapter_version"])}:
        raise RunAttestationError("attestation_adapter_identity_mismatch")
    if (
        config["league"] != manifest.league
        or config["model"] != manifest.model
        or config["effort"] != manifest.effort
        or config["seed"] != manifest.seed
    ):
        raise RunAttestationError("attestation_config_mismatch")
    attempts = config["attempts"]
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 10:
        raise RunAttestationError("attestation_attempts_invalid")
    for task_id, _, _ in derived_identities:
        task_trials = tuple(trial for trial in manifest.trials if trial.task_id == task_id)
        if tuple(trial.attempt for trial in task_trials) != tuple(range(1, attempts + 1)):
            raise RunAttestationError("attestation_attempt_population_mismatch")
        if tuple(trial.seed for trial in task_trials) != tuple(
            manifest.seed + attempt - 1 for attempt in range(1, attempts + 1)
        ):
            raise RunAttestationError("attestation_seed_population_mismatch")
    return scorecard
