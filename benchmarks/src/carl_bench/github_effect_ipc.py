"""Credential-free canonical protocol for the protected GitHub effect service."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Literal

REQUEST_DOMAIN = "carl.github-effect.ipc.request.v1"
RESPONSE_DOMAIN = "carl.github-effect.ipc.response.v1"
MAX_FRAME_BYTES = 262_144

_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_EFFECT_RE = re.compile(r"^cloud-effect-[0-9a-f]{64}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_BRANCH_RE = re.compile(r"^(?:experimental|revert)/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_WORKFLOW_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.ya?ml$")
_REQUIRED_CHECKS = [
    "Quality",
    "Benchmark contracts",
    "Test (ubuntu-latest)",
    "Test (macos-latest)",
    "Test (windows-latest)",
]
_FORBIDDEN_FIELDS = frozenset(
    {
        "authorization",
        "authority",
        "body",
        "claim_expires_at",
        "claim_id",
        "claim_revision",
        "graphql",
        "headers",
        "method",
        "path",
        "query",
        "state_controller",
        "token",
        "transport",
        "url",
        "variables",
    }
)


class GitHubEffectProtocolError(ValueError):
    """Stable, redacted protocol failure."""


class GitHubEffectOperation(str, Enum):
    CREATE_EXPERIMENTAL_REF = "create_experimental_ref"
    CREATE_PULL_REQUEST = "create_pull_request"
    CREATE_REVERT_PULL_REQUEST = "create_revert_pull_request"
    CREATE_REVERT_REF = "create_revert_ref"
    DISPATCH_WORKFLOW = "dispatch_workflow"
    ENABLE_PULL_REQUEST_AUTO_MERGE = "enable_pull_request_auto_merge"
    MARK_PULL_REQUEST_READY = "mark_pull_request_ready"
    OBSERVE_REQUIRED_CHECKS = "observe_required_checks"
    UPDATE_PULL_REQUEST = "update_pull_request"


_REQUEST_FIELDS = frozenset(
    {
        "command_key",
        "domain",
        "effect_key",
        "occurred_at",
        "operation",
        "parameters",
        "request_key",
        "schema_version",
    }
)
_RESPONSE_FIELDS = frozenset(
    {
        "domain",
        "error_code",
        "observed_at",
        "request_digest",
        "result",
        "retry_not_before",
        "schema_version",
        "status",
    }
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GitHubEffectProtocolError("github_effect_ipc_duplicate_key")
        result[key] = value
    return result


def _decode(payload: bytes, code: str) -> dict[str, object]:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_FRAME_BYTES:
        raise GitHubEffectProtocolError(code)
    try:
        value = json.loads(payload, object_pairs_hook=_pairs_object)
    except (UnicodeDecodeError, json.JSONDecodeError, GitHubEffectProtocolError) as error:
        raise GitHubEffectProtocolError(code) from error
    if type(value) is not dict or _canonical(value) != payload:
        raise GitHubEffectProtocolError(code)
    return value


def _utc(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) > 32:
        raise GitHubEffectProtocolError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise GitHubEffectProtocolError(code) from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise GitHubEffectProtocolError(code)
    return value


def _text(value: object, *, maximum: int, nonempty: bool = True) -> str:
    if (
        not isinstance(value, str)
        or (nonempty and not value)
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
    ):
        raise ValueError
    return value


def _exact(parameters: object, fields: set[str]) -> dict[str, object]:
    if type(parameters) is not dict or set(parameters) != fields:
        raise ValueError
    if _FORBIDDEN_FIELDS & set(parameters):
        raise ValueError
    return parameters


def _sha(value: object) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise ValueError
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError
    return value


def _identifier(value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError
    return value


def _pull_identity(parameters: dict[str, object]) -> None:
    _identifier(parameters["promotion_id"])
    if parameters["base_branch"] != "main":
        raise ValueError
    if (
        not isinstance(parameters["head_branch"], str)
        or _BRANCH_RE.fullmatch(parameters["head_branch"]) is None
    ):
        raise ValueError
    _sha(parameters["head_sha"])


def _pull_target(parameters: dict[str, object]) -> None:
    _pull_identity(parameters)
    number = parameters["number"]
    if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
        raise ValueError


def _validate_parameters(operation: GitHubEffectOperation, value: object) -> dict[str, object]:
    try:
        if operation is GitHubEffectOperation.OBSERVE_REQUIRED_CHECKS:
            result = _exact(value, {"head_sha", "required_checks"})
            _sha(result["head_sha"])
            checks = result["required_checks"]
            if checks != _REQUIRED_CHECKS:
                raise ValueError
        elif operation is GitHubEffectOperation.CREATE_EXPERIMENTAL_REF:
            result = _exact(value, {"branch", "candidate_commit", "experiment_id"})
            experiment_id = _identifier(result["experiment_id"])
            if result["branch"] != f"experimental/{experiment_id}":
                raise ValueError
            _sha(result["candidate_commit"])
        elif operation in {
            GitHubEffectOperation.CREATE_PULL_REQUEST,
            GitHubEffectOperation.CREATE_REVERT_PULL_REQUEST,
        }:
            if operation is GitHubEffectOperation.CREATE_PULL_REQUEST:
                result = _exact(
                    value,
                    {
                        "base_branch",
                        "draft",
                        "head_branch",
                        "head_sha",
                        "promotion_id",
                        "pull_request_body",
                        "title",
                    },
                )
                if result["draft"] is not True:
                    raise ValueError
            else:
                result = _exact(
                    value,
                    {
                        "base_branch",
                        "draft",
                        "expected_restored_tree",
                        "head_branch",
                        "promotion_id",
                        "promotion_merge_commit",
                        "pull_request_body",
                        "revert_candidate_commit",
                        "title",
                    },
                )
                if result["draft"] is not False:
                    raise ValueError
                result = dict(result)
                result["head_sha"] = result["revert_candidate_commit"]
                _sha(result["promotion_merge_commit"])
                _sha(result["expected_restored_tree"])
            _pull_identity(result)
            _text(result["title"], maximum=256)
            _text(result["pull_request_body"], maximum=8_192)
            if operation is GitHubEffectOperation.CREATE_REVERT_PULL_REQUEST:
                result.pop("head_sha")
        elif operation is GitHubEffectOperation.UPDATE_PULL_REQUEST:
            result = _exact(
                value,
                {
                    "base_branch",
                    "head_branch",
                    "head_sha",
                    "number",
                    "promotion_id",
                    "pull_request_body",
                    "title",
                },
            )
            _pull_target(result)
            _text(result["title"], maximum=256)
            _text(result["pull_request_body"], maximum=8_192)
        elif operation in {
            GitHubEffectOperation.MARK_PULL_REQUEST_READY,
            GitHubEffectOperation.ENABLE_PULL_REQUEST_AUTO_MERGE,
        }:
            fields = {"base_branch", "head_branch", "head_sha", "number", "promotion_id"}
            if operation is GitHubEffectOperation.ENABLE_PULL_REQUEST_AUTO_MERGE:
                fields.add("merge_method")
            result = _exact(value, fields)
            _pull_target(result)
            if (
                operation is GitHubEffectOperation.ENABLE_PULL_REQUEST_AUTO_MERGE
                and result["merge_method"] != "squash"
            ):
                raise ValueError
        elif operation is GitHubEffectOperation.CREATE_REVERT_REF:
            result = _exact(
                value,
                {
                    "branch",
                    "expected_restored_tree",
                    "promotion_id",
                    "promotion_merge_commit",
                    "revert_candidate_commit",
                },
            )
            promotion_id = _identifier(result["promotion_id"])
            if result["branch"] != f"revert/{promotion_id}":
                raise ValueError
            for name in (
                "expected_restored_tree",
                "promotion_merge_commit",
                "revert_candidate_commit",
            ):
                _sha(result[name])
        elif operation is GitHubEffectOperation.DISPATCH_WORKFLOW:
            result = _exact(
                value,
                {
                    "candidate_commit",
                    "experiment_digest",
                    "metric_pack_digest",
                    "parent_commit",
                    "policy_digest",
                    "repository",
                    "task_set_digest",
                    "workflow_blob_digest",
                    "workflow_file",
                    "workflow_revision",
                },
            )
            if result["repository"] != "StephenBickel/carl-agent":
                raise ValueError
            if (
                not isinstance(result["workflow_file"], str)
                or _WORKFLOW_RE.fullmatch(result["workflow_file"]) is None
            ):
                raise ValueError
            for name in ("candidate_commit", "parent_commit", "workflow_revision"):
                _sha(result[name])
            for name in (
                "experiment_digest",
                "metric_pack_digest",
                "policy_digest",
                "task_set_digest",
                "workflow_blob_digest",
            ):
                _digest(result[name])
        else:  # pragma: no cover - exhaustive enum guard
            raise ValueError
    except (KeyError, TypeError, ValueError) as error:
        raise GitHubEffectProtocolError("github_effect_ipc_request_invalid") from error
    return result


_RESULT_FIELDS = {
    "WorkflowDispatchSnapshot": {
        "attempt_key",
        "command_occurred_at",
        "effect_key",
        "head_sha",
        "observed_at",
        "repository",
        "request_key",
        "run_id",
        "status",
        "workflow_file",
        "workflow_revision",
    },
    "GitReferenceSnapshot": {
        "command_occurred_at",
        "commit_sha",
        "effect_key",
        "observed_at",
        "ref",
        "repository",
        "request_key",
        "status",
    },
    "PullRequestEffectSnapshot": {
        "auto_merge_enabled",
        "base_branch",
        "command_occurred_at",
        "draft",
        "effect_key",
        "head_branch",
        "head_sha",
        "number",
        "observed_at",
        "pull_request_body",
        "pull_request_url",
        "repository",
        "request_key",
        "state",
        "status",
        "title",
    },
    "RequiredChecksSnapshot": {
        "checks",
        "command_occurred_at",
        "complete",
        "effect_key",
        "head_sha",
        "observed_at",
        "repository",
        "request_key",
    },
}


def _contains_forbidden_field(value: object) -> bool:
    if type(value) is dict:
        return bool(_FORBIDDEN_FIELDS & set(value)) or any(
            _contains_forbidden_field(item) for item in value.values()
        )
    if type(value) is list:
        return any(_contains_forbidden_field(item) for item in value)
    return False


def _validate_response_result(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != {"result_type", "value"}:
        raise ValueError
    result_type = value["result_type"]
    document = value["value"]
    if (
        not isinstance(result_type, str)
        or result_type not in _RESULT_FIELDS
        or type(document) is not dict
        or set(document) != _RESULT_FIELDS[result_type]
        or _contains_forbidden_field(document)
    ):
        raise ValueError
    if document.get("repository") != "StephenBickel/carl-agent":
        raise ValueError
    _utc(document.get("command_occurred_at"), "github_effect_ipc_response_invalid")
    _utc(document.get("observed_at"), "github_effect_ipc_response_invalid")
    if (
        not isinstance(document.get("request_key"), str)
        or _KEY_RE.fullmatch(document["request_key"]) is None
    ):
        raise ValueError
    if (
        not isinstance(document.get("effect_key"), str)
        or _EFFECT_RE.fullmatch(document["effect_key"]) is None
    ):
        raise ValueError
    if result_type == "WorkflowDispatchSnapshot":
        if document["status"] not in {"dispatched", "reconciled", "uncertain"}:
            raise ValueError
        if (
            not isinstance(document["workflow_file"], str)
            or _WORKFLOW_RE.fullmatch(document["workflow_file"]) is None
        ):
            raise ValueError
        _sha(document["workflow_revision"])
        if document["head_sha"] is not None:
            _sha(document["head_sha"])
        run_id = document["run_id"]
        if run_id is not None and (
            isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0
        ):
            raise ValueError
    elif result_type == "GitReferenceSnapshot":
        if document["status"] not in {"created", "reconciled", "uncertain"}:
            raise ValueError
        _sha(document["commit_sha"])
        _text(document["ref"], maximum=256)
    elif result_type == "PullRequestEffectSnapshot":
        if document["status"] not in {"created", "updated", "reconciled", "uncertain"}:
            raise ValueError
        if document["state"] not in {"open", "closed"}:
            raise ValueError
        if (
            isinstance(document["number"], bool)
            or not isinstance(document["number"], int)
            or document["number"] <= 0
            or document["base_branch"] != "main"
            or not isinstance(document["head_branch"], str)
            or _BRANCH_RE.fullmatch(document["head_branch"]) is None
        ):
            raise ValueError
        _sha(document["head_sha"])
        for name in ("auto_merge_enabled", "draft"):
            if not isinstance(document[name], bool):
                raise ValueError
        _text(document["title"], maximum=256)
        _text(document["pull_request_body"], maximum=8_192, nonempty=False)
        _text(document["pull_request_url"], maximum=512)
    else:
        _sha(document["head_sha"])
        if not isinstance(document["complete"], bool) or type(document["checks"]) is not list:
            raise ValueError
        if len(document["checks"]) > 64:
            raise ValueError
        for check in document["checks"]:
            if type(check) is not dict or set(check) != {
                "app_id",
                "conclusion",
                "name",
                "status",
            }:
                raise ValueError
            if (
                isinstance(check["app_id"], bool)
                or not isinstance(check["app_id"], int)
                or check["app_id"] <= 0
                or (check["conclusion"] is not None and not isinstance(check["conclusion"], str))
            ):
                raise ValueError
            _text(check["name"], maximum=128)
            _text(check["status"], maximum=32)
    return value


@dataclass(frozen=True, slots=True)
class GitHubEffectRequest:
    schema_version: int
    domain: str
    request_key: str
    effect_key: str
    command_key: str
    operation: GitHubEffectOperation
    occurred_at: str
    parameters: dict[str, object]

    @classmethod
    def from_canonical_dict(cls, value: object) -> GitHubEffectRequest:
        code = "github_effect_ipc_request_invalid"
        try:
            if type(value) is not dict or set(value) != _REQUEST_FIELDS:
                raise ValueError
            if value["schema_version"] != 1 or value["domain"] != REQUEST_DOMAIN:
                raise ValueError
            for name in ("request_key", "command_key"):
                if not isinstance(value[name], str) or _KEY_RE.fullmatch(value[name]) is None:
                    raise ValueError
            if (
                not isinstance(value["effect_key"], str)
                or _EFFECT_RE.fullmatch(value["effect_key"]) is None
            ):
                raise ValueError
            operation = GitHubEffectOperation(value["operation"])
            occurred_at = _utc(value["occurred_at"], code)
            parameters = _validate_parameters(operation, value["parameters"])
        except (KeyError, TypeError, ValueError) as error:
            raise GitHubEffectProtocolError(code) from error
        return cls(
            schema_version=1,
            domain=REQUEST_DOMAIN,
            request_key=value["request_key"],
            effect_key=value["effect_key"],
            command_key=value["command_key"],
            operation=operation,
            occurred_at=occurred_at,
            parameters=parameters,
        )

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "command_key": self.command_key,
            "domain": self.domain,
            "effect_key": self.effect_key,
            "occurred_at": self.occurred_at,
            "operation": self.operation.value,
            "parameters": self.parameters,
            "request_key": self.request_key,
            "schema_version": self.schema_version,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(encode_request_bytes(self)).hexdigest()


@dataclass(frozen=True, slots=True)
class GitHubEffectResponse:
    schema_version: int
    domain: str
    status: Literal["completed", "rejected", "retry_scheduled", "uncertain"]
    request_digest: str
    observed_at: str
    result: dict[str, object] | None
    retry_not_before: str | None
    error_code: str | None

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "error_code": self.error_code,
            "observed_at": self.observed_at,
            "request_digest": self.request_digest,
            "result": self.result,
            "retry_not_before": self.retry_not_before,
            "schema_version": self.schema_version,
            "status": self.status,
        }


def encode_request_bytes(request: GitHubEffectRequest) -> bytes:
    if not isinstance(request, GitHubEffectRequest):
        raise GitHubEffectProtocolError("github_effect_ipc_request_invalid")
    validated = GitHubEffectRequest.from_canonical_dict(request.to_canonical_dict())
    payload = _canonical(validated.to_canonical_dict())
    if len(payload) > MAX_FRAME_BYTES:
        raise GitHubEffectProtocolError("github_effect_ipc_request_invalid")
    return payload


def decode_request_bytes(payload: bytes) -> GitHubEffectRequest:
    code = "github_effect_ipc_request_invalid"
    try:
        return GitHubEffectRequest.from_canonical_dict(_decode(payload, code))
    except GitHubEffectProtocolError as error:
        raise GitHubEffectProtocolError(code) from error


def encode_response_bytes(response: GitHubEffectResponse) -> bytes:
    if not isinstance(response, GitHubEffectResponse):
        raise GitHubEffectProtocolError("github_effect_ipc_response_invalid")
    validated = decode_response_bytes(_canonical(response.to_canonical_dict()))
    return _canonical(validated.to_canonical_dict())


def decode_response_bytes(payload: bytes) -> GitHubEffectResponse:
    code = "github_effect_ipc_response_invalid"
    try:
        value = _decode(payload, code)
        if set(value) != _RESPONSE_FIELDS or value["schema_version"] != 1:
            raise ValueError
        if value["domain"] != RESPONSE_DOMAIN or value["status"] not in {
            "completed",
            "rejected",
            "retry_scheduled",
            "uncertain",
        }:
            raise ValueError
        request_digest = _digest(value["request_digest"])
        observed_at = _utc(value["observed_at"], code)
        result = value["result"]
        retry = value["retry_not_before"]
        error = value["error_code"]
        if result is not None:
            if len(_canonical(result)) > 131_072:
                raise ValueError
            result = _validate_response_result(result)
        if retry is not None:
            retry = _utc(retry, code)
        if error is not None and (
            not isinstance(error, str) or re.fullmatch(r"github_[a-z0-9_]{1,95}", error) is None
        ):
            raise ValueError
        status = value["status"]
        if status == "completed" and (result is None or retry is not None or error is not None):
            raise ValueError
        if status == "rejected" and (result is not None or retry is not None or error is None):
            raise ValueError
        if status == "retry_scheduled" and (
            result is not None or retry is None or error is not None
        ):
            raise ValueError
        if status == "uncertain" and (result is not None or retry is not None or error is not None):
            raise ValueError
    except (KeyError, TypeError, ValueError, GitHubEffectProtocolError) as exc:
        raise GitHubEffectProtocolError(code) from exc
    return GitHubEffectResponse(
        schema_version=1,
        domain=RESPONSE_DOMAIN,
        status=status,
        request_digest=request_digest,
        observed_at=observed_at,
        result=result,
        retry_not_before=retry,
        error_code=error,
    )
