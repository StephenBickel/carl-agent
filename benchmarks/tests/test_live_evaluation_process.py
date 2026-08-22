from __future__ import annotations

import base64
import hashlib
import json
import multiprocessing
import os
import shutil
import socket
import struct
import tempfile
from configparser import ConfigParser
from importlib.metadata import entry_points
from inspect import signature
from pathlib import Path
from queue import Empty

import pytest

from carl_bench.live_evaluation_authority import (
    LiveEvaluationAuthorityError,
    ProtectedArchiveVersion,
    ProtectedEvidenceLocator,
    ProtectedLiveEvaluationAuthority,
)
from carl_bench.live_evaluation_client import (
    LiveEvaluationClientError,
    LiveEvaluationSocketClient,
)
from carl_bench.live_evaluation_ipc import (
    LiveEvaluationProtocolError,
    ProtectedJoinRequest,
    decode_request_bytes,
)
from carl_bench.live_gateway_authority import ProtectedModelGatewayServer


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _locator(kind: str, label: str, version: str) -> ProtectedEvidenceLocator:
    digest = _digest(label)
    return ProtectedEvidenceLocator(
        kind=kind,
        object_key=f"carl-evidence/v1/sha256/{digest[:2]}/{digest}",
        version_id=version,
        payload_digest=digest,
    )


def _request() -> ProtectedJoinRequest:
    return ProtectedJoinRequest(
        schema_version=1,
        request_digest=_digest("join-request"),
        deterministic_locator=_locator("protected_deterministic_pair", "deterministic", "det-v1"),
        live_locator=_locator("protected_live_pair", "live", "live-v1"),
    )


def _listener(path: Path) -> socket.socket:
    value = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    value.bind(os.fspath(path))
    os.chmod(path, 0o600)
    value.listen(8)
    return value


def _socket_root() -> Path:
    temporary_root = Path("/private/tmp") if Path("/tmp").is_symlink() else Path("/tmp")
    value = Path(tempfile.mkdtemp(prefix="carl-live-", dir=temporary_root))
    value.chmod(0o700)
    return value


class _PinnedRejectingAuthority:
    def combine(self, **kwargs: object) -> object:
        del kwargs
        raise LiveEvaluationAuthorityError("pinned_child_authority")


def _serve_rejecting(
    listener: socket.socket,
    socket_path: str,
    ready: object,
) -> None:
    from datetime import UTC, datetime

    from carl_bench.live_evaluation_service import _serve_activated_listener

    _serve_activated_listener(
        listener_fd=listener.fileno(),
        socket_path=Path(socket_path),
        allowed_client_uid=os.getuid(),
        service_uid=os.getuid(),
        authority=_PinnedRejectingAuthority(),
        clock=lambda: datetime(2026, 8, 22, 12, tzinfo=UTC),
        connection_timeout_seconds=0.5,
        on_ready=ready.set,
    )


def _validate_replaced_listener(
    listener: socket.socket,
    socket_path: str,
    results: object,
) -> None:
    from carl_bench.live_evaluation_service import _validated_activated_listener

    try:
        with _validated_activated_listener(
            listener_fd=listener.fileno(),
            socket_path=Path(socket_path),
            expected_uid=os.getuid(),
        ):
            results.put("accepted")
    except RuntimeError as error:
        results.put(str(error))


def _serve_archive_read(
    listener: socket.socket,
    captured: object,
    response_payload: bytes,
) -> None:
    from carl_bench.live_archive_client import encode_archive_response_for_testing

    with listener.accept()[0] as connection:
        size = struct.unpack(">I", connection.recv(4))[0]
        request_payload = connection.recv(size)
        captured.put(request_payload)
        request = json.loads(request_payload)
        response = encode_archive_response_for_testing(
            request_digest=hashlib.sha256(request_payload).hexdigest(),
            archive=ProtectedArchiveVersion(
                object_key=request["object_key"],
                version_id=request["version_id"],
                payload=response_payload,
                checksum_sha256=hashlib.sha256(response_payload).hexdigest(),
                byte_length=len(response_payload),
                retention_mode="COMPLIANCE",
                retain_until="2027-08-22T12:00:00Z",
                created_at="2026-08-22T11:59:00Z",
            ),
        )
        connection.sendall(struct.pack(">I", len(response)) + response)


def test_join_protocol_is_canonical_and_has_no_authority_or_secret_fields() -> None:
    request = _request()
    encoded = request.to_bytes()

    assert decode_request_bytes(encoded) == request
    assert b"authority" not in encoded
    assert b"clock" not in encoded
    assert b"signing_key" not in encoded
    assert b"token" not in encoded
    assert b"gateway" not in encoded
    with pytest.raises(LiveEvaluationProtocolError):
        decode_request_bytes(encoded.replace(b'"schema_version":1', b'"schema_version":true'))
    with pytest.raises(LiveEvaluationProtocolError):
        decode_request_bytes(encoded[:-1] + b' ,"signing_key":"attacker"}')


def test_protected_service_has_a_packaged_entrypoint() -> None:
    entry = next(
        item
        for item in entry_points(group="console_scripts")
        if item.name == "carl-live-evaluation-service"
    )

    assert entry.load().__module__ == "carl_bench.live_evaluation_service"


def test_production_constructors_accept_no_caller_selected_dependencies() -> None:
    authority_parameters = signature(
        ProtectedLiveEvaluationAuthority.from_protected_process
    ).parameters
    assert set(authority_parameters) == set()
    assert set(signature(ProtectedModelGatewayServer.from_protected_process).parameters) == set()


def test_protected_service_constructs_its_pinned_archive_gateway_clock_and_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from carl_bench.live_evaluation_service import _load_protected_authority
    from carl_bench.live_execution_policy import LiveExecutionCommissioningPolicy
    from carl_bench.live_grader import ProtectedGraderBundle
    from carl_bench.live_worker_isolation import CgroupV2WorkerIsolation

    class Grader:
        def grade(self, **kwargs: object) -> int:
            del kwargs
            return 0

    class Isolation:
        def begin(self, execution_digest: str) -> object:
            del execution_digest
            return object()

    class ExecutionCommissioning:
        workers = ((62_001, 62_001), (62_002, 62_002))

        def verifies(self, receipt: object) -> bool:
            del receipt
            return True

    monkeypatch.setattr(ProtectedGraderBundle, "from_protected_process", lambda: Grader())
    monkeypatch.setattr(
        CgroupV2WorkerIsolation,
        "from_live_evaluator_process",
        lambda: Isolation(),
    )
    monkeypatch.setattr(
        LiveExecutionCommissioningPolicy,
        "from_protected_process",
        lambda *, workers: ExecutionCommissioning(),
    )

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-1234567890123456")
    for name, key in (
        ("CARL_OPENAI_PROVENANCE_KEY_B64", b"P" * 32),
        ("CARL_DETERMINISTIC_ATTESTATION_KEY_B64", b"D" * 32),
        ("CARL_LIVE_ATTESTATION_KEY_B64", b"L" * 32),
        ("CARL_LIVE_EXECUTION_KEY_B64", b"E" * 32),
        ("CARL_COMBINED_EVIDENCE_KEY_B64", b"R" * 32),
        ("CARL_GRADER_ATTESTATION_KEY_B64", b"G" * 32),
    ):
        monkeypatch.setenv(name, base64.b64encode(key).decode("ascii"))
    monkeypatch.setenv("CARL_PARENT_WORKER_UID", "62001")
    monkeypatch.setenv("CARL_PARENT_WORKER_GID", "62001")
    monkeypatch.setenv("CARL_CANDIDATE_WORKER_UID", "62002")
    monkeypatch.setenv("CARL_CANDIDATE_WORKER_GID", "62002")

    assert type(_load_protected_authority()) is ProtectedLiveEvaluationAuthority


def test_protected_service_requires_distinct_unprivileged_worker_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from carl_bench.live_evaluation_service import _load_protected_authority

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-1234567890123456")
    for name, key in (
        ("CARL_OPENAI_PROVENANCE_KEY_B64", b"P" * 32),
        ("CARL_DETERMINISTIC_ATTESTATION_KEY_B64", b"D" * 32),
        ("CARL_LIVE_ATTESTATION_KEY_B64", b"L" * 32),
        ("CARL_COMBINED_EVIDENCE_KEY_B64", b"R" * 32),
    ):
        monkeypatch.setenv(name, base64.b64encode(key).decode("ascii"))
    for name in (
        "CARL_PARENT_WORKER_UID",
        "CARL_PARENT_WORKER_GID",
        "CARL_CANDIDATE_WORKER_UID",
        "CARL_CANDIDATE_WORKER_GID",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(LiveEvaluationAuthorityError, match="live_worker_identity_missing"):
        _load_protected_authority()

    monkeypatch.setenv("CARL_PARENT_WORKER_UID", "62001")
    monkeypatch.setenv("CARL_PARENT_WORKER_GID", "62001")
    monkeypatch.setenv("CARL_CANDIDATE_WORKER_UID", "62001")
    monkeypatch.setenv("CARL_CANDIDATE_WORKER_GID", "62002")
    with pytest.raises(LiveEvaluationAuthorityError, match="live_worker_identity_invalid"):
        _load_protected_authority()


def test_live_evaluator_systemd_contract_commissions_deterministic_cgroup_isolation() -> None:
    root = Path(__file__).parents[2] / "infra/autonomy/systemd"
    service = ConfigParser(interpolation=None, strict=True)
    service.optionxform = str
    socket_unit = ConfigParser(interpolation=None, strict=True)
    socket_unit.optionxform = str

    assert service.read(root / "carl-live-evaluator.service")
    assert socket_unit.read(root / "carl-live-evaluator.socket")
    assert service["Unit"] == {
        "Description": "Carl protected live evidence evaluator",
        "After": "carl-live-gateway.service",
        "Requires": "carl-live-evaluator.socket carl-live-gateway.service",
    }
    assert service["Service"] == {
        "Type": "simple",
        "ExecStart": "/opt/carl/venv/bin/carl-live-evaluation-service",
        "EnvironmentFile": "/etc/carl/live-evaluator.env",
        "User": "root",
        "Group": "root",
        "Delegate": "pids",
        "TasksMax": "256",
        "NoNewPrivileges": "yes",
        "PrivateDevices": "yes",
        "PrivateTmp": "yes",
        "ProtectControlGroups": "no",
        "ProtectHome": "yes",
        "ProtectKernelModules": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectSystem": "strict",
        "ReadOnlyPaths": "/srv/carl/checkouts /var/lib/carl/live-gateway/state.sqlite3",
        "RestrictAddressFamilies": "AF_UNIX",
        "UMask": "0077",
    }
    assert socket_unit["Socket"] == {
        "FileDescriptorName": "live-evaluator",
        "ListenStream": "/run/carl-live-evaluator/live-evaluator.sock",
        "DirectoryMode": "0700",
        "SocketMode": "0600",
        "Service": "carl-live-evaluator.service",
    }


@pytest.mark.skipif(os.name == "nt", reason="requires Unix peer credentials")
def test_archive_reader_uses_exact_credential_free_protected_storage_read() -> None:
    from carl_bench.live_archive_client import ProtectedArchiveSocketReader

    context = multiprocessing.get_context("fork")
    socket_root = _socket_root()
    socket_path = socket_root / "archive.sock"
    listener = _listener(socket_path)
    captured = context.Queue()
    archived_payload = b'{"protected":"signed-receipt"}'
    process = context.Process(
        target=_serve_archive_read,
        args=(listener, captured, archived_payload),
    )
    process.start()
    try:
        payload_digest = hashlib.sha256(archived_payload).hexdigest()
        locator = ProtectedEvidenceLocator(
            kind="protected_live_pair",
            object_key=(f"carl-evidence/v1/sha256/{payload_digest[:2]}/{payload_digest}"),
            version_id="live-v4",
            payload_digest=payload_digest,
        )
        reader = ProtectedArchiveSocketReader._for_testing(
            socket_path=socket_path,
            expected_peer_uid=os.getuid(),
            timeout_seconds=1,
        )

        archived = reader.read_exact(locator.object_key, locator.version_id)

        request_payload = captured.get(timeout=1)
        assert json.loads(request_payload) == {
            "domain": "carl.evidence-archive.read.request.v1",
            "object_key": locator.object_key,
            "schema_version": 1,
            "version_id": locator.version_id,
        }
        assert b"credential" not in request_payload
        assert b"token" not in request_payload
        assert archived.payload == archived_payload
        assert archived.object_key == locator.object_key
        assert archived.version_id == locator.version_id
    finally:
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join(2)
        listener.close()
        shutil.rmtree(socket_root)
    assert process.exitcode == 0


@pytest.mark.parametrize("missing", ("api", "provenance"))
def test_protected_service_maps_missing_gateway_credentials_to_stable_boundary(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    from carl_bench.live_evaluation_service import _load_protected_authority

    if missing == "api":
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    else:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-1234567890123456")
    monkeypatch.delenv("CARL_OPENAI_PROVENANCE_KEY_B64", raising=False)

    with pytest.raises(LiveEvaluationAuthorityError, match="live_acp_credential_missing"):
        _load_protected_authority()


@pytest.mark.skipif(os.name == "nt", reason="requires Unix peer credentials and inherited sockets")
def test_separate_process_keeps_pinned_authority_despite_caller_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = multiprocessing.get_context("fork")
    socket_root = _socket_root()
    socket_path = socket_root / "s"
    listener = _listener(socket_path)
    ready = context.Event()
    process = context.Process(
        target=_serve_rejecting,
        args=(listener, os.fspath(socket_path), ready),
    )
    process.start()
    try:
        assert ready.wait(3)
        from carl_bench import live_evaluation_service

        monkeypatch.setattr(
            live_evaluation_service,
            "ProtectedLiveEvaluationAuthority",
            object(),
        )
        client = LiveEvaluationSocketClient._for_testing(
            socket_path=socket_path,
            expected_peer_uid=os.getuid(),
            timeout_seconds=1,
        )

        with pytest.raises(LiveEvaluationClientError, match="pinned_child_authority"):
            client.combine(_request())
    finally:
        process.terminate()
        process.join(3)
        listener.close()
        shutil.rmtree(socket_root)


@pytest.mark.skipif(os.name == "nt", reason="requires Unix inherited sockets")
def test_separate_process_rejects_replaced_supervisor_socket(tmp_path: Path) -> None:
    context = multiprocessing.get_context("fork")
    socket_root = _socket_root()
    socket_path = socket_root / "s"
    original = _listener(socket_path)
    displaced = tmp_path / "displaced.sock"
    os.replace(socket_path, displaced)
    attacker = _listener(socket_path)
    results = context.Queue()
    process = context.Process(
        target=_validate_replaced_listener,
        args=(original, os.fspath(socket_path), results),
    )
    process.start()
    process.join(3)
    try:
        assert process.exitcode == 0
        try:
            outcome = results.get(timeout=1)
        except Empty:
            pytest.fail("replacement validation produced no result")
        assert outcome == "live_evaluation_service_socket_identity_invalid"
    finally:
        original.close()
        attacker.close()
        shutil.rmtree(socket_root)
