from __future__ import annotations

import hashlib
import io
import multiprocessing
import os
import tarfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from carl_bench.canonical import canonical_json_bytes
from carl_bench.immutable_inputs import (
    EXPERIMENT_MEDIA_TYPE,
    IMPROVEMENT_TASK_SET_MEDIA_TYPE,
    IMPROVEMENT_TASK_SET_VERSION,
    MAX_SOAK_ARCHIVE_ENTRIES,
    MAX_SOAK_MEMBER_BYTES,
    METRIC_PACK_MEDIA_TYPE,
    POLICY_MEDIA_TYPE,
    REGISTRY_MEDIA_TYPE,
    SOAK_TASK_SET_MEDIA_TYPE,
    SOAK_TASK_SET_VERSION,
    ImmutableInputError,
    evaluate_soak_health,
    load_registry,
    pack_improvement_task_set,
    pack_soak_archive,
    publish_private_commitment,
    publish_public,
    resolve_entry,
    verify_soak_archive,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMITTED_REGISTRY = REPOSITORY_ROOT / "benchmarks/immutable-inputs/registry.json"


def _hold_publication_lock(entered: object, release: object) -> None:
    import carl_bench.immutable_inputs as immutable_inputs

    original = immutable_inputs._publication_lock

    @contextmanager
    def synchronized_lock(*args: object, **kwargs: object):
        with original(*args, **kwargs) as transaction:
            entered.set()  # type: ignore[attr-defined]
            if not release.wait(timeout=10):  # type: ignore[attr-defined]
                raise RuntimeError("publication test release timed out")
            yield transaction

    immutable_inputs._publication_lock = synchronized_lock


def _observe_publication_after_load(entered: object, release: object | None = None) -> None:
    import carl_bench.immutable_inputs as immutable_inputs

    def after_load() -> None:
        entered.set()  # type: ignore[attr-defined]
        if release is not None and not release.wait(timeout=10):  # type: ignore[attr-defined]
            raise RuntimeError("publication after-load test release timed out")

    immutable_inputs._publication_after_registry_load_for_test = after_load


def _publish_public_worker(
    root_text: str,
    payload: bytes,
    results: object,
    entered: object | None = None,
    release: object | None = None,
    after_load_entered: object | None = None,
    after_load_release: object | None = None,
    started: object | None = None,
) -> None:
    if entered is not None and release is not None:
        _hold_publication_lock(entered, release)
    if after_load_entered is not None:
        _observe_publication_after_load(after_load_entered, after_load_release)
    if started is not None:
        started.set()  # type: ignore[attr-defined]
    try:
        entry = publish_public(
            Path(root_text) / "registry.json",
            root=Path(root_text),
            payload=payload,
            media_type=POLICY_MEDIA_TYPE,
            media_version=1,
        )
        results.put(("ok", entry.digest))  # type: ignore[attr-defined]
    except ImmutableInputError as error:
        results.put(("error", error.code))  # type: ignore[attr-defined]


def _publish_conflicting_private_worker(
    registry_text: str,
    digest: str,
    media_type: str,
    results: object,
    after_load_entered: object,
    after_load_release: object | None = None,
    started: object | None = None,
) -> None:
    _observe_publication_after_load(after_load_entered, after_load_release)
    if started is not None:
        started.set()  # type: ignore[attr-defined]
    try:
        entry = publish_private_commitment(
            Path(registry_text),
            digest=digest,
            size_bytes=17,
            media_type=media_type,
            media_version=1,
            object_key=f"private/sha256/{digest}",
        )
        results.put(("ok", entry.media_type))  # type: ignore[attr-defined]
    except ImmutableInputError as error:
        results.put(("error", error.code))  # type: ignore[attr-defined]


def _join_publishers(processes: tuple[object, object]) -> None:
    for process in processes:
        process.join(timeout=15)  # type: ignore[attr-defined]
    try:
        assert all(not process.is_alive() for process in processes)  # type: ignore[attr-defined]
        assert all(process.exitcode == 0 for process in processes)  # type: ignore[attr-defined]
    finally:
        for process in processes:
            if process.is_alive():  # type: ignore[attr-defined]
                process.terminate()  # type: ignore[attr-defined]
                process.join(timeout=5)  # type: ignore[attr-defined]


def test_repository_commits_the_versioned_immutable_input_registry() -> None:
    assert COMMITTED_REGISTRY.is_file()
    assert load_registry(COMMITTED_REGISTRY).entries == ()


def _improvement_task_set() -> dict[str, object]:
    return {
        "schema_version": 1,
        "probes": [
            {
                "timeout_seconds": 5,
                "stdout_contains": ["carl"],
                "id": "version",
                "expected_exit": 0,
                "argv": ["--version"],
            }
        ],
        "attempts": 1,
        "adapter": "trusted-carl-cli-v1",
    }


def _write_empty_registry(root: Path) -> Path:
    public = root / "public"
    public.mkdir(parents=True)
    registry = root / "registry.json"
    registry.write_bytes(
        canonical_json_bytes({"entries": [], "media_type": REGISTRY_MEDIA_TYPE, "media_version": 1})
        + b"\n"
    )
    return registry


def _raw_tar(members: list[tarfile.TarInfo], contents: list[bytes]) -> bytes:
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for member, content in zip(members, contents, strict=True):
            archive.addfile(member, io.BytesIO(content) if member.isreg() else None)
    return target.getvalue()


def _file_member(name: str, content: bytes) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mode = 0o644
    return member


def _soak_contracts() -> tuple[bytes, bytes, bytes, bytes, dict[str, bool]]:
    check_ids = ["benchmark-smoke", "workflow-contracts"]
    experiment = canonical_json_bytes({"schema_version": 1, "soak_check_ids": check_ids})
    task_set = pack_soak_archive(
        {
            "soak-contract.json": canonical_json_bytes(
                {"check_ids": check_ids, "schema_version": 1}
            ),
            "tasks/health.json": b'{"kind":"health"}',
        }
    )
    metric_pack = canonical_json_bytes(
        {
            "algorithm": "weighted-binary-soak-v1",
            "check_weights": {"benchmark-smoke": 3, "workflow-contracts": 1},
            "schema_version": 1,
        }
    )
    policy = canonical_json_bytes(
        {
            "minimum_score_basis_points": 7000,
            "require_all_checks": False,
            "schema_version": 1,
        }
    )
    observations = {"benchmark-smoke": True, "workflow-contracts": False}
    return experiment, task_set, metric_pack, policy, observations


def test_improvement_task_set_is_strict_canonical_json_with_distinct_media_version() -> None:
    encoded = pack_improvement_task_set(_improvement_task_set())

    assert encoded == (
        b'{"adapter":"trusted-carl-cli-v1","attempts":1,"probes":['
        b'{"argv":["--version"],"expected_exit":0,"id":"version",'
        b'"stdout_contains":["carl"],"timeout_seconds":5}],"schema_version":1}'
    )
    assert IMPROVEMENT_TASK_SET_MEDIA_TYPE != SOAK_TASK_SET_MEDIA_TYPE
    assert (IMPROVEMENT_TASK_SET_MEDIA_TYPE, IMPROVEMENT_TASK_SET_VERSION) != (
        SOAK_TASK_SET_MEDIA_TYPE,
        SOAK_TASK_SET_VERSION,
    )

    smuggled = _improvement_task_set() | {"unused_policy": {"minimum": 0}}
    with pytest.raises(ImmutableInputError, match="improvement_task_set_invalid"):
        pack_improvement_task_set(smuggled)


def test_soak_archive_is_byte_deterministic_and_normalizes_all_metadata() -> None:
    first = pack_soak_archive({"z.txt": b"z", "nested/a.txt": b"a"})
    second = pack_soak_archive({"nested/a.txt": b"a", "z.txt": b"z"})

    assert first == second
    assert verify_soak_archive(first) == {"nested/a.txt": b"a", "z.txt": b"z"}
    with tarfile.open(fileobj=io.BytesIO(first), mode="r:") as archive:
        members = archive.getmembers()
    assert [member.name for member in members] == ["nested/a.txt", "z.txt"]
    assert all(member.mtime == member.uid == member.gid == 0 for member in members)
    assert all(member.uname == member.gname == "" for member in members)
    assert all(member.mode == 0o644 and member.isreg() for member in members)


@pytest.mark.parametrize("name", ("/absolute", "../traversal", "a/../../traversal"))
def test_soak_archive_rejects_absolute_and_traversal_paths(name: str) -> None:
    content = b"x"
    payload = _raw_tar([_file_member(name, content)], [content])

    with pytest.raises(ImmutableInputError, match="soak_archive_path_invalid"):
        verify_soak_archive(payload)


def test_soak_archive_rejects_duplicate_normalized_paths() -> None:
    first = b"first"
    second = b"second"
    payload = _raw_tar(
        [_file_member("café.txt", first), _file_member("café.txt", second)],
        [first, second],
    )

    with pytest.raises(ImmutableInputError, match="soak_archive_path_duplicate"):
        verify_soak_archive(payload)


@pytest.mark.parametrize("member_type", (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE))
def test_soak_archive_rejects_links_and_special_files(member_type: bytes) -> None:
    member = tarfile.TarInfo("unsafe")
    member.type = member_type
    if member_type in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
        member.linkname = "target"
    payload = _raw_tar([member], [b""])

    with pytest.raises(ImmutableInputError, match="soak_archive_entry_invalid"):
        verify_soak_archive(payload)


def test_soak_archive_rejects_count_and_size_bombs() -> None:
    count_bomb_files = {
        f"task-{index:04d}.json": b"{}" for index in range(MAX_SOAK_ARCHIVE_ENTRIES + 1)
    }
    oversized_content = b"x" * (MAX_SOAK_MEMBER_BYTES + 1)
    size_bomb_files = {"huge.bin": oversized_content}
    count_members = [_file_member(name, content) for name, content in count_bomb_files.items()]
    count_bomb_archive = _raw_tar(count_members, list(count_bomb_files.values()))
    size_bomb_archive = _raw_tar([_file_member("huge.bin", oversized_content)], [oversized_content])

    with pytest.raises(ImmutableInputError, match="soak_archive_too_many_entries"):
        pack_soak_archive(count_bomb_files)
    with pytest.raises(ImmutableInputError, match="soak_archive_member_too_large"):
        pack_soak_archive(size_bomb_files)
    with pytest.raises(ImmutableInputError, match="soak_archive_too_many_entries"):
        verify_soak_archive(count_bomb_archive)
    with pytest.raises(ImmutableInputError, match="soak_archive_member_too_large"):
        verify_soak_archive(size_bomb_archive)


def test_soak_archive_rejects_non_normalized_metadata() -> None:
    content = b"health"
    member = _file_member("health.txt", content)
    member.mtime = 1

    with pytest.raises(ImmutableInputError, match="soak_archive_entry_invalid"):
        verify_soak_archive(_raw_tar([member], [content]))


@pytest.mark.parametrize(
    ("payload", "code"),
    (
        (
            b'{"entries":[],"entries":[],"media_type":"'
            + REGISTRY_MEDIA_TYPE.encode()
            + b'","media_version":1}',
            "registry_json_invalid",
        ),
        (
            canonical_json_bytes(
                {
                    "entries": [],
                    "media_type": REGISTRY_MEDIA_TYPE,
                    "media_version": 1,
                    "unknown": True,
                }
            ),
            "registry_schema_invalid",
        ),
        (
            b'{ "entries":[],"media_type":"'
            + REGISTRY_MEDIA_TYPE.encode()
            + b'","media_version":1}',
            "registry_not_canonical",
        ),
    ),
)
def test_registry_is_duplicate_aware_unknown_field_closed_and_canonical(
    tmp_path: Path, payload: bytes, code: str
) -> None:
    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(payload)

    with pytest.raises(ImmutableInputError, match=code):
        load_registry(registry_path)


def test_public_publish_is_atomic_create_or_reconcile_and_conflicts_fail(tmp_path: Path) -> None:
    registry_path = _write_empty_registry(tmp_path)
    payload = pack_improvement_task_set(_improvement_task_set())

    first = publish_public(
        registry_path,
        root=tmp_path,
        payload=payload,
        media_type=IMPROVEMENT_TASK_SET_MEDIA_TYPE,
        media_version=IMPROVEMENT_TASK_SET_VERSION,
    )
    second = publish_public(
        registry_path,
        root=tmp_path,
        payload=payload,
        media_type=IMPROVEMENT_TASK_SET_MEDIA_TYPE,
        media_version=IMPROVEMENT_TASK_SET_VERSION,
    )

    assert first == second
    assert first.object_key == f"public/{first.digest}"
    assert (tmp_path / first.object_key).read_bytes() == payload
    assert not list((tmp_path / "public").glob(".*.tmp"))
    assert load_registry(registry_path).entries == (first,)

    with pytest.raises(ImmutableInputError, match="registry_entry_conflict"):
        publish_private_commitment(
            registry_path,
            digest=first.digest,
            size_bytes=len(payload),
            media_type=SOAK_TASK_SET_MEDIA_TYPE,
            media_version=SOAK_TASK_SET_VERSION,
            object_key=f"private/sha256/{first.digest}",
        )

    other_digest = hashlib.sha256(b"other").hexdigest()
    private = publish_private_commitment(
        registry_path,
        digest=other_digest,
        size_bytes=5,
        media_type=POLICY_MEDIA_TYPE,
        media_version=1,
        object_key="private/sha256/shared-object",
    )
    assert private.visibility == "private"
    with pytest.raises(ImmutableInputError, match="registry_object_key_conflict"):
        publish_private_commitment(
            registry_path,
            digest=hashlib.sha256(b"third").hexdigest(),
            size_bytes=5,
            media_type=POLICY_MEDIA_TYPE,
            media_version=1,
            object_key="private/sha256/shared-object",
        )


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX flock and fork")
def test_concurrent_distinct_publishers_retain_both_registry_entries(tmp_path: Path) -> None:
    registry_path = _write_empty_registry(tmp_path)
    context = multiprocessing.get_context("fork")
    results = context.Queue()
    first_loaded = context.Event()
    release_first = context.Event()
    second_started = context.Event()
    second_loaded = context.Event()
    payloads = (
        canonical_json_bytes({"policy": "first", "schema_version": 1}),
        canonical_json_bytes({"policy": "second", "schema_version": 1}),
    )
    first = context.Process(
        target=_publish_public_worker,
        args=(str(tmp_path), payloads[0], results),
        kwargs={
            "after_load_entered": first_loaded,
            "after_load_release": release_first,
        },
    )
    second = context.Process(
        target=_publish_public_worker,
        args=(str(tmp_path), payloads[1], results),
        kwargs={"after_load_entered": second_loaded, "started": second_started},
    )
    processes = (first, second)

    try:
        first.start()
        assert first_loaded.wait(timeout=10)
        second.start()
        assert second_started.wait(timeout=10)
        assert not second_loaded.wait(timeout=1)
        release_first.set()
        _join_publishers(processes)
    finally:
        release_first.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

    assert second_loaded.is_set()

    outcomes = {results.get(timeout=2) for _ in processes}
    expected_digests = {hashlib.sha256(payload).hexdigest() for payload in payloads}
    assert outcomes == {("ok", digest) for digest in expected_digests}
    assert {entry.digest for entry in load_registry(registry_path).entries} == expected_digests


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX flock and fork")
def test_concurrent_conflicting_publishers_have_one_winner_and_one_conflict(
    tmp_path: Path,
) -> None:
    registry_path = _write_empty_registry(tmp_path)
    context = multiprocessing.get_context("fork")
    results = context.Queue()
    first_loaded = context.Event()
    release_first = context.Event()
    second_started = context.Event()
    second_loaded = context.Event()
    digest = hashlib.sha256(b"same committed private object").hexdigest()
    media_types = (EXPERIMENT_MEDIA_TYPE, POLICY_MEDIA_TYPE)
    first = context.Process(
        target=_publish_conflicting_private_worker,
        args=(str(registry_path), digest, media_types[0], results, first_loaded, release_first),
    )
    second = context.Process(
        target=_publish_conflicting_private_worker,
        args=(str(registry_path), digest, media_types[1], results, second_loaded),
        kwargs={"started": second_started},
    )
    processes = (first, second)

    try:
        first.start()
        assert first_loaded.wait(timeout=10)
        second.start()
        assert second_started.wait(timeout=10)
        assert not second_loaded.wait(timeout=1)
        release_first.set()
        _join_publishers(processes)
    finally:
        release_first.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

    assert second_loaded.is_set()

    outcomes = [results.get(timeout=2) for _ in processes]
    assert ("ok", EXPERIMENT_MEDIA_TYPE) in outcomes
    assert ("error", "registry_entry_conflict") in outcomes
    assert load_registry(registry_path).entries[0].media_type == EXPERIMENT_MEDIA_TYPE


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX no-follow open")
def test_publication_rejects_unsafe_lock_files_and_reconciles_crash_temps(
    tmp_path: Path,
) -> None:
    registry_path = _write_empty_registry(tmp_path)
    lock_path = tmp_path / ".registry.json.lock"
    victim = tmp_path / "victim"
    victim.write_bytes(b"do not touch")
    lock_path.symlink_to(victim)
    payload = canonical_json_bytes({"policy": "safe", "schema_version": 1})

    with pytest.raises(ImmutableInputError, match="registry_lock_invalid"):
        publish_public(
            registry_path,
            root=tmp_path,
            payload=payload,
            media_type=POLICY_MEDIA_TYPE,
            media_version=1,
        )
    assert victim.read_bytes() == b"do not touch"

    lock_path.unlink()
    lock_path.write_bytes(b"")
    lock_path.chmod(0o644)
    with pytest.raises(ImmutableInputError, match="registry_lock_invalid"):
        publish_public(
            registry_path,
            root=tmp_path,
            payload=payload,
            media_type=POLICY_MEDIA_TYPE,
            media_version=1,
        )
    lock_path.unlink()
    lock_source = tmp_path / "lock-source"
    lock_source.write_bytes(b"")
    lock_source.chmod(0o600)
    os.link(lock_source, lock_path)
    with pytest.raises(ImmutableInputError, match="registry_lock_invalid"):
        publish_public(
            registry_path,
            root=tmp_path,
            payload=payload,
            media_type=POLICY_MEDIA_TYPE,
            media_version=1,
        )

    lock_path.unlink()
    stale_registry_temp = tmp_path / ".immutable-crashed.tmp"
    stale_object_temp = tmp_path / "public/.immutable-crashed.tmp"
    linked_temp = tmp_path / ".immutable-linked.tmp"
    stale_registry_temp.write_bytes(b"partial registry")
    stale_object_temp.write_bytes(b"partial object")
    linked_temp.symlink_to(victim)

    publish_public(
        registry_path,
        root=tmp_path,
        payload=payload,
        media_type=POLICY_MEDIA_TYPE,
        media_version=1,
    )

    assert not stale_registry_temp.exists()
    assert not stale_object_temp.exists()
    assert linked_temp.is_symlink()
    assert victim.read_bytes() == b"do not touch"


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX no-follow open and fork")
def test_publication_fails_closed_when_registry_root_is_replaced_while_locked(
    tmp_path: Path,
) -> None:
    root = tmp_path / "registry-root"
    root.mkdir(mode=0o700)
    _write_empty_registry(root)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    _write_empty_registry(outside)
    payload = canonical_json_bytes({"policy": "pinned-root", "schema_version": 1})
    context = multiprocessing.get_context("fork")
    entered = context.Event()
    release = context.Event()
    results = context.Queue()
    process = context.Process(
        target=_publish_public_worker,
        args=(str(root), payload, results, entered, release),
    )

    process.start()
    assert entered.wait(timeout=10)
    parked = tmp_path / "parked-root"
    root.rename(parked)
    root.symlink_to(outside, target_is_directory=True)
    release.set()
    process.join(timeout=15)
    assert not process.is_alive()
    assert process.exitcode == 0

    assert results.get(timeout=2) == ("error", "registry_root_invalid")
    assert load_registry(outside / "registry.json").entries == ()
    assert list((outside / "public").iterdir()) == []
    assert load_registry(parked / "registry.json").entries == ()


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX flock and fork")
def test_publication_rejects_replaced_lock_before_any_commit(tmp_path: Path) -> None:
    root = tmp_path / "registry-root"
    root.mkdir(mode=0o700)
    registry_path = _write_empty_registry(root)
    first = canonical_json_bytes({"policy": "old-lock", "schema_version": 1})
    second = canonical_json_bytes({"policy": "new-lock", "schema_version": 1})
    context = multiprocessing.get_context("fork")
    entered = context.Event()
    release = context.Event()
    first_results = context.Queue()
    first_process = context.Process(
        target=_publish_public_worker,
        args=(str(root), first, first_results, entered, release),
    )

    first_process.start()
    assert entered.wait(timeout=10)
    lock_path = root / ".registry.json.lock"
    lock_path.unlink()
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)

    second_results = context.Queue()
    second_process = context.Process(
        target=_publish_public_worker,
        args=(str(root), second, second_results),
    )
    second_process.start()
    second_process.join(timeout=10)
    assert second_process.exitcode == 0
    assert second_results.get(timeout=2)[0] == "ok"
    release.set()
    first_process.join(timeout=10)
    assert first_process.exitcode == 0

    assert first_results.get(timeout=2) == ("error", "registry_lock_invalid")
    entries = load_registry(registry_path).entries
    assert [entry.digest for entry in entries] == [hashlib.sha256(second).hexdigest()]
    assert not (root / "public" / hashlib.sha256(first).hexdigest()).exists()


def test_publication_rejects_group_or_world_writable_registry_root(tmp_path: Path) -> None:
    root = tmp_path / "registry-root"
    root.mkdir(mode=0o700)
    registry_path = _write_empty_registry(root)
    root.chmod(0o777)

    with pytest.raises(ImmutableInputError, match="registry_root_invalid"):
        publish_public(
            registry_path,
            root=root,
            payload=canonical_json_bytes({"policy": "unsafe-root", "schema_version": 1}),
            media_type=POLICY_MEDIA_TYPE,
            media_version=1,
        )


def test_public_resolution_stays_under_public_dir_and_verifies_every_commitment(
    tmp_path: Path,
) -> None:
    registry_path = _write_empty_registry(tmp_path)
    payload = pack_improvement_task_set(_improvement_task_set())
    entry = publish_public(
        registry_path,
        root=tmp_path,
        payload=payload,
        media_type=IMPROVEMENT_TASK_SET_MEDIA_TYPE,
        media_version=IMPROVEMENT_TASK_SET_VERSION,
    )

    assert (
        resolve_entry(
            registry_path,
            root=tmp_path,
            digest=entry.digest,
            expected_media_type=IMPROVEMENT_TASK_SET_MEDIA_TYPE,
            expected_media_version=IMPROVEMENT_TASK_SET_VERSION,
        )
        == payload
    )
    public_object = tmp_path / entry.object_key
    public_object.chmod(0o644)
    public_object.write_bytes(b"tampered")
    with pytest.raises(ImmutableInputError, match="object_size_mismatch"):
        resolve_entry(
            registry_path,
            root=tmp_path,
            digest=entry.digest,
            expected_media_type=IMPROVEMENT_TASK_SET_MEDIA_TYPE,
            expected_media_version=IMPROVEMENT_TASK_SET_VERSION,
        )
    with pytest.raises(ImmutableInputError, match="object_media_mismatch"):
        resolve_entry(
            registry_path,
            root=tmp_path,
            digest=entry.digest,
            expected_media_type=SOAK_TASK_SET_MEDIA_TYPE,
            expected_media_version=SOAK_TASK_SET_VERSION,
        )


def test_private_resolution_uses_only_bounded_injected_store_after_commitment_lookup(
    tmp_path: Path,
) -> None:
    registry_path = _write_empty_registry(tmp_path)
    payload = pack_improvement_task_set(_improvement_task_set())
    digest = hashlib.sha256(payload).hexdigest()
    locator = f"private/sha256/{digest}"
    entry = publish_private_commitment(
        registry_path,
        digest=digest,
        size_bytes=len(payload),
        media_type=IMPROVEMENT_TASK_SET_MEDIA_TYPE,
        media_version=IMPROVEMENT_TASK_SET_VERSION,
        object_key=locator,
    )

    class Store:
        def __init__(self, content: bytes) -> None:
            self.content = content
            self.calls: list[tuple[str, int]] = []

        def fetch(self, object_key: str, *, max_bytes: int) -> bytes:
            self.calls.append((object_key, max_bytes))
            return self.content

    store = Store(payload)
    resolved = resolve_entry(
        registry_path,
        root=tmp_path,
        digest=digest,
        expected_media_type=IMPROVEMENT_TASK_SET_MEDIA_TYPE,
        expected_media_version=IMPROVEMENT_TASK_SET_VERSION,
        object_store=store,
    )

    assert resolved == payload
    assert store.calls == [(locator, len(payload))]
    registry_bytes = registry_path.read_bytes()
    assert payload not in registry_bytes
    assert str(tmp_path).encode() not in registry_bytes
    assert entry.object_key.encode() in registry_bytes

    oversized = Store(payload + b"x")
    with pytest.raises(ImmutableInputError, match="object_size_mismatch"):
        resolve_entry(
            registry_path,
            root=tmp_path,
            digest=digest,
            expected_media_type=IMPROVEMENT_TASK_SET_MEDIA_TYPE,
            expected_media_version=IMPROVEMENT_TASK_SET_VERSION,
            object_store=oversized,
        )

    corrupted = Store(payload[:-1] + b"x")
    with pytest.raises(ImmutableInputError, match="object_digest_mismatch"):
        resolve_entry(
            registry_path,
            root=tmp_path,
            digest=digest,
            expected_media_type=IMPROVEMENT_TASK_SET_MEDIA_TYPE,
            expected_media_version=IMPROVEMENT_TASK_SET_VERSION,
            object_store=corrupted,
        )


def test_soak_experiment_contract_cannot_omit_a_task_set_check() -> None:
    _, task_set, metric_pack, policy, observations = _soak_contracts()
    experiment = canonical_json_bytes({"schema_version": 1, "soak_check_ids": ["benchmark-smoke"]})

    with pytest.raises(ImmutableInputError, match="soak_contract_identity_mismatch"):
        evaluate_soak_health(experiment, task_set, metric_pack, policy, observations)


def test_soak_task_set_failed_check_changes_health_decision() -> None:
    experiment, task_set, metric_pack, policy, observations = _soak_contracts()

    healthy = evaluate_soak_health(experiment, task_set, metric_pack, policy, observations)
    failed = evaluate_soak_health(
        experiment,
        task_set,
        metric_pack,
        policy,
        observations | {"benchmark-smoke": False},
    )

    assert healthy.healthy is True
    assert failed.healthy is False
    assert failed.reasons == ("soak_minimum_score_not_met",)


def test_soak_task_set_contract_cannot_omit_an_experiment_check() -> None:
    experiment, task_set, metric_pack, policy, observations = _soak_contracts()
    files = verify_soak_archive(task_set)
    files["soak-contract.json"] = canonical_json_bytes(
        {"check_ids": ["benchmark-smoke"], "schema_version": 1}
    )

    with pytest.raises(ImmutableInputError, match="soak_contract_identity_mismatch"):
        evaluate_soak_health(
            experiment,
            pack_soak_archive(files),
            metric_pack,
            policy,
            observations,
        )


def test_soak_metric_weights_change_health_decision() -> None:
    experiment, task_set, _, policy, observations = _soak_contracts()
    failing_weighted_metric = canonical_json_bytes(
        {
            "algorithm": "weighted-binary-soak-v1",
            "check_weights": {"benchmark-smoke": 1, "workflow-contracts": 3},
            "schema_version": 1,
        }
    )

    decision = evaluate_soak_health(
        experiment, task_set, failing_weighted_metric, policy, observations
    )

    assert decision.healthy is False
    assert decision.score_basis_points == 2500


def test_soak_policy_gate_changes_health_decision() -> None:
    experiment, task_set, metric_pack, _, observations = _soak_contracts()
    require_all_policy = canonical_json_bytes(
        {
            "minimum_score_basis_points": 7000,
            "require_all_checks": True,
            "schema_version": 1,
        }
    )

    decision = evaluate_soak_health(
        experiment, task_set, metric_pack, require_all_policy, observations
    )

    assert decision.healthy is False
    assert decision.reasons == ("soak_required_check_failed",)


def test_soak_contract_media_types_are_registered_independently(tmp_path: Path) -> None:
    registry_path = _write_empty_registry(tmp_path)
    experiment, task_set, metric_pack, policy, _ = _soak_contracts()
    entries = (
        publish_public(
            registry_path,
            root=tmp_path,
            payload=experiment,
            media_type=EXPERIMENT_MEDIA_TYPE,
            media_version=1,
        ),
        publish_public(
            registry_path,
            root=tmp_path,
            payload=task_set,
            media_type=SOAK_TASK_SET_MEDIA_TYPE,
            media_version=SOAK_TASK_SET_VERSION,
        ),
        publish_public(
            registry_path,
            root=tmp_path,
            payload=metric_pack,
            media_type=METRIC_PACK_MEDIA_TYPE,
            media_version=1,
        ),
        publish_public(
            registry_path,
            root=tmp_path,
            payload=policy,
            media_type=POLICY_MEDIA_TYPE,
            media_version=1,
        ),
    )

    assert {entry.media_type for entry in entries} == {
        EXPERIMENT_MEDIA_TYPE,
        SOAK_TASK_SET_MEDIA_TYPE,
        METRIC_PACK_MEDIA_TYPE,
        POLICY_MEDIA_TYPE,
    }
