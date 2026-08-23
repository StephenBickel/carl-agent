"""Independent protected resolution of candidate commit and tree identity."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from carl_bench.product_builder import BuilderError

_OBJECT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_PROTECTED_REPOSITORY = Path("/var/lib/carl/product-builder/candidate-repository.git")


class ProtectedCandidateIdentityResolver:
    __slots__ = ("_repository",)

    def __init__(self, repository: Path) -> None:
        if not repository.is_absolute():
            raise BuilderError("builder_candidate_repository_invalid")
        self._repository = repository

    @classmethod
    def from_store(cls, store: object) -> ProtectedCandidateIdentityResolver:
        repository = store.root / "candidate-repository" if store.testing else _PROTECTED_REPOSITORY
        return cls(repository)

    @classmethod
    def _for_testing(cls, repository: Path) -> ProtectedCandidateIdentityResolver:
        return cls(repository)

    def resolve_tree(self, candidate_commit: str) -> str:
        if not isinstance(candidate_commit, str) or _OBJECT.fullmatch(candidate_commit) is None:
            raise BuilderError("builder_candidate_commit_invalid")
        try:
            completed = subprocess.run(
                (
                    "git",
                    "-C",
                    os.fspath(self._repository),
                    "rev-parse",
                    "--verify",
                    f"{candidate_commit}^{{tree}}",
                ),
                check=False,
                capture_output=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise BuilderError("builder_candidate_commit_unresolvable") from error
        try:
            tree = completed.stdout.decode("ascii").strip()
        except UnicodeError as error:
            raise BuilderError("builder_candidate_commit_unresolvable") from error
        if completed.returncode != 0 or _OBJECT.fullmatch(tree) is None:
            raise BuilderError("builder_candidate_commit_unresolvable")
        return tree

    def verify(self, candidate_commit: str, candidate_tree: str) -> str:
        resolved = self.resolve_tree(candidate_commit)
        if resolved != candidate_tree:
            raise BuilderError("builder_candidate_tree_mismatch")
        return resolved
