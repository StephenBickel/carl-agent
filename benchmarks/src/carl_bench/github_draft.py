"""Disabled draft-publication boundary for the foundation-only factory."""

from __future__ import annotations

from pathlib import Path

from carl_bench.candidate import DraftPullRequest
from carl_bench.experiment import ExperimentManifest, ExperimentProjection


class DraftPrGatewayError(ValueError):
    """A stable draft-publication error that omits command output and credentials."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DraftPrGateway:
    """Inert API placeholder until isolated publication authority exists."""

    def __init__(
        self,
        *,
        repository_root: Path,
        repository_slug: str,
        remote: str,
        expected_remote_url: str,
        base_branch: str,
        gh_executable: Path,
        private_root: Path,
        command_env: dict[str, str],
    ) -> None:
        # Deliberately retain no executable, repository, environment, or command capability.
        pass

    def open_or_reconcile(
        self, manifest: ExperimentManifest, projection: ExperimentProjection
    ) -> DraftPullRequest:
        raise DraftPrGatewayError("experimental_publication_disabled")
