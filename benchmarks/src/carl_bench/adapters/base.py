"""Private execution boundary shared by benchmark harness adapters."""

from __future__ import annotations

from typing import Protocol

from carl_bench.models import AgentOutcome, AgentRequest


class AgentAdapter(Protocol):
    adapter_id: str

    def version(self) -> str: ...

    async def run(self, request: AgentRequest) -> AgentOutcome: ...
