"""Agent harness adapters available to the benchmark runner."""

from carl_bench.adapters.base import AgentAdapter
from carl_bench.adapters.scripted import ScriptedAdapter

__all__ = ["AgentAdapter", "ScriptedAdapter"]
