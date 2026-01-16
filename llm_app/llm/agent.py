from __future__ import annotations

from typing import Optional

from .graph import build_langgraph
from .model import LLMClient
from ..tools.registry import ToolRegistry


class Agent:
    def __init__(
        self,
        llm: LLMClient,
        registry: ToolRegistry,
        use_langgraph: bool = True,
    ) -> None:
        self._llm = llm
        self._registry = registry
        self._use_langgraph = use_langgraph
        self._graph = None

    def run(self, prompt: str) -> str:
        if self._use_langgraph:
            return self._run_langgraph(prompt)
        return self._llm.complete(prompt)

    def _run_langgraph(self, prompt: str) -> str:
        if self._graph is None:
            self._graph = build_langgraph(self._llm, self._registry.list())
        result = self._graph.invoke({"messages": [prompt]})
        messages = result.get("messages", [])
        return messages[-1] if messages else ""
