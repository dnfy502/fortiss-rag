from __future__ import annotations

from typing import Any, TypedDict, List

from .model import LLMClient
from ..tools.registry import Tool


class GraphState(TypedDict):
    messages: List[str]


def build_langgraph(llm: LLMClient, tools: list[Tool]):
    try:
        from langgraph.graph import StateGraph, START, END
    except Exception as exc:  # pragma: no cover - only hit if missing
        raise RuntimeError(
            "LangGraph is not installed or failed to import. "
            "Install it or set LLM_USE_LANGGRAPH=0."
        ) from exc

    graph = StateGraph(GraphState)

    def model_node(state: GraphState) -> dict[str, Any]:
        last_message = state["messages"][-1] if state["messages"] else ""
        response = llm.complete(last_message)
        return {"messages": state["messages"] + [response]}

    graph.add_node("model", model_node)
    graph.add_edge(START, "model")
    graph.add_edge("model", END)
    return graph.compile()
