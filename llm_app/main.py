from __future__ import annotations

from llm_app.config import load_settings
from llm_app.llm.agent import Agent
from llm_app.llm.model import EchoLLM
from llm_app.tools.registry import ToolRegistry
from llm_app.tools import filesystem


def build_agent() -> Agent:
    settings = load_settings()
    registry = ToolRegistry()
    filesystem.register_tools(registry)
    llm = EchoLLM()
    return Agent(llm=llm, registry=registry, use_langgraph=settings.use_langgraph)


def main() -> None:
    agent = build_agent()
    while True:
        try:
            prompt = input(">> ").strip()
        except EOFError:
            break
        if not prompt:
            continue
        if prompt.lower() in {"exit", "quit"}:
            break
        print(agent.run(prompt))


if __name__ == "__main__":
    main()
