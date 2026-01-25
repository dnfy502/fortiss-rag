from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from llm_app.config import load_settings
from llm_app.cve_loader import build_cve_prompt, load_cve_record, normalize_cve_id
from llm_app.llm.agent import Agent
from llm_app.llm.model import OllamaLLM
from llm_app.tools.registry import ToolRegistry
from llm_app.tools import cwe_search, final_answer


def build_agent(settings) -> Agent:
    registry = ToolRegistry()
    cwe_search.register_tools(registry)
    final_answer.register_tools(registry)
    llm = OllamaLLM(model=settings.model_name, temperature=settings.temperature)
    return Agent(llm=llm, registry=registry, verbose=settings.verbose)


def run_cve_lookup(agent: Agent, settings) -> None:
    raw = input("CVE ID: ").strip()
    if not raw:
        return
    cve_id = normalize_cve_id(raw)
    record = load_cve_record(cve_id)
    prompt = build_cve_prompt(cve_id, record)
    print(agent.run(prompt))


def main() -> None:
    settings = load_settings()
    if settings.verbose:
        print(f"LLM model: {settings.model_name}")
    agent = build_agent(settings)
    while True:
        try:
            prompt = input(">> ").strip()
        except EOFError:
            break
        if not prompt:
            continue
        if prompt.lower() in {"exit", "quit"}:
            break
        try:
            normalized = normalize_cve_id(prompt)
        except Exception:
            normalized = ""
        if normalized:
            try:
                record = load_cve_record(normalized)
                cve_prompt = build_cve_prompt(normalized, record)
            except Exception as exc:
                print(f"Failed to load CVE: {exc}")
                continue
            print(agent.run(cve_prompt))
            continue
        if prompt.lower().startswith("cve "):
            cve_id = prompt.split(" ", 1)[1].strip()
            if not cve_id:
                print("Please provide a CVE ID after 'cve'.")
                continue
            try:
                normalized = normalize_cve_id(cve_id)
                record = load_cve_record(normalized)
                cve_prompt = build_cve_prompt(normalized, record)
            except Exception as exc:
                print(f"Failed to load CVE: {exc}")
                continue
            print(agent.run(cve_prompt))
            continue
        if prompt.lower() == "cve":
            try:
                run_cve_lookup(agent, settings)
            except Exception as exc:
                print(f"Failed to load CVE: {exc}")
            continue
        print(agent.run(prompt))


if __name__ == "__main__":
    main()
