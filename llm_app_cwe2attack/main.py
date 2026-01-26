from __future__ import annotations

import sys
from pathlib import Path

# Fix path to include project root so we can import mapping_agent
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

# Also add the parent of that if needed (just to be safe for imports)
# if str(PROJECT_ROOT.parent) not in sys.path:
#     sys.path.append(str(PROJECT_ROOT.parent))

from llm_app_cwe2attack.config import load_settings
# Import new loader and tools
from llm_app_cwe2attack.cwe_loader import build_cwe_prompt, CWELoader
from llm_app_cwe2attack.llm.agent import Agent
from llm_app_cwe2attack.llm.model import OllamaLLM
from llm_app_cwe2attack.tools.registry import ToolRegistry
# Note: we are using our new tools, but importing from package
from llm_app_cwe2attack.tools import attack_search, final_answer, cwe_search


def build_agent(settings) -> Agent:
    registry = ToolRegistry()
    # Register core tools
    cwe_search.register_tools(registry)
    attack_search.register_tools(registry)
    final_answer.register_tools(registry)
    
    # Optional: We could also add a system prompt here if the Agent class supports it.
    # The Agent class in this codebase likely just takes the LLM and registry.
    
    llm = OllamaLLM(model=settings.model_name, temperature=settings.temperature)
    return Agent(llm=llm, registry=registry, verbose=settings.verbose)


def run_cwe_lookup(agent: Agent, cwe_id: str) -> None:
    loader = CWELoader()
    try:
        record = loader.get_cwe(cwe_id)
        if not record:
            print(f"CWE {cwe_id} not found.")
            return
        
        prompt = build_cwe_prompt(cwe_id, record)
        # print("\n--- Prompt sent to Agent ---")
        # print(prompt) # Debugging
        # print("----------------------------\n")
        
        print(agent.run(prompt))
    except Exception as e:
        print(f"Error processing {cwe_id}: {e}")


def main() -> None:
    settings = load_settings()
    if settings.verbose:
        print(f"LLM model: {settings.model_name}")
    
    # Initialize agent with all tools
    agent = build_agent(settings)
    
    print("CWE2ATT&CK Agent Ready.")
    print("Enter a CWE ID (e.g., 'CWE-79', '89') or 'exit' to quit.")
    
    while True:
        try:
            prompt = input(">> ").strip()
        except EOFError:
            break
            
        if not prompt:
            continue
            
        if prompt.lower() in {"exit", "quit"}:
            break

        # Check if input looks like a CWE ID
        # Accept "CWE-123" or just "123"
        normalized = prompt.upper()
        if normalized.startswith("CWE-"):
            cwe_id = normalized
        elif normalized.isdigit():
            cwe_id = f"CWE-{normalized}"
        else:
            # Maybe just chat? Or specific command?
            # For now let's assume if it's not a number, it might be a general query
            # But the user asked for CWE ID input.
            print("Please enter a valid CWE ID (e.g., CWE-79) or 'exit'.")
            continue

        run_cwe_lookup(agent, cwe_id)


if __name__ == "__main__":
    main()
