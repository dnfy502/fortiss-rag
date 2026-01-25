
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent))

from llm_app.config import load_settings
from llm_app.cve_loader import build_cve_prompt, load_cve_record, normalize_cve_id
from llm_app.main import build_agent

def run_repro(cve_input: str):
    print(f"--- Running Reproduction for {cve_input} ---")
    settings = load_settings()
    settings.verbose = True # Force verbose to see tool calls
    agent = build_agent(settings)
    
    try:
        normalized = normalize_cve_id(cve_input)
        record = load_cve_record(normalized)
        prompt = build_cve_prompt(normalized, record)
        print("\n[User Prompt Constructed]")
        # print(prompt[:200] + "...") 
        
        print("\n[Agent Running...]")
        result = agent.run(prompt)
        print("\n[Final Result]")
        print(result)
        
    except Exception as e:
        print(f"\n[Error] {e}")

if __name__ == "__main__":
    cve = "CVE-2024-24004"
    if len(sys.argv) > 1:
        cve = sys.argv[1]
    run_repro(cve)
