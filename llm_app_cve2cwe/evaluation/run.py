import argparse
import json
import sys
import dataclasses
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from llm_app.config import load_settings
from llm_app.cve_loader import build_cve_prompt, load_cve_record, normalize_cve_id
from llm_app.main import build_agent
from llm_app.evaluation.cwe_graph import get_cwe_graph
from llm_app.evaluation.dataset import get_random_cves

def run_evaluation(num_cves: int):
    print(f"--- Starting Evaluation on {num_cves} CVEs ---")
    
    # Initialize Graph
    print("Loading CWE Graph...")
    graph = get_cwe_graph()
    
    # Initialize Agent
    print("Initializing Agent...")
    settings = load_settings()
    settings = dataclasses.replace(settings, verbose=False) # Keep stdout clean
    agent = build_agent(settings)
    
    # Get Dataset
    print("Fetching Dataset...")
    dataset = get_random_cves(num_cves)
    
    results = []
    
    print(f"\n{'CVE ID':<15} | {'Truth':<10} | {'Pred':<10} | {'Score':<5} | {'Type'}")
    print("-" * 70)
    
    total_score = 0
    valid_runs = 0
    
    for item in dataset:
        cve_id = item["cve_id"]
        truth = item["truth_cwe"]
        
        try:
            # Load and Run
            record = load_cve_record(cve_id)
            prompt = build_cve_prompt(cve_id, record)
            
            # Run Agent
            # Capture output in real app maybe? For now just run
            raw_response = agent.run(prompt)
            
            # Parse response
            # We expect a JSON string like {"tool": "provide_cwe_match", "args": {...}}
            try:
                data = json.loads(raw_response)
                
                # Handling the case where it might be wrapped or just the args
                if "cwe_id" in data:
                    pred = data["cwe_id"]
                elif "args" in data and "cwe_id" in data["args"]:
                    pred = data["args"]["cwe_id"]
                else:
                    pred = "Unknown"
            except json.JSONDecodeError:
                pred = "Egg (Parse Fail)"
            
            # Score
            if pred.startswith("CWE"):
                score, match_type = graph.score_match(truth, pred)
                total_score += score
                valid_runs += 1
            else:
                 score = 0
                 match_type = f"Egg ({pred})"
                 
            print(f"{cve_id:<15} | {truth:<10} | {pred:<10} | {score:<5} | {match_type}")
            
        except Exception as e:
            print(f"{cve_id:<15} | {truth:<10} | {'Error':<10} | {0:<5} | Error: {str(e)[:20]}")

    if valid_runs > 0:
        avg = total_score / valid_runs
        print("-" * 70)
        print(f"Average Score: {avg:.2f} / 10.0")
    else:
        print("\nNo valid runs completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--num", type=int, default=20, help="Number of CVEs to test")
    args = parser.parse_args()
    run_evaluation(args.num)
