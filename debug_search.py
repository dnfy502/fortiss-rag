
import sys
from pathlib import Path
import logging

# Setup path
sys.path.append("/home/dnfy/Desktop/Fortiss")

from llm_app_cwe2attack.tools.attack_search import _keyword_search, _load_attack_corpus, _ensure_tfidf, _tokenize

# Setup logging
logging.basicConfig(level=logging.INFO)

def debug_query(query):
    print(f"--- Debugging Query: '{query}' ---")
    
    # 1. Check Corpus
    corpus = _load_attack_corpus()
    print(f"Corpus size: {len(corpus)}")
    
    # Check for expected techniques
    expected_ids = ["T1210", "T1203", "T1211", "T1212"] # Exploitation related
    for eid in expected_ids:
        found = False
        for item in corpus:
            if item["attack_id"] == eid:
                print(f"Found expected technique {eid}: {item['name']}")
                # print(f"  Text preview: {item['text'][:100]}...")
                
                # Check tokens
                tokens = _tokenize(item['text'])
                q_tokens = _tokenize(query)
                matches = [t for t in q_tokens if t in tokens]
                print(f"  Query tokens present: {matches}")
                found = True
                break
        if not found:
            print(f"WARNING: Expected technique {eid} NOT FOUND in corpus.")

    # 2. Run Search
    print("\nRunning Search...")
    results = _keyword_search(query, top_k=5)
    
    for i, res in enumerate(results):
        print(f"\nRank {i+1}: {res['id']} - {res['name']}")
        print(f"  Score: {res['score']}")
        print(f"  Desc: {res['description'][:100]}...")
        
        # Explain score (reverse engineer)
        # We need access to the vectorizer internals which are hidden in the module globals
        # But we can infer from the text in the corpus
        
        # Find this item in corpus
        for item in corpus:
            if item["attack_id"] == res["id"]:
                 tokens = _tokenize(item['text'])
                 q_tokens = _tokenize(query)
                 matches = [t for t in q_tokens if t in tokens]
                 print(f"  Matching Tokens in Corpus Text: {matches}")
                 break

if __name__ == "__main__":
    debug_query("buffer overflow")
