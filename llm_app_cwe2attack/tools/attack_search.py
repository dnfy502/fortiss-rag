from __future__ import annotations

import math
import re
import sys
from pathlib import Path
from typing import Dict, Any, List

import numpy as np
import scipy.sparse as sp

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from mapping_agent.lookups.object_lookup import ObjectLookup
from .registry import ToolRegistry

# Globals for caching
_ATTACK_CORPUS: list[dict] | None = None
_TFIDF_INDEX: tuple[sp.csr_matrix, dict[str, int], np.ndarray] | None = None
_VECTOR_INDEX: dict[str, tuple[object, np.ndarray]] = {}

def _load_attack_corpus() -> list[dict]:
    global _ATTACK_CORPUS
    if _ATTACK_CORPUS is not None:
        return _ATTACK_CORPUS

    data_dir = PROJECT_ROOT / "mapping_agent" / "data" / "output"
    lookup = ObjectLookup(str(data_dir))
    
    # lookup.attacks is a dict {attack_id: full_object}
    # We want a list of dicts for search
    corpus = []
    for attack_id, data in lookup.attacks.items():
        # Clean text for search
        # Boost name importance for TF-IDF (5x boost)
        name = data.get('name', '')
        text_parts = [
            f"{name} " * 5, 
            data.get('description', ''),
            " ".join(data.get('tactics', [])),
            " ".join(data.get('platforms', []))
        ]
        text = " ".join(t for t in text_parts if t)
        
        # Add to corpus
        item = data.copy()
        item['text'] = text
        corpus.append(item)
        
    _ATTACK_CORPUS = corpus
    return corpus

def _normalize_text(text: str) -> str:
    text = (text or "").lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def _tokenize(text: str) -> list[str]:
    return [t for t in _normalize_text(text).split(" ") if t]

def _build_tfidf_index(corpus_texts: list[str]) -> tuple[sp.csr_matrix, dict[str, int], np.ndarray]:
    n_docs = len(corpus_texts)
    doc_term_counts: list[dict[str, int]] = []
    df: dict[str, int] = {}
    
    for text in corpus_texts:
        counts: dict[str, int] = {}
        for tok in _tokenize(text):
            counts[tok] = counts.get(tok, 0) + 1
        doc_term_counts.append(counts)
        for tok in counts.keys():
            df[tok] = df.get(tok, 0) + 1
            
    vocab = {tok: i for i, tok in enumerate(sorted(df.keys()))}
    n_terms = len(vocab)
    
    rows: list[int] = []
    cols: list[int] = []
    vals: list[float] = []
    for r, counts in enumerate(doc_term_counts):
        for tok, tf in counts.items():
            c = vocab[tok]
            rows.append(r)
            cols.append(c)
            vals.append(float(tf))
            
    tf = sp.csr_matrix((vals, (rows, cols)), shape=(n_docs, n_terms), dtype=np.float32)
    
    idf = np.empty(n_terms, dtype=np.float32)
    for tok, c in vocab.items():
        idf[c] = math.log((1.0 + n_docs) / (1.0 + df[tok])) + 1.0
        
    X = tf.multiply(idf)
    row_norm = np.sqrt(X.multiply(X).sum(axis=1)).A1
    row_norm[row_norm == 0] = 1.0
    X = sp.diags(1.0 / row_norm).dot(X)
    
    return X, vocab, idf
    
def _tfidf_query(text: str, vocab: dict[str, int], idf_vec: np.ndarray) -> sp.csr_matrix:
    counts: dict[str, int] = {}
    for tok in _tokenize(text):
        if tok in vocab:
            counts[tok] = counts.get(tok, 0) + 1
            
    if not counts:
        return sp.csr_matrix((1, len(vocab)), dtype=np.float32)
        
    rows: list[int] = []
    cols: list[int] = []
    vals: list[float] = []
    for tok, tf in counts.items():
        c = vocab[tok]
        rows.append(0)
        cols.append(c)
        vals.append(float(tf))
        
    q_tf = sp.csr_matrix((vals, (rows, cols)), shape=(1, len(vocab)), dtype=np.float32)
    q = q_tf.multiply(idf_vec)
    q_norm = np.sqrt(q.multiply(q).sum(axis=1)).A1
    q_norm[q_norm == 0] = 1.0
    return q.multiply(1.0 / q_norm[0])

def _ensure_tfidf() -> tuple[list[dict], sp.csr_matrix, dict[str, int], np.ndarray]:
    global _TFIDF_INDEX
    corpus = _load_attack_corpus()
    if _TFIDF_INDEX is None:
        texts = [c["text"] for c in corpus]
        _TFIDF_INDEX = _build_tfidf_index(texts)
    X, vocab, idf_vec = _TFIDF_INDEX
    return corpus, X, vocab, idf_vec

def _keyword_search(query: str, top_k: int) -> list[dict]:
    corpus, X, vocab, idf_vec = _ensure_tfidf()
    q = _tfidf_query(query, vocab, idf_vec)
    sims = (X @ q.T).toarray().ravel()
    
    # Fetch more to allow for filtering
    k_fetch = min(len(corpus), top_k * 5)
    top_idx = np.argsort(-sims)[:k_fetch]
    
    results = []
    for idx in top_idx:
        if len(results) >= top_k:
            break
        attack = corpus[int(idx)]
        
        # Filter deprecated/revoked
        if attack.get("deprecated", False) or attack.get("revoked", False):
            continue
            
        score = float(sims[int(idx)])
        # Filter low relevance matches (e.g. accidental single-word matches in long descriptions)
        if score < 0.1:
            continue

        # Truncate description to avoid context flooding
        full_desc = attack["description"] or ""
        short_desc = full_desc[:300] + "..." if len(full_desc) > 300 else full_desc
            
        results.append({
            "id": attack["attack_id"],
            "name": attack["name"],
            "description": short_desc,
            "score": score
        })
    return results

def _get_vector_index(model_name: str) -> tuple[object, np.ndarray, list[dict]]:
    corpus = _load_attack_corpus()
    if model_name in _VECTOR_INDEX:
        embedder, embeddings = _VECTOR_INDEX[model_name]
        return embedder, embeddings, corpus

    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as exc:
        raise RuntimeError(
            "sentence-transformers is not installed. "
            "Install it (plus torch/transformers) to enable vector search."
        ) from exc

    embedder = SentenceTransformer(model_name)
    texts = [c["text"] for c in corpus]
    embeddings = embedder.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    _VECTOR_INDEX[model_name] = (embedder, embeddings)
    return embedder, embeddings, corpus

def _vector_search(query: str, top_k: int, model_name: str) -> list[dict]:
    embedder, embeddings, corpus = _get_vector_index(model_name)
    q = embedder.encode([query], normalize_embeddings=True, show_progress_bar=False)[0]
    sims = embeddings @ q
    
    # Fetch more to allow for filtering
    k_fetch = min(len(corpus), top_k * 5)
    top_idx = np.argsort(-sims)[:k_fetch]
    
    results = []
    for idx in top_idx:
        if len(results) >= top_k:
            break
        attack = corpus[int(idx)]
        
        # Filter deprecated/revoked
        if attack.get("deprecated", False) or attack.get("revoked", False):
            continue
        
        # Truncate description to avoid context flooding
        full_desc = attack["description"] or ""
        short_desc = full_desc[:300] + "..." if len(full_desc) > 300 else full_desc
            
        results.append({
            "id": attack["attack_id"],
            "name": attack["name"],
            "description": short_desc,
            "score": float(sims[int(idx)])
        })
    return results

def register_tools(registry: ToolRegistry) -> None:
    @registry.register("attack_search_keyword", "Search ATT&CK techniques via keyword/TF-IDF. Argument 'query' is required.")
    def attack_search_keyword(query: str = "", top_k: int = 5, **kwargs) -> list[dict]:
        # Handle agent confusion between 'query' and 'keyword'
        if not query and "keyword" in kwargs:
            query = kwargs["keyword"]
        if not query:
            return [{"error": "Missing required argument 'query'."}]
        return _keyword_search(query=query, top_k=top_k)

    @registry.register("attack_search_vector", "Search ATT&CK techniques via embeddings. Argument 'query' is required.")
    def attack_search_vector(
        query: str = "",
        top_k: int = 5,
        model_name: str = "sentence-transformers/all-mpnet-base-v2",
        **kwargs
    ) -> list[dict]:
        # Handle agent confusion between 'query' and 'keyword'
        if not query and "keyword" in kwargs:
            query = kwargs["keyword"]
        if not query:
            return [{"error": "Missing required argument 'query'."}]
        return _vector_search(query=query, top_k=top_k, model_name=model_name)

    @registry.register("get_attack_information", "Return full ATT&CK technique record by ID.")
    def get_attack_information(attack_id: str) -> dict:
        corpus = _load_attack_corpus()
        normalized = attack_id.strip().upper()
        # Some attack IDs might be T1027 or T1027.001
        for attack in corpus:
            if attack["attack_id"].upper() == normalized:
                return attack
        return {"error": f"Unknown ATT&CK ID: {attack_id}"}
