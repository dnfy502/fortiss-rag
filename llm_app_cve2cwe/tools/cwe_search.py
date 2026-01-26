from __future__ import annotations

import math
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import numpy as np
import scipy.sparse as sp

from .registry import ToolRegistry

_CWE_XML_PATH = Path(__file__).resolve().parents[2] / "data" / "cwec_v4.19.xml"
_CWE_CORPUS: list[dict] | None = None
_TFIDF_INDEX: tuple[sp.csr_matrix, dict[str, int], np.ndarray] | None = None
_VECTOR_INDEX: dict[str, tuple[object, np.ndarray]] = {}


def _element_text(elem: ET.Element | None) -> str:
    if elem is None:
        return ""
    return " ".join(part.strip() for part in elem.itertext() if part and part.strip())


def _collect_alternate_terms(weakness: ET.Element, ns: dict) -> list[str]:
    terms: list[str] = []
    alt_terms = weakness.find("cwe:Alternate_Terms", ns) if ns else weakness.find("Alternate_Terms")
    if alt_terms is None:
        return terms
    for term in alt_terms.findall("cwe:Alternate_Term", ns) if ns else alt_terms.findall("Alternate_Term"):
        term_elem = term.find("cwe:Term", ns) if ns else term.find("Term")
        term_text = _element_text(term_elem)
        if term_text:
            terms.append(term_text)
    return terms


def _collect_section_texts(weakness: ET.Element, ns: dict, tag: str) -> list[str]:
    results: list[str] = []
    section = weakness.find(f"cwe:{tag}", ns) if ns else weakness.find(tag)
    if section is None:
        return results
    for child in list(section):
        text = _element_text(child)
        if text:
            results.append(text)
    if not results:
        text = _element_text(section)
        if text:
            results.append(text)
    return results


def _collect_observed_examples(weakness: ET.Element, ns: dict) -> list[str]:
    results: list[str] = []
    section = weakness.find("cwe:Observed_Examples", ns) if ns else weakness.find("Observed_Examples")
    if section is None:
        return results
    examples = section.findall("cwe:Observed_Example", ns) if ns else section.findall("Observed_Example")
    for example in examples:
        ref = _element_text(example.find("cwe:Reference", ns) if ns else example.find("Reference"))
        desc = _element_text(example.find("cwe:Description", ns) if ns else example.find("Description"))
        if ref and desc:
            results.append(f"{ref}: {desc}")
        elif ref:
            results.append(ref)
        elif desc:
            results.append(desc)
    return results


def _collect_related_weaknesses(weakness: ET.Element, ns: dict) -> list[str]:
    results: list[str] = []
    section = weakness.find("cwe:Related_Weaknesses", ns) if ns else weakness.find("Related_Weaknesses")
    if section is None:
        return results
    items = section.findall("cwe:Related_Weakness", ns) if ns else section.findall("Related_Weakness")
    for item in items:
        nature = item.get("Nature")
        cwe_id = item.get("CWE_ID")
        if nature and cwe_id:
            results.append(f"{nature}: CWE-{cwe_id}")
        elif cwe_id:
            results.append(f"CWE-{cwe_id}")
    return results


def _collect_references(weakness: ET.Element, ns: dict) -> list[str]:
    results: list[str] = []
    section = weakness.find("cwe:References", ns) if ns else weakness.find("References")
    if section is None:
        return results
    refs = section.findall("cwe:Reference", ns) if ns else section.findall("Reference")
    for ref in refs:
        ref_id = ref.get("External_Reference_ID")
        if ref_id:
            results.append(ref_id)
    return results


def _load_cwe_corpus() -> list[dict]:
    global _CWE_CORPUS
    if _CWE_CORPUS is not None:
        return _CWE_CORPUS

    if not _CWE_XML_PATH.exists():
        raise FileNotFoundError(
            f"CWE XML not found at {_CWE_XML_PATH}. "
            "Place cwec_v4.19.xml under data/ (e.g., data/cwec_v4.19.xml)."
        )

    tree = ET.parse(_CWE_XML_PATH)
    root = tree.getroot()
    ns = {"cwe": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
    xpath = ".//cwe:Weakness" if ns else ".//Weakness"

    corpus: list[dict] = []
    for weakness in root.findall(xpath, ns):
        wid = weakness.get("ID")
        wname = weakness.get("Name")
        abstraction = weakness.get("Abstraction") or ""
        structure = weakness.get("Structure") or ""
        status = weakness.get("Status") or ""
        desc_elem = weakness.find("cwe:Description", ns) if ns else weakness.find("Description")
        description = _element_text(desc_elem)
        ext_desc_elem = (
            weakness.find("cwe:Extended_Description", ns)
            if ns
            else weakness.find("Extended_Description")
        )
        extended_description = _element_text(ext_desc_elem)
        alternate_terms = _collect_alternate_terms(weakness, ns)
        background_details = _collect_section_texts(weakness, ns, "Background_Details")
        introduction_phases = _collect_section_texts(weakness, ns, "Modes_Of_Introduction")
        consequences = _collect_section_texts(weakness, ns, "Common_Consequences")
        detection_methods = _collect_section_texts(weakness, ns, "Detection_Methods")
        mitigations = _collect_section_texts(weakness, ns, "Potential_Mitigations")
        demonstrative_examples = _collect_section_texts(weakness, ns, "Demonstrative_Examples")
        observed_examples = _collect_observed_examples(weakness, ns)
        related_weaknesses = _collect_related_weaknesses(weakness, ns)
        references = _collect_references(weakness, ns)
        if not description:
            description = "No description available."

        cwe_id = f"CWE-{wid}"
        chunks = [
            f"{wname}.",
            f"Abstraction: {abstraction}." if abstraction else "",
            f"Structure: {structure}." if structure else "",
            f"Status: {status}." if status else "",
            description,
            extended_description,
        ]
        if alternate_terms:
            chunks.append("Alternate terms: " + ", ".join(alternate_terms) + ".")
        if background_details:
            chunks.append("Background: " + " ".join(background_details))
        if introduction_phases:
            chunks.append("Modes of introduction: " + " ".join(introduction_phases))
        if consequences:
            chunks.append("Common consequences: " + " ".join(consequences))
        if detection_methods:
            chunks.append("Detection methods: " + " ".join(detection_methods))
        if mitigations:
            chunks.append("Potential mitigations: " + " ".join(mitigations))
        if demonstrative_examples:
            chunks.append("Demonstrative examples: " + " ".join(demonstrative_examples))
        if observed_examples:
            chunks.append("Observed examples: " + " ".join(observed_examples))
        if related_weaknesses:
            chunks.append("Related weaknesses: " + ", ".join(related_weaknesses) + ".")
        if references:
            chunks.append("References: " + ", ".join(references) + ".")
        text = " ".join(chunk for chunk in chunks if chunk)
        corpus.append(
            {
                "id": cwe_id,
                "name": wname,
                "description": description,
                "extended_description": extended_description,
                "abstraction": abstraction,
                "structure": structure,
                "status": status,
                "alternate_terms": alternate_terms,
                "background_details": background_details,
                "modes_of_introduction": introduction_phases,
                "common_consequences": consequences,
                "detection_methods": detection_methods,
                "potential_mitigations": mitigations,
                "demonstrative_examples": demonstrative_examples,
                "observed_examples": observed_examples,
                "related_weaknesses": related_weaknesses,
                "references": references,
                "text": text,
            }
        )

    _CWE_CORPUS = corpus
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
    corpus = _load_cwe_corpus()
    if _TFIDF_INDEX is None:
        texts = [c["text"] for c in corpus]
        _TFIDF_INDEX = _build_tfidf_index(texts)
    X, vocab, idf_vec = _TFIDF_INDEX
    return corpus, X, vocab, idf_vec


def _keyword_search(query: str, top_k: int) -> list[dict]:
    corpus, X, vocab, idf_vec = _ensure_tfidf()
    q = _tfidf_query(query, vocab, idf_vec)
    sims = (X @ q.T).toarray().ravel()
    k = max(1, min(top_k, len(corpus)))
    top_idx = np.argsort(-sims)[:k]
    results = []
    for idx in top_idx:
        cwe = corpus[int(idx)]
        results.append(
            {
                "id": cwe["id"],
                "description": cwe["description"],
                "score": float(sims[int(idx)]),
            }
        )
    return results


def _get_vector_index(model_name: str) -> tuple[object, np.ndarray, list[dict]]:
    corpus = _load_cwe_corpus()
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
    k = max(1, min(top_k, len(corpus)))
    top_idx = np.argsort(-sims)[:k]
    results = []
    for idx in top_idx:
        cwe = corpus[int(idx)]
        results.append(
            {
                "id": cwe["id"],
                "description": cwe["description"],
                "score": float(sims[int(idx)]),
            }
        )
    return results


def register_tools(registry: ToolRegistry) -> None:
    @registry.register("cwe_search_keyword", "Search CWE definitions via keyword/TF-IDF.")
    def cwe_search_keyword(query: str, top_k: int = 5) -> list[dict]:
        return _keyword_search(query=query, top_k=top_k)

    @registry.register(
        "cwe_search_vector",
        "Search CWE definitions via embeddings (sentence-transformers).",
    )
    def cwe_search_vector(
        query: str,
        top_k: int = 5,
        model_name: str = "sentence-transformers/all-mpnet-base-v2",
    ) -> list[dict]:
        return _vector_search(query=query, top_k=top_k, model_name=model_name)

    @registry.register("get_cwe_information", "Return full CWE record by ID.")
    def get_cwe_information(cwe_id: str) -> dict:
        corpus = _load_cwe_corpus()
        normalized = cwe_id.strip().upper()
        if not normalized.startswith("CWE-"):
            normalized = f"CWE-{normalized}"
        for cwe in corpus:
            if cwe["id"] == normalized:
                return cwe
        return {"error": f"Unknown CWE ID: {cwe_id}"}
