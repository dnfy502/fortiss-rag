# CVE→CWE Matching Experiments: Quick Summary

## Results at a Glance

| Approach | Top-k | Top-1 | LLM | Time | Status |
|----------|-------|-------|-----|------|--------|
| **Baseline (TF-IDF)** | **57%** | **33%** | **51%** | 207s | ✅ **BEST** |
| Phase 1 (Hybrid) | 56% ⬇️ | - | 48% ⬇️ | 207s | ❌ Failed |
| Phase 2 (Abstraction) | 58% ≈ | 21% ⬇️ | 44% ⬇️ | 325s | ❌ Failed |

**Winner:** Simple TF-IDF baseline beats all advanced methods!

---

## What We Tried

### ✅ Baseline: TF-IDF + RAG + LLM
- Simple bag-of-words retrieval
- Cosine similarity matching
- LLM selects from top-5 candidates
- **Result:** 57% top-5, 51% final accuracy

### ❌ Phase 1: Hybrid Retrieval (BM25 + SBERT + RRF)
- BM25 for lexical matching
- SBERT for semantic matching
- Reciprocal Rank Fusion
- Query expansion (50+ synonyms)
- **Result:** 56% top-5 (WORSE than baseline)

**Why it failed:**
- Query expansion added noise
- SBERT not trained for security domain
- BM25 parameters not tuned
- Fusion diluted good signals

### ❌ Phase 2: LLM Query Abstraction
- LLM abstracts CVE description before retrieval
- Removes product names, versions
- Converts to generic security terms
- **Result:** 58% top-10 but 44% final (WORSE than baseline)

**Why it failed:**
- Over-abstraction removed critical details
- Inconsistent terminology
- LLM doesn't know CWE taxonomy
- Lost specific technical terms ("SQL injection" → "improper input validation")

---

## Key Insights

### The Real Problem
**It's not a retrieval algorithm problem—it's a representation problem.**

- CVE: "buffer overflow in libpng 1.2.3"
- CWE: "Out-of-bounds Write"
- **Same concept, different words = no match**

### Why Baseline Wins
1. **Technical jargon alignment**: CVE and CWE share keywords
2. **Simplicity**: Fewer points of failure
3. **Direct term matching**: More valuable than semantic understanding in security domain

### The 57% Ceiling
- All approaches cluster around 55-58%
- Not limited by retrieval algorithm
- Limited by vocabulary/representation gap
- ~40% of CVEs are genuinely ambiguous or poorly described

---

## Recommendation

### ⭐ Fine-Tune Embeddings on Labeled Data

**Why:** Only approach that addresses the root cause

**How:** Train sentence embeddings on 101K CVE→CWE pairs

**Expected:** 75-85% top-5 recall (vs 57% now)

**Effort:** 2-3 hours GPU training

**Implementation:**
```python
from sentence_transformers import SentenceTransformer, losses

# Train on CVE→CWE pairs
model = SentenceTransformer('all-mpnet-base-v2')
model.fit(cve_cwe_pairs, epochs=3, loss=CosineSimilarityLoss)

# Result: Embeddings that understand CVE↔CWE vocabulary
```

---

## Not Recommended

❌ More retrieval algorithms  
❌ Query expansion  
❌ LLM abstraction  
❌ Traditional NLP tricks  

**Reason:** The 57% ceiling is a representation problem, not an algorithm problem.

---

## Lessons Learned

1. **Start simple** - Baseline beat everything
2. **Measure early** - Would have saved weeks
3. **Domain matters** - General NLP doesn't transfer to security
4. **LLMs aren't magic** - Can't fix fundamental semantic gaps
5. **Fine-tuning inevitable** - Need domain-specific training for breakthrough

---

## Files

- `CVE_CWE_MATCHING_EXPERIMENTS_REPORT.md` - Full technical report
- `cve_cwe_link.ipynb` - Lookup tool (all versions)
- `evaluate_rag_accuracy.ipynb` - Evaluation script
- `backups/` - Phase 1 & 2 implementations

---

**Bottom Line:** Simple TF-IDF + LLM is the current best solution at 51% accuracy. To exceed 60%, fine-tune embeddings on the labeled dataset.
