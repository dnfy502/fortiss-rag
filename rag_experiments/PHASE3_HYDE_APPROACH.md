# Phase 3: HyDE (Hypothetical Document Embeddings)

**Date:** January 13, 2026  
**Status:** Implemented - Ready for Testing

---

## What is HyDE?

**HyDE (Hypothetical Document Embeddings)** is a retrieval technique that instead of using the query directly, generates a **hypothetical answer document** and uses that for retrieval.

### Applied to CVE→CWE Matching

Instead of:
1. ❌ CVE description → Retrieval → CWE match

We do:
2. ✅ CVE description → **Generate hypothetical CWE definition** → Retrieval → CWE match

---

## Key Difference from Phase 2 (Abstraction)

| Aspect | Phase 2 (Abstraction) | Phase 3 (HyDE) |
|--------|----------------------|----------------|
| **Goal** | Make CVE more generic | Generate CWE-style definition |
| **Output** | Abstract pattern | CWE-style weakness description |
| **Style** | Generic security terms | Matches CWE writing style |
| **Focus** | Remove specifics | Write as if authoring a CWE |

### Example Comparison

**CVE Input:**
> "SQL injection vulnerability in login.php via username parameter allows unauthorized database access"

**Phase 2 Output (Abstraction):**
> "Improper input validation leading to unauthorized access"

**Phase 3 Output (HyDE):**
> "The product constructs SQL queries using externally-influenced input without proper neutralization of special elements, allowing attackers to modify the intended SQL command structure."

**Why HyDE is better:**
- ✅ Matches CWE writing conventions ("The product...")
- ✅ Uses CWE-specific terminology ("neutralization", "special elements")
- ✅ Same document type (definition → definition)
- ✅ More likely to match actual CWE text

---

## Implementation Details

### HyDE Prompt

```
You are a CWE (Common Weakness Enumeration) author writing weakness definitions.
Return ONLY the weakness definition text. Do not add explanations or markdown.

TASK: Given this vulnerability instance, write a CWE-style weakness definition.

VULNERABILITY INSTANCE:
[CVE description]

INSTRUCTIONS:
- Write in CWE style: describe the weakness TYPE, not the specific instance
- Start with 'The product...' or 'The software...' (like real CWE definitions)
- Remove specific product names and versions
- Focus on what the SOFTWARE does wrong (not what attackers do)
- Use CWE terminology: 'improper validation', 'insufficient verification', etc.
- Keep it 2-4 sentences

Example:
  CVE: 'SQL injection in login.php via username parameter'
  CWE-style: 'The product constructs SQL queries using externally-influenced 
              input without proper neutralization of special elements, allowing 
              attackers to modify the intended SQL command structure.'

WEAKNESS DEFINITION:
```

### Key Prompt Elements

1. **Role**: "CWE author" (not "security analyst")
2. **Task**: "Write CWE-style definition" (not "abstract the CVE")
3. **Style Guide**: "The product..." convention
4. **Terminology**: CWE-specific vocabulary
5. **Example**: Shows exact transformation expected

---

## Why HyDE Should Work Better

### 1. Document Type Alignment
- **Problem**: CVE (instance description) ≠ CWE (weakness definition)
- **Solution**: Generate CWE-style definition from CVE
- **Result**: Definition → Definition matching

### 2. Vocabulary Alignment
- **Problem**: CVE uses incident language, CWE uses taxonomy language
- **Solution**: LLM translates to CWE vocabulary
- **Result**: "SQL injection" → "improper neutralization of special elements"

### 3. Style Matching
- **Problem**: CVE is attacker-focused, CWE is software-focused
- **Solution**: Reframe from software perspective ("The product does X wrong")
- **Result**: Matches how CWEs are actually written

### 4. Abstraction Level
- **Problem**: CVE too specific, CWE too abstract
- **Solution**: LLM finds the right abstraction level
- **Result**: Removes "libpng 1.2.3" but keeps "buffer overflow"

---

## Expected Improvements Over Phase 2

### Phase 2 Problems (Abstraction):
- ❌ Over-abstracted: Lost critical technical terms
- ❌ Inconsistent: Different terms for same concepts
- ❌ Generic: "Improper input validation" matches everything poorly
- ❌ Results: 58% top-10, 21% top-1, 44% LLM

### Phase 3 Advantages (HyDE):
- ✅ Preserves technical terms in CWE style
- ✅ Consistent: Follows CWE writing conventions
- ✅ Specific: Maintains weakness type information
- ✅ Expected: 65-70% top-10? (hypothesis to test)

---

## Examples

### Example 1: Buffer Overflow

**CVE:**
> "A buffer overflow vulnerability in libpng version 1.2.3 allows remote attackers to execute arbitrary code via a crafted PNG file."

**HyDE Generated:**
> "The product writes data past the end or before the beginning of an allocated buffer when processing image data, allowing attackers to execute arbitrary code or cause a denial of service."

**Matches:**
- CWE-787: Out-of-bounds Write ✓
- CWE-120: Buffer Copy without Checking Size of Input ✓

### Example 2: SQL Injection

**CVE:**
> "SQL injection vulnerability in the user authentication module via the username parameter."

**HyDE Generated:**
> "The product constructs SQL queries using externally-influenced input without proper neutralization of SQL special characters, allowing attackers to modify the intended query logic and access unauthorized data."

**Matches:**
- CWE-89: SQL Injection ✓
- CWE-943: Improper Neutralization of Special Elements used in SQL Commands ✓

### Example 3: Path Traversal

**CVE:**
> "Directory traversal vulnerability allows remote attackers to read arbitrary files via '../' sequences in the filename parameter."

**HyDE Generated:**
> "The product uses external input to construct pathname that should be within a restricted directory, but does not properly neutralize sequences such as '..' that can resolve to a location outside that directory."

**Matches:**
- CWE-22: Path Traversal ✓
- CWE-23: Relative Path Traversal ✓

---

## Configuration

### In `cve_cwe_link.ipynb`:
```python
lookup_cve_hybrid(
    "CVE-2024-0001",
    top_k=5,
    run_llm=True,
    use_hyde=True,  # Enable HyDE
    ollama_model="mistral:7b-instruct",
)
```

### In `evaluate_rag_accuracy.ipynb`:
```python
USE_HYDE = True
HYDE_TIMEOUT_S = 60
MAX_RECORDS = 100  # Start small to test
```

---

## Testing Plan

### Step 1: Interactive Test
```bash
# Open cve_cwe_link.ipynb
# Run all cells
# Observe HyDE output for test example
# Compare generated CWE-style text to actual CWEs
```

### Step 2: Small Evaluation
```bash
# In evaluate_rag_accuracy.ipynb
MAX_RECORDS = 20  # Quick test
USE_HYDE = True
# Run and observe:
# - HyDE generation quality
# - Retrieval improvement
# - Any failures/timeouts
```

### Step 3: Full Evaluation
```bash
MAX_RECORDS = 100
USE_HYDE = True
# Compare to Phase 2:
# Phase 2: 58% top-10, 21% top-1, 44% LLM
# Phase 3: ???
```

---

## Success Criteria

### Minimum (Better than Phase 2):
- Top-10 > 58%
- Top-1 > 21%
- LLM > 44%

### Target (Better than Baseline):
- Top-10 > 62%
- Top-1 > 33%
- LLM > 51%

### Stretch (Breaking the Ceiling):
- Top-10 > 70%
- Top-1 > 40%
- LLM > 60%

---

## If HyDE Fails

### Possible Issues:
1. **LLM doesn't know CWE style well enough**
   - Solution: Add more examples to prompt (few-shot)
   - Solution: Use larger/better model (GPT-4)

2. **Generated definitions too verbose**
   - Solution: Add length constraint to prompt
   - Solution: Post-process to first 2 sentences

3. **Still over-abstracts**
   - Solution: Instruct to keep technical terms
   - Solution: Add negative examples

4. **Inconsistent quality**
   - Solution: Temperature=0 for deterministic output
   - Solution: Multiple generations + voting

### Next Steps After HyDE:
If HyDE doesn't break 60%:
- **Fine-tune embeddings** remains the best path forward
- Expected: 75-85% with domain training
- HyDE + Fine-tuned embeddings could be 80-90%

---

## Files Updated

### Backed Up (Phase 2):
- `backups/cve_cwe_link_phase2_abstraction.ipynb`
- `backups/evaluate_rag_accuracy_phase2_abstraction.ipynb`

### Current (Phase 3 - HyDE):
- `cve_cwe_link.ipynb` - Updated with HyDE
- `evaluate_rag_accuracy.ipynb` - Updated with HyDE

### All Backups:
- `backups/cve_cwe_link_backup_20260112_230519.ipynb` - Original baseline
- `backups/cve_cwe_link_phase1_hybrid_retrieval.ipynb` - BM25+SBERT
- `backups/cve_cwe_link_phase2_abstraction.ipynb` - Abstraction
- (Same for evaluate_rag_accuracy)

---

## Technical Notes

### HyDE vs Traditional Query Expansion

| Technique | Method | Output |
|-----------|--------|--------|
| **Query Expansion** | Add synonyms | "SQL injection OR query injection OR improper neutralization" |
| **Abstraction (P2)** | Generalize | "Improper input validation" |
| **HyDE (P3)** | Generate document | Full CWE-style definition paragraph |

HyDE is more powerful because:
- Generates dense text (not just keywords)
- Matches target document style
- Preserves semantic richness

### Retriever Choice

Still using **TF-IDF** (not SBERT) because:
- Phase 1 showed SBERT didn't help (56% vs 57%)
- TF-IDF good at matching technical terms
- HyDE should work with any retriever
- Can test SBERT later if HyDE improves TF-IDF results

---

## References

### Original HyDE Paper:
- **Title**: "Precise Zero-Shot Dense Retrieval without Relevance Labels"
- **Authors**: Gao et al., 2022
- **Key Idea**: Generate hypothetical answer, use for retrieval
- **Domains Tested**: Question answering, fact verification
- **Results**: +10-20% improvement over direct query

### Adapted for CVE→CWE:
- **Query**: CVE instance description
- **Hypothetical Document**: CWE-style weakness definition
- **Corpus**: Actual CWE definitions
- **Expected**: Better matching due to style/vocabulary alignment

---

**Ready to test!** Run the evaluation and see if HyDE breaks through the ceiling. 🚀

Good luck!
