import json
import random
from pathlib import Path
from typing import List, Dict, Optional

# Path to CVE Data
_CVE_ROOT = Path(__file__).resolve().parents[2] / "data" / "cvelistV5-main" / "cves"

def _extract_cwe(record: dict) -> Optional[str]:
    """Extract the first valid CWE ID from a CVE record."""
    containers = record.get("containers", {})
    
    # Check CNA first (primary source)
    cna = containers.get("cna", {})
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId")
            if cwe_id and cwe_id.startswith("CWE-"):
                return cwe_id
            # sometimes it's in description text, but let's rely on structured ID first
            
    # Check ADP (secondary source)
    adp_list = containers.get("adp", [])
    for adp in adp_list:
        if not isinstance(adp, dict):
             continue
        for pt in adp.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")
                if cwe_id and cwe_id.startswith("CWE-"):
                    return cwe_id

    return None

def get_random_cves(n: int = 20) -> List[Dict]:
    """
    Select N random CVEs that have a valid CWE mapping.
    Start from recent years to be relevant.
    """
    if not _CVE_ROOT.exists():
        raise FileNotFoundError(f"CVE data not found at {_CVE_ROOT}")

    # Gather ALL json files efficiently
    # To avoid scanning 200k+ files every time, we can limit to recent years
    # or just accept the scan time (it's fast enough on local usually).
    # Let's target 2023 and 2024 for relevance first.
    pass

    years = ["2024", "2023", "2022", "2021", "2020", "2019"]
    candidates = []
    
    for year in years:
        year_dir = _CVE_ROOT / year
        if not year_dir.exists():
            continue
        # Use rglob but limit it slightly to avoid massive wait? No, rglob is fine on subset.
        candidates.extend(list(year_dir.rglob("*.json")))

    if len(candidates) < n:
        # Fallback to broad scan if we don't have enough candidates
        candidates = list(_CVE_ROOT.rglob("*.json"))

    random.shuffle(candidates)
    
    dataset = []
    for path in candidates:
        if len(dataset) >= n:
            break
            
        try:
            content = path.read_text(encoding="utf-8")
            record = json.loads(content)
            cwe_id = _extract_cwe(record)
            
            if cwe_id:
                cve_metadata = record.get("cveMetadata", {})
                cve_id = cve_metadata.get("cveId", path.stem)
                dataset.append({
                    "cve_id": cve_id,
                    "truth_cwe": cwe_id
                })
        except Exception:
            continue
            
    return dataset
