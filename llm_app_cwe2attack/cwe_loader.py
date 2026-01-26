from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Any

# Add project root to sys.path to ensure we can import mapping_agent
# This assumes the structure:
# Fortiss/
#   llm_app_cwe2attack/
#   mapping_agent/
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

try:
    from mapping_agent.lookups.object_lookup import ObjectLookup
except ImportError:
    # Fallback/Error handling if mapping_agent is not found
    print("Warning: mapping_agent module not found. Please ensure it is in the python path.")
    ObjectLookup = None


class CWELoader:
    def __init__(self):
        if ObjectLookup is None:
            raise RuntimeError("Cannot load CWEs: mapping_agent.lookups.object_lookup not importable.")
        
        # We assume data is in Fortiss/mapping_agent/data/output
        # The ObjectLookup default might need a path or we rely on main passing it?
        # ObjectLookup takes `data_dir`.
        self.data_dir = PROJECT_ROOT / "mapping_agent" / "data" / "output"
        self.lookup = ObjectLookup(str(self.data_dir))

    def get_cwe(self, cwe_id: str) -> Dict[str, Any]:
        """
        Get full CWE object by ID.
        Accepts "CWE-123" or "123".
        """
        clean_id = cwe_id.upper().replace("CWE-", "").strip()
        # ObjectLookup expects just the number string for CWE keys based on previous file read?
        # Let's verify `cwe_parsed.json` keys format in ObjectLookup usage demo...
        # Demo said: cwe_obj = lookup.get_cwe("89") -> ID: CWE-89. So keys are likely "89".
        
        return self.lookup.get_cwe(clean_id)


def build_cwe_prompt(cwe_id: str, record: Dict[str, Any]) -> str:
    """
    Construct a prompt for the agent based on the CWE record.
    """
    if not record:
        return f"CWE ID: {cwe_id}\nError: CWE record not found."

    lines = [f"CWE ID: CWE-{record.get('cwe_id', 'Unknown')}"]
    lines.append(f"Name: {record.get('name', 'n/a')}")
    lines.append(f"Abstraction: {record.get('abstraction', 'n/a')}")
    
    desc = record.get('description', '')
    if desc:
        lines.append(f"Description:\n{desc}")
        
    ext_desc = record.get('extended_description', '')
    if ext_desc:
        lines.append(f"Extended Description:\n{ext_desc}")

    # Add related weaknesses if useful?
    # For now, keep it simple as the user wants to map to ATT&CK.

    lines.append("\nTask: Identify relevant MITRE ATT&CK techniques that an adversary might use to exploit this weakness.")
    return "\n".join(lines)
