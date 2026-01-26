import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Set, Optional

# Path to the CWE XML data
_CWE_XML_PATH = Path(__file__).resolve().parents[2] / "data" / "cwec_v4.19.xml"

@dataclass
class CWENode:
    id: str
    name: str
    abstraction: str  # Pillar, Class, Base, Variant
    parents: Set[str]
    children: Set[str]

class CWEGraph:
    def __init__(self, xml_path: Path = _CWE_XML_PATH):
        self.nodes: Dict[str, CWENode] = {}
        self._load_graph(xml_path)

    def _load_graph(self, xml_path: Path):
        if not xml_path.exists():
             raise FileNotFoundError(f"CWE XML not found at {xml_path}")
        
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = {"cwe": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
        xpath = ".//cwe:Weakness" if ns else ".//Weakness"

        # First pass: Create nodes
        for weakness in root.findall(xpath, ns):
            wid = weakness.get("ID")
            cwe_id = f"CWE-{wid}"
            abstraction = weakness.get("Abstraction", "Unknown")
            name = weakness.get("Name", "")
            
            self.nodes[cwe_id] = CWENode(
                id=cwe_id,
                name=name,
                abstraction=abstraction,
                parents=set(),
                children=set()
            )

        # Second pass: Build relationships
        for weakness in root.findall(xpath, ns):
            wid = weakness.get("ID")
            child_id = f"CWE-{wid}"
            
            rel_xpath = "cwe:Related_Weaknesses/cwe:Related_Weakness" if ns else "Related_Weaknesses/Related_Weakness"
            for rel in weakness.findall(rel_xpath, ns):
                if rel.get("Nature") == "ChildOf":
                    parent_id = f"CWE-{rel.get('CWE_ID')}"
                    if parent_id in self.nodes and child_id in self.nodes:
                        self.nodes[child_id].parents.add(parent_id)
                        self.nodes[parent_id].children.add(child_id)

    def get_ancestors(self, cwe_id: str) -> Set[str]:
        """Return all ancestors of a CWE."""
        ancestors = set()
        queue = [cwe_id]
        visited = {cwe_id}
        
        while queue:
            curr = queue.pop(0)
            if curr not in self.nodes:
                continue
            
            for parent in self.nodes[curr].parents:
                if parent not in visited:
                    visited.add(parent)
                    ancestors.add(parent)
                    queue.append(parent)
        return ancestors

    def get_descendants(self, cwe_id: str) -> Set[str]:
        """Return all descendants of a CWE."""
        descendants = set()
        queue = [cwe_id]
        visited = {cwe_id}
        
        while queue:
            curr = queue.pop(0)
            if curr not in self.nodes:
                continue
            
            for child in self.nodes[curr].children:
                if child not in visited:
                    visited.add(child)
                    descendants.add(child)
                    queue.append(child)
        return descendants

    def score_match(self, truth: str, pred: str) -> tuple[int, str]:
        """
        Score the prediction against the truth.
        Returns (score, description).
        """
        truth = truth.upper().strip()
        pred = pred.upper().strip()

        if truth == pred:
            return 10, "Exact Match"

        if truth not in self.nodes:
            return 0, "Truth Not In Graph (Unknown)"
        
        if pred not in self.nodes:
             # Fallback: exact string match failed, and pred is unknown
             return 0, "Prediction Unknown"

        # Check if Pred is a specific child of Truth (Agent is smarter/more specific)
        descendants = self.get_descendants(truth)
        if pred in descendants:
            return 8, "Specific Child"

        # Check if Pred is a parent of Truth
        ancestors = self.get_ancestors(truth)
        if pred in ancestors:
            abstraction = self.nodes[pred].abstraction
            if abstraction == "Pillar":
                return 1, "Vague Pillar"
            return 5, "Direct Parent/Class"

        # Branch failure
        return 0, "Branch Failure"

# Global instance for ease of use
_GRAPH_INSTANCE = None

def get_cwe_graph() -> CWEGraph:
    global _GRAPH_INSTANCE
    if _GRAPH_INSTANCE is None:
        _GRAPH_INSTANCE = CWEGraph()
    return _GRAPH_INSTANCE
