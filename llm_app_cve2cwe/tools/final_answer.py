from typing import Literal
from .registry import ToolRegistry

def register_tools(registry: ToolRegistry) -> None:
    @registry.register(
        "provide_cwe_match",
        "Submit the final CWE assignment for the CVE. This ends the session."
    )
    def provide_cwe_match(
        cwe_id: str,
        confidence: Literal["High", "Medium", "Low"],
        rationale: str
    ) -> str:
        """
        Record the final decision.
        
        Args:
            cwe_id: The specific ID, e.g., 'CWE-564'.
            confidence: Confidence level in this assignment.
            rationale: Explanation of the logic chain used to reach this conclusion, including why generic parents were rejected.
        """
        # In a real app, this might save to a DB. 
        # Here we just return a success message that the agent loop will detect to stop.
        return "Match recorded."
