from typing import Literal, List
from .registry import ToolRegistry

def register_tools(registry: ToolRegistry) -> None:
    @registry.register(
        "provide_attack_match",
        "Submit the final ATT&CK technique assignment for the CWE. This ends the session."
    )
    def provide_attack_match(
        attack_ids: List[str],
        confidence: Literal["High", "Medium", "Low"],
        rationale: str
    ) -> str:
        """
        Record the final decision.
        
        Args:
            attack_ids: A LIST of ATT&CK T-codes (e.g. ["T1203", "T1068"]).
            confidence: "High", "Medium", or "Low".
            rationale: A single string explaining why these IDs were chosen.
        """
        # In a real app, this might save to a DB. 
        # Here we just return a success message that the agent loop will detect to stop.
        return f"Match recorded: {attack_ids}"

