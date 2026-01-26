from __future__ import annotations

import json
from pathlib import Path
from .model import LLMClient
from ..tools.registry import ToolRegistry
from pydantic import BaseModel, Field, ValidationError
from typing import Literal


class ToolCall(BaseModel):
    tool: str
    args: dict
    thought: str | None = None


class FinalAttackAssignment(BaseModel):
    attack_ids: list[str] = Field(description="The list of ATT&CK technique IDs, e.g., ['T1059.007']")
    confidence: Literal["High", "Medium", "Low"]
    logic_chain: str = Field(description="Why these specific techniques?")


class Agent:
    def __init__(
        self,
        llm: LLMClient,
        registry: ToolRegistry,
        max_steps: int = 15,
        verbose: bool = False,
    ) -> None:
        self._llm = llm
        self._registry = registry
        self._max_steps = max_steps
        self._verbose = verbose
        self._system_prompt = self._load_system_prompt()

    def run(self, prompt: str) -> str:
        messages = [
            {"role": "system", "content": self._system_prompt},
            {"role": "user", "content": prompt},
        ]

        tool_history: list[str] = []
        search_history: set[str] = set()

        tool_history: list[str] = []
        search_history: set[str] = set()

        total_steps = 0
        while total_steps < self._max_steps:
            current_step = total_steps + 1
            
            # Force a decision if we are at the last step
            if current_step == self._max_steps:
                 messages.append({
                     "role": "system",
                     "content": "You have reached the maximum number of steps. You MUST now call 'provide_attack_match' with your best current conclusion.",
                 })

            rendered = self._render_messages(messages)
            response = self._llm.complete(rendered)
            
            # Skip step counting for empty responses
            if not response or not response.strip():
                if self._verbose:
                    print(f"DEBUG: Empty response at step attempt. Retrying without consuming step.")
                messages.append({
                    "role": "system",
                    "content": "You sent an empty response. Please respond with a valid JSON tool call."
                })
                continue

            total_steps += 1
            
            if self._verbose:
                print(f"STEP {total_steps} MODEL_RESPONSE: {response!r}")
            
            parsed = self._parse_tool_requests(response)
            if parsed is None:
                # No JSON found. Remind the model.
                # SYSTEM TRAP: If they wrote a lot of text but called no tool, they might be trying to answer in text.
                if len(response) > 50:
                    messages.append({
                        "role": "system",
                        "content": "You seem to have found the answer, but you didn't call the 'provide_attack_match' tool. Please submit your findings now using the correct JSON tool format."
                    })
                else:
                    messages.append(
                        {
                            "role": "system",
                            "content": "You must respond with a valid JSON tool call. Format: {\"tool\": \"...\", \"args\": {...}, \"thought\": \"...\"}",
                        }
                    )
                continue

            tool_requests, had_extra, validation_error = parsed
            
            # Check for text outside JSON -> warn about it
            if had_extra:
                messages.append(
                    {
                        "role": "system",
                        "content": "Tool calls must be strictly JSON. Do not include introductory text or markdown fencing outside the JSON.",
                    }
                )
            
            if validation_error:
                messages.append({"role": "system", "content": validation_error})
                continue

            # Enforce exclusivity for final answer
            tool_names = [req.tool for req in tool_requests]
            if "provide_attack_match" in tool_names and len(tool_requests) > 1:
                messages.append({
                    "role": "system", 
                    "content": "Error: You cannot call 'provide_attack_match' simultaneously with other tools. You must wait for other tool results before providing the final answer. If you are ready to answer, call only 'provide_attack_match'."
                })
                continue

            for idx, tool_request in enumerate(tool_requests, start=1):
                tool_name = tool_request.tool
                tool_args = tool_request.args
                
                # Check for termination tool
                if tool_name == "provide_attack_match":
                    if self._verbose:
                        print(f"DEBUG: tool_history={tool_history}")
                    # Validation: check if they actually searched/looked up attacks
                    if "get_attack_information" not in tool_history and "attack_search_keyword" not in tool_history and "attack_search_vector" not in tool_history:
                         warn_msg = "You must search for or verify ATT&CK techniques before finalizing (e.g., call 'get_attack_information')."
                         messages.append({
                             "role": "system", 
                             "content": warn_msg
                         })
                         if self._verbose:
                             print(f"DEBUG: Rejected provide_attack_match. Message: {warn_msg}")
                         continue
                    
                    # Success! Return the args as the final answer.
                    return json.dumps(tool_args)

                if tool_name == "get_cwe_information" and "result" in payload:
                    payload["result"] = self._format_cwe_result(payload["result"])

                if self._verbose:
                    print(
                        f"STEP {total_steps} TOOL_CALL {idx}/{len(tool_requests)}:",
                        json.dumps({"tool": tool_name, "args": tool_args}),
                    )
                
                tool = self._registry.get(tool_name)
                if tool is None:
                    messages.append(
                        {
                            "role": "system",
                            "content": f"Tool '{tool_name}' not found. Available tools: {self._registry.list_tools()}",
                        }
                    )
                    continue

                # --- CIRCUIT BREAKER: Query Deduplication ---
                if tool_name in ["attack_search_vector", "attack_search_keyword"]:
                    query = tool_args.get("query", "").lower().strip()
                    if query in search_history:
                        # Intercept calls - do NOT run the tool
                        msg = (
                            f"SYSTEM MONITOR: You have already searched for '{query}'. "
                            "This yielded no useful results or you are repeating yourself. "
                            "STOP. Do not retry this term. "
                            "Pivot to a mechanism (e.g., 'User Execution', 'Drive-by')."
                        )
                        payload = {"tool": tool_name, "error": msg}
                        messages.append({"role": "tool", "content": json.dumps(payload)})
                        if self._verbose:
                             print(f"DEBUG: Circuit Breaker triggered for query '{query}'")
                        continue
                    else:
                        search_history.add(query)
                # --------------------------------------------

                try:
                    result = tool.func(**tool_args)
                    # Payload creation
                    payload = {"tool": tool_name, "result": result}
                except Exception as exc:
                    payload = {"tool": tool_name, "error": str(exc)}

                # Smart formatting/truncation
                if tool_name == "get_cwe_information" and "result" in payload:
                    payload["result"] = self._format_cwe_result(payload["result"])

                if self._verbose:
                    print(
                        f"STEP {total_steps} TOOL_RESULT {idx}/{len(tool_requests)}:",
                        self._summarize_payload(payload),
                    )
                
                messages.append({"role": "tool", "content": json.dumps(payload)})
                tool_history.append(tool_name)

        return json.dumps({
            "error": "Unable to complete within tool step limit.",
            "status": "Incomplete"
        })

    def _render_messages(self, messages: list[dict[str, str]]) -> str:
        rendered = []
        for message in messages:
            role = message.get("role", "user").upper()
            content = message.get("content", "")
            rendered.append(f"{role}: {content}")
        return "\n\n".join(rendered)

    def _parse_tool_requests(
        self, response: str
    ) -> tuple[list[ToolCall], bool, str] | None:
        """
        Robustly find JSON objects in the text.
        Returns (list[ToolCall], had_extra_text, error_message).
        """
        text = response.strip()
        if not text:
            return None

        decoder = json.JSONDecoder()
        idx = 0
        tool_calls: list[ToolCall] = []
        had_extra = False
        
        # Simple scan for '{'
        while True:
            idx = text.find("{", idx)
            if idx == -1:
                break
            
            # Check if there was text before this brace that wasn't whitespace
            if idx > 0 and text[:idx].strip():
                had_extra = True
                
            try:
                data, end = decoder.raw_decode(text[idx:])
                idx += end
                
                # Check for array of calls vs single call
                if isinstance(data, list):
                    # Not supporting list of calls at root level per strict prompt, 
                    # but if model does it, we could handle it. 
                    # For now, let's assume one JSON object per tool call or single object.
                    pass 
                
                if isinstance(data, dict):
                    # Robustness fix: Handle flattened arguments
                    # If "tool" is in data but "args" is NOT, assume all other keys are arguments.
                    if "tool" in data and "args" not in data:
                        reserved = {"tool", "thought"}
                        reconstructed_args = {k: v for k, v in data.items() if k not in reserved}
                        if reconstructed_args:
                            if self._verbose:
                                print(f"DEBUG: reconstructing flat JSON for {data['tool']}")
                            data["args"] = reconstructed_args

                    try:
                        tool_call = ToolCall.model_validate(data)
                        if not tool_call.args:
                             return [], had_extra, "Invalid tool call. 'args' must not be empty."
                        tool_calls.append(tool_call)
                    except ValidationError as ve:
                        if self._verbose:
                            print(f"DEBUG: JSON validation failed for '{data}': {ve}")
                        # might be a result or something else, but we expect tool calls
                        pass
                        
            except json.JSONDecodeError:
                idx += 1 # Advance past this brace to find next
                continue

        if not tool_calls:
            return None
            
        return tool_calls, had_extra, ""

    def _summarize_payload(self, payload: dict) -> str:
        text = json.dumps(payload)
        if len(text) <= 600:
            return text
        return text[:600] + "...(truncated)"
    
    # Replaces _parse_final_answer (deleted)

    def _format_cwe_result(self, result: object) -> object:
        """
        Smart formatting for CWE records to keep prompt size manageable 
        while retaining critical decision info.
        """
        if not isinstance(result, dict):
            return result
        
        # If it's an error dict
        if "error" in result:
            return result
        
        # We want to keep: 
        # id, name, description, extended_description, related_weaknesses
        # modes_of_introduction, common_consequences (maybe summarized)
        
        formatted = {}
        keep_fields = ["id", "name", "abstraction", "structure", "status", "description", "extended_description", "related_weaknesses"]
        
        for k in keep_fields:
            if k in result:
                formatted[k] = result[k]

        # Summarize lists
        if "observed_examples" in result and isinstance(result["observed_examples"], list):
            # Keep top 3
            examples = result["observed_examples"]
            formatted["observed_examples"] = examples[:3]
            if len(examples) > 3:
                formatted["observed_examples"].append(f"... (+{len(examples)-3} more)")
        
        # Truncate potentially huge text fields in lists
        truncatable_lists = ["background_details", "modes_of_introduction", "common_consequences", "detection_methods", "potential_mitigations"]
        for field in truncatable_lists:
            if field in result and isinstance(result[field], list):
                # Join and truncate total length for this section
                joined = "; ".join(result[field])
                if len(joined) > 500:
                    formatted[field] = joined[:500] + "...(truncated)"
                else:
                    formatted[field] = joined
        
        if "alternate_terms" in result:
            formatted["alternate_terms"] = result["alternate_terms"]

        return formatted

    def _load_system_prompt(self) -> str:
        prompt_path = Path(__file__).resolve().parents[1] / "prompts" / "system.txt"
        return prompt_path.read_text(encoding="utf-8")
