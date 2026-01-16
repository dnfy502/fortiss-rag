from __future__ import annotations


class LLMClient:
    def complete(self, prompt: str) -> str:
        raise NotImplementedError


class EchoLLM(LLMClient):
    def complete(self, prompt: str) -> str:
        return f"[echo] {prompt}"
