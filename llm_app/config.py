from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    model_name: str = os.getenv("LLM_MODEL", "gpt-4o-mini")
    temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    use_langgraph: bool = os.getenv("LLM_USE_LANGGRAPH", "1") == "1"


def load_settings() -> Settings:
    return Settings()
