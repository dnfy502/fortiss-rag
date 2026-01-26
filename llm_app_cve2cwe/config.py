from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    model_name: str = os.getenv("LLM_MODEL", "gpt-oss:120b")
    temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    verbose: bool = os.getenv("LLM_VERBOSE", "0") == "1"


def load_settings() -> Settings:
    return Settings()
