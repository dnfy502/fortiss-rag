from __future__ import annotations

import os

from .registry import ToolRegistry


def register_tools(registry: ToolRegistry) -> None:
    @registry.register("list_dir", "List files in a directory.")
    def list_dir(path: str = ".") -> list[str]:
        return sorted(os.listdir(path))

    @registry.register("read_file", "Read a text file, truncated to max_chars.")
    def read_file(path: str, max_chars: int = 2000) -> str:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read(max_chars)
