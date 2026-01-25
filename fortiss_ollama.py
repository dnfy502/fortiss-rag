import os
import time
from typing import Optional

import requests
from dotenv import load_dotenv

API_BASE_URL = "https://ollama.fortiss-demo.org"


class OllamaClient:
    def __init__(self, api_key: Optional[str] = None, api_base_url: str = API_BASE_URL):
        load_dotenv()
        self.api_key = api_key or os.getenv("API_KEY")
        if not self.api_key:
            raise ValueError("API key missing. Set API_KEY in .env or pass api_key.")
        self.api_base_url = api_base_url.rstrip("/")
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

    def _get_auth_token(self) -> str:
        response = requests.post(
            f"{self.api_base_url}/api/get-token",
            headers={"api-key": self.api_key},
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        self._token = payload["access_token"]
        # Refresh a bit early to avoid edge timing issues.
        self._token_expiry = time.time() + int(payload.get("expires_in", 3600)) - 60
        return self._token

    def _get_valid_token(self) -> str:
        if not self._token or time.time() >= self._token_expiry:
            return self._get_auth_token()
        return self._token

    def generate_text(
        self,
        prompt: str,
        model: str = "llama3.2:latest",
        stream: bool = False,
        temperature: Optional[float] = None,
    ) -> str:
        token = self._get_valid_token()
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": stream,
        }
        if temperature is not None:
            payload["temperature"] = temperature
        response = requests.post(
            f"{self.api_base_url}/api/generate",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()
        return data["response"]


def generate_text(
    prompt: str,
    model: str = "llama3.2:latest",
    stream: bool = False,
    temperature: Optional[float] = None,
    api_key: Optional[str] = None,
) -> str:
    client = OllamaClient(api_key=api_key)
    return client.generate_text(
        prompt=prompt,
        model=model,
        stream=stream,
        temperature=temperature,
    )

if __name__ == "__main__":
    time_start = time.time()
    prompt = "Explain npm's package lock file in 3 sentences."
    print(generate_text(prompt, model = 'gpt-oss:120b'))
    time_end = time.time()
    print(f"Time taken: {time_end - time_start} seconds")