#!/usr/bin/env python3
import os
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("API_KEY")
API_BASE_URL = "https://ollama.fortiss-demo.org"

def get_token():
    response = requests.post(
        f"{API_BASE_URL}/api/get-token",
        headers={"api-key": API_KEY}
    )
    response.raise_for_status()
    return response.json()["access_token"]

def list_models(token):
    response = requests.get(
        f"{API_BASE_URL}/api/tags",
        headers={"Authorization": f"Bearer {token}"}
    )
    response.raise_for_status()
    return response.json()["models"]

def generate(token, model, prompt):
    response = requests.post(
        f"{API_BASE_URL}/api/generate",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "model": model,
            "prompt": prompt,
            "stream": False
        }
    )
    response.raise_for_status()
    return response.json()["response"]

def chat(token, model, messages):
    response = requests.post(
        f"{API_BASE_URL}/api/chat",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "model": model,
            "messages": messages,
            "stream": False
        }
    )
    response.raise_for_status()
    return response.json()["message"]["content"]

if __name__ == "__main__":
    token = get_token()
    print("✓ Token obtained")

    print("\nAvailable models:")
    models = list_models(token)
    for model in models:
        print(f" - {model['name']}")

    print("\n" + "="*60)
    print("Text Generation:")
    print("="*60)
    print(generate(token, "llama3.2:latest", "Explain platform engineering in 2 sentences."))

    print("\n" + "="*60)
    print("Chat:")
    print("="*60)
    print(chat(
        token,
        "llama3.2:latest",
        [
            {"role": "system", "content": "You are a concise AI assistant."},
            {"role": "user", "content": "What is Kubernetes?"}
        ]
    ))
