from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Protocol

from codecforge.errors import CodecForgeError


class LLMProvider(Protocol):
    def generate_json(self, system_prompt: str, user_prompt: str) -> str: ...


_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL | re.IGNORECASE)


def extract_json_object(raw: str) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        raise CodecForgeError("LLM returned empty response")
    text = raw.strip()
    fence_match = _FENCE_RE.search(text)
    if fence_match:
        text = fence_match.group(1).strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise CodecForgeError(f"Response is not valid JSON: {raw[:200]!r}")
        try:
            parsed = json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            raise CodecForgeError(f"Failed to parse JSON object: {exc}") from exc

    if not isinstance(parsed, dict):
        raise CodecForgeError(f"Expected JSON object (dict), got {type(parsed).__name__}")
    return parsed


class GeminiInteractionsProvider:
    def __init__(
        self,
        model: str = "gemini-4-hydrogen",
        api_key: str | None = None,
        endpoint: str = "https://generativelanguage.googleapis.com/v1beta/interactions",
        timeout: float = 60.0,
    ) -> None:
        resolved_key = api_key if api_key is not None else os.environ.get("GEMINI_API_KEY", "")
        if not resolved_key:
            raise CodecForgeError("GEMINI_API_KEY is not set")
        self.model = model
        self.api_key = resolved_key
        self.endpoint = endpoint
        self.timeout = timeout

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model,
            "input": f"{system_prompt}\n\n{user_prompt}",
            "response_format": {"type": "text", "mime_type": "application/json"},
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "x-goog-api-key": self.api_key,
            "Content-Type": "application/json",
            "Api-Revision": "2026-05-20",
        }
        req = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_resp = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise CodecForgeError(
                f"Gemini Interactions HTTP {exc.code}: {detail[:300]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise CodecForgeError(f"Gemini Interactions request failed: {exc}") from exc

        try:
            data = json.loads(raw_resp)
        except json.JSONDecodeError as exc:
            raise CodecForgeError(f"Invalid JSON from Gemini Interactions API: {exc}") from exc

        for step in data.get("steps", []):
            if isinstance(step, dict) and step.get("type") == "model_output":
                for part in step.get("content", []):
                    if isinstance(part, dict) and part.get("type") == "text" and "text" in part:
                        return str(part["text"])

        if isinstance(data.get("output_text"), str):
            return data["output_text"]

        raise CodecForgeError("Gemini Interactions response missing model_output text")


class OpenAICompatibleProvider:
    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        provider_name: str = "openai",
        timeout: float = 60.0,
    ) -> None:
        self.provider_name = provider_name
        self.timeout = timeout
        if provider_name == "ollama":
            self.base_url = (
                base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
            ).rstrip("/")
            self.api_key = api_key if api_key is not None else "ollama"
            self.model = model or "qwen2.5-coder:7b"
        else:
            self.base_url = (
                base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
            ).rstrip("/")
            resolved_key = (
                api_key if api_key is not None else os.environ.get("OPENAI_API_KEY", "")
            )
            if not resolved_key and "api.openai.com" in self.base_url:
                raise CodecForgeError("OPENAI_API_KEY is not set")
            self.api_key = resolved_key
            self.model = model or "gpt-4o-mini"

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        endpoint = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_resp = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise CodecForgeError(
                f"{self.provider_name} HTTP {exc.code}: {detail[:300]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise CodecForgeError(f"{self.provider_name} request failed: {exc}") from exc

        try:
            data = json.loads(raw_resp)
            return str(data["choices"][0]["message"]["content"])
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise CodecForgeError(
                f"Malformed response from {self.provider_name} chat/completions: {exc}"
            ) from exc


class ScriptedMockProvider:
    def __init__(self, responses: list[str | dict[str, Any]]) -> None:
        self._responses = list(responses)
        self._index = 0
        self.calls: list[tuple[str, str]] = []

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        self.calls.append((system_prompt, user_prompt))
        if self._index >= len(self._responses):
            raise CodecForgeError("ScriptedMockProvider exhausted")
        item = self._responses[self._index]
        self._index += 1
        if isinstance(item, dict):
            return json.dumps(item)
        return item


def build_llm_provider(provider_name: str, model: str | None = None) -> LLMProvider:
    if provider_name == "gemini":
        return GeminiInteractionsProvider(model=model or "gemini-4-hydrogen")
    if provider_name == "openai":
        return OpenAICompatibleProvider(model=model, provider_name="openai")
    if provider_name == "ollama":
        return OpenAICompatibleProvider(model=model, provider_name="ollama")
    raise CodecForgeError(f"Unsupported LLM provider: {provider_name!r}")
