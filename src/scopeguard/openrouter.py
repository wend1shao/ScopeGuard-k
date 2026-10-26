from __future__ import annotations

import os
from typing import Any

import openai


def build_openrouter_client() -> openai.OpenAI:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is required for live experiments")

    headers: dict[str, str] = {}
    if site_url := os.getenv("OPENROUTER_SITE_URL"):
        headers["HTTP-Referer"] = site_url
    if app_name := os.getenv("OPENROUTER_APP_NAME"):
        headers["X-Title"] = app_name

    return openai.OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        default_headers=headers or None,
        timeout=120.0,
        max_retries=3,
    )


def model_dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value

