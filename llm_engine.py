"""Cloud LLM integration (OpenAI / Groq) for phishing email analysis."""

import json
import os
from typing import Optional, Tuple

from openai import OpenAI

DEFAULT_PROVIDER = "groq"  # "groq" or "openai"
DEFAULT_MODEL_OPENAI = "gpt-4o-mini"
DEFAULT_MODEL_GROQ = "llama-3.1-8b-instant"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RETRIES = 2

_client_cache: dict[Tuple[str, str, str, float, int], OpenAI] = {}


def _provider_config(provider: str) -> tuple[str, str]:
    """
    Returns (api_key_env_var, base_url).
    For OpenAI, base_url is empty string meaning default OpenAI endpoint.
    """
    p = (provider or "").strip().lower()
    if p == "openai":
        return "OPENAI_API_KEY", ""
    if p == "groq":
        return "GROQ_API_KEY", "https://api.groq.com/openai/v1"
    raise ValueError("provider must be 'openai' or 'groq'")


def _get_client(
    provider: str,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> OpenAI:
    """Get a cached client for a provider + key + options."""
    api_key_env, base_url = _provider_config(provider)
    api_key = os.getenv(api_key_env, "")
    if not api_key:
        raise RuntimeError(f"{api_key_env} environment variable is not set.")

    # Include api_key in cache key so changes take effect without restart.
    cache_key = (provider, base_url, api_key, float(timeout_seconds), int(max_retries))
    if cache_key in _client_cache:
        return _client_cache[cache_key]

    if base_url:
        client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout_seconds, max_retries=max_retries)
    else:
        client = OpenAI(api_key=api_key, timeout=timeout_seconds, max_retries=max_retries)

    _client_cache[cache_key] = client
    return client


def _build_prompt(email_text: str, url_count: int, keyword_list: list) -> str:
    """Build analysis prompt for the LLM."""
    keyword_str = ", ".join(keyword_list) if keyword_list else "None detected"
    return f"""Analyze this email for phishing indicators.

EMAIL:
---
{email_text}
---

Pre-analysis: {url_count} URL(s) found, suspicious keywords: {keyword_str}

Respond in JSON format only:
{{
  "classification": "Phishing" | "Suspicious" | "Safe",
  "risk_score": 0-100,
  "reasoning": "Brief explanation of why"
}}"""


def analyze_email(
    email_text: str,
    url_count: int = 0,
    keyword_list: Optional[list] = None,
    provider: str = DEFAULT_PROVIDER,
    model: Optional[str] = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> dict:
    """
    Use a cloud LLM (OpenAI or Groq) to analyze email for phishing.
    Returns dict with classification, risk_score, reasoning.
    """
    keyword_list = keyword_list or []
    prompt = _build_prompt(email_text, url_count, keyword_list)

    p = (provider or DEFAULT_PROVIDER).strip().lower()
    if model is None or not str(model).strip():
        model = DEFAULT_MODEL_OPENAI if p == "openai" else DEFAULT_MODEL_GROQ

    try:
        client = _get_client(provider=p, timeout_seconds=timeout_seconds, max_retries=max_retries)
    except (RuntimeError, ValueError) as e:
        return {
            "classification": "Unknown",
            "risk_score": 0,
            "reasoning": str(e),
        }

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a security analyst that detects phishing emails. "
                    "Always respond with STRICT JSON only, no Markdown.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=300,
        )
        raw = (response.choices[0].message.content or "").strip()
    except Exception as e:  # Broad on purpose to surface any client/API error
        msg = str(e)
        if "timed out" in msg.lower() or "timeout" in msg.lower():
            msg = (
                "Request timed out. This is usually caused by slow/blocked internet, a corporate proxy/firewall, "
                "or an unreachable API endpoint. Try increasing the timeout in the app sidebar, "
                "or run from a network that allows outbound HTTPS to the LLM provider."
            )
        return {
            "classification": "Unknown",
            "risk_score": 0,
            "reasoning": f"LLM unavailable or API error: {msg}",
        }

    # Parse JSON from response
    raw_clean = raw
    if "```json" in raw:
        raw_clean = raw.split("```json")[1].split("```")[0].strip()
    elif "```" in raw:
        raw_clean = raw.split("```")[1].split("```")[0].strip()

    try:
        result = json.loads(raw_clean)
        risk_score = int(result.get("risk_score", 0))
        if risk_score < 0:
            risk_score = 0
        if risk_score > 100:
            risk_score = 100
        return {
            "classification": result.get("classification", "Unknown"),
            "risk_score": risk_score,
            "reasoning": result.get("reasoning", "No explanation provided."),
        }
    except (json.JSONDecodeError, ValueError):
        return {
            "classification": "Unknown",
            "risk_score": 0,
            "reasoning": f"Could not parse LLM response: {raw[:200]}...",
        }


def is_llm_available() -> bool:
    """
    Lightweight availability check.
    For now, we just ensure the required API key is set.
    """
    provider = (os.getenv("LLM_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    try:
        api_key_env, _ = _provider_config(provider)
    except ValueError:
        return False
    return bool(os.getenv(api_key_env))


def is_provider_available(provider: str) -> bool:
    """Availability check for a specific provider (e.g., 'groq')."""
    try:
        api_key_env, _ = _provider_config(provider)
    except ValueError:
        return False
    return bool(os.getenv(api_key_env))
