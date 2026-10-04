"""Local dashboard settings for scanner and cloud AI connections."""

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .storage import data_dir


def _settings_path() -> Path:
    return data_dir() / "app-settings.json"


def load_app_settings() -> dict[str, str]:
    """Load saved settings; environment values are defaults for fresh installs."""
    ai_base_url = os.environ.get("SOC_AI_BASE_URL", "https://api.openai.com")
    # Do not carry forward the old local Ollama URL as the cloud default.
    if urlparse(ai_base_url).hostname in {"localhost", "127.0.0.1", "::1"}:
        ai_base_url = "https://api.openai.com"
    settings = {
        "burp_api_url": os.environ.get("BURP_API_URL", "http://127.0.0.1:1337"),
        "burp_api_key": os.environ.get("BURP_API_KEY", ""),
        "ai_base_url": ai_base_url,
        "ai_model": os.environ.get("SOC_AI_MODEL", "gpt-4o-mini"),
        "ai_api_key": os.environ.get("SOC_AI_API_KEY", ""),
    }
    path = _settings_path()
    if path.is_file():
        try:
            saved: Any = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return settings
        if isinstance(saved, dict):
            for name in settings:
                if isinstance(saved.get(name), str):
                    settings[name] = saved[name]
    if urlparse(settings["ai_base_url"]).hostname in {"localhost", "127.0.0.1", "::1"}:
        settings["ai_base_url"] = "https://api.openai.com"
    if urlparse(settings["ai_base_url"]).scheme != "https":
        settings["ai_base_url"] = "https://api.openai.com"
    if settings["ai_model"].casefold().startswith("llama"):
        settings["ai_model"] = "gpt-4o-mini"
    return settings


def save_burp_settings(api_url: str, api_key: str) -> None:
    """Persist Burp settings locally and restrict the settings file on POSIX."""
    parsed = urlparse(api_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid http(s) Burp service URL without credentials.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Enter only the service root URL, such as http://127.0.0.1:1337; leave out the API key and /v0.1 path.")

    settings = load_app_settings()
    settings.update({"burp_api_url": api_url.rstrip("/"), "burp_api_key": api_key.strip()})
    _write_settings(settings)


def save_ai_settings(base_url: str, model: str, api_key: str) -> None:
    """Validate and persist the OpenAI-compatible cloud endpoint configuration."""
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter an online HTTPS AI endpoint without embedded credentials.")
    if parsed.hostname.casefold() in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Local AI endpoints are disabled. Enter your cloud provider's OpenAI-compatible base URL.")
    if parsed.query or parsed.fragment:
        raise ValueError("Remove query parameters and fragments from the AI base URL.")
    if not model.strip():
        raise ValueError("Enter the exact model name supported by your provider.")
    settings = load_app_settings()
    settings.update({
        "ai_base_url": base_url.rstrip("/"),
        "ai_model": model.strip(),
        "ai_api_key": api_key.strip(),
    })
    _write_settings(settings)


def _write_settings(settings: dict[str, str]) -> None:
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
