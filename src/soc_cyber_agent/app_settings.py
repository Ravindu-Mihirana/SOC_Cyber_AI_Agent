"""Local dashboard settings, including persistent Burp API connection details."""

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
    settings = {
        "burp_api_url": os.environ.get("BURP_API_URL", "http://127.0.0.1:1337"),
        "burp_api_key": os.environ.get("BURP_API_KEY", ""),
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
    return settings


def save_burp_settings(api_url: str, api_key: str) -> None:
    """Persist Burp settings locally and restrict the settings file on POSIX."""
    parsed = urlparse(api_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid http(s) Burp service URL without credentials.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Enter only the service root URL, such as http://127.0.0.1:1337; leave out the API key and /v0.1 path.")

    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({
        "burp_api_url": api_url.rstrip("/"),
        "burp_api_key": api_key.strip(),
    }, indent=2), encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
