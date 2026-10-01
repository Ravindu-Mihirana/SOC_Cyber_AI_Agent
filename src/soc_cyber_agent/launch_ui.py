"""Launch the Streamlit app using the active cross-platform Python runtime."""

import subprocess
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parents[2]
    app_path = Path(__file__).with_name("ui.py")
    command = [sys.executable, "-m", "streamlit", "run", str(app_path), "--server.headless=true", "--server.port=8501"]
    return subprocess.call(command, cwd=project_root)


if __name__ == "__main__":
    raise SystemExit(main())
