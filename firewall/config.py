import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_env_file(path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file(ROOT / ".env")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "qwen3:1.7b")
FIREWALL_MODEL = os.environ.get("FIREWALL_MODEL", "qwen3:1.7b")
PORT = int(os.environ.get("PORT", "8788"))
FAIL_MODE = os.environ.get("FIREWALL_FAIL_MODE", "closed").strip().lower()
CLASSIFIER_TIMEOUT = float(os.environ.get("FIREWALL_CLASSIFIER_TIMEOUT", "10"))
CONTEXT_TURNS = int(os.environ.get("FIREWALL_CONTEXT_TURNS", "4"))
