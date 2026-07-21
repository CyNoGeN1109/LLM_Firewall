#!/usr/bin/env python3
import json
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from firewall import config, engine

STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/styles.css": "styles.css",
}

_THINK_OPEN = "<think>"
_THINK_CLOSE = "</think>"


def ollama_models():
    try:
        request = urllib.request.Request(f"{config.OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(request, timeout=4) as resp:
            data = json.loads(resp.read())
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


class ChatHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(config.ROOT), **kwargs)

    def do_GET(self):
        if self.path == "/api/health":
            models = ollama_models()
            return self._json({
                "ok": bool(models),
                "status": "ok" if models else "offline",
                "model": config.MODEL_NAME,
                "firewall_model": config.FIREWALL_MODEL,
                "firewall_available": config.FIREWALL_MODEL in set(models),
                "fail_mode": config.FAIL_MODE,
            })

        if self.path == "/api/config":
            models = ollama_models() or [config.MODEL_NAME]
            return self._json({
                "default_model": config.MODEL_NAME,
                "firewall_model": config.FIREWALL_MODEL,
                "models": models,
                "ollama_url": config.OLLAMA_URL,
                "fail_mode": config.FAIL_MODE,
            })

        target = STATIC_FILES.get(self.path.split("?", 1)[0])
        if target is None:
            return self.send_error(404)
        self.path = "/" + target
        return super().do_GET()

    def do_POST(self):
        if self.path != "/api/chat":
            return self.send_error(404)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
            messages = body.get("messages", [])
            system_prompt = (body.get("system_prompt") or "").strip()
            firewall_enabled = bool(body.get("firewall", True))

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            if firewall_enabled:
                decision = engine.inspect(messages, system_prompt)
                self._event("firewall", {
                    "allowed": decision.allowed,
                    "risk": decision.risk,
                    "attack_type": decision.attack_type,
                    "reason": decision.reason,
                    "layer": decision.layer,
                    "rule_id": decision.rule_id,
                    "confidence": decision.confidence,
                    "signals": decision.signals,
                })
                if not decision.allowed:
                    self._event("blocked", {
                        "message": f"[CynoShield] blocked at {decision.layer}: {decision.reason}"
                    })
                    self._event("done", {"blocked": True})
                    return

            self._stream_ollama(messages, system_prompt, body.get("temperature", 0.7))
        except Exception as exc:
            self._event("error", {"message": str(exc)})

    def _stream_ollama(self, messages, system_prompt, temperature):
        chat_messages = (
            [{"role": "system", "content": system_prompt}] + messages
            if system_prompt else messages
        )
        payload = {
            "model": config.MODEL_NAME,
            "messages": chat_messages,
            "stream": True,
            "options": {
                "temperature": float(temperature),
                "num_ctx": 4096,
                "repeat_penalty": 1.2,
                "top_p": 0.9,
            },
        }
        request = urllib.request.Request(
            f"{config.OLLAMA_URL}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        strip = _ThinkStripper()
        try:
            with urllib.request.urlopen(request) as resp:
                for line in resp:
                    if not line.strip():
                        continue
                    chunk = json.loads(line)
                    token = chunk.get("message", {}).get("content", "")
                    if token:
                        visible = strip.feed(token)
                        if visible:
                            self._event("token", {"text": visible})
                    if chunk.get("done"):
                        self._event("done", {"model": config.MODEL_NAME})
                        return
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:
            self._event("error", {"message": str(exc)})

    def _event(self, name, data):
        try:
            self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, data):
        encoded = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):
        if args and str(args[1]) != "200":
            super().log_message(fmt, *args)


class _ThinkStripper:
    def __init__(self):
        self.inside = False
        self.buffer = ""

    def feed(self, token):
        text = self.buffer + token
        self.buffer = ""
        out = []
        i = 0
        while i < len(text):
            if self.inside:
                end = text.find(_THINK_CLOSE, i)
                if end == -1:
                    keep = max(0, len(text) - len(_THINK_CLOSE) + 1)
                    self.buffer = text[keep:]
                    i = len(text)
                else:
                    self.inside = False
                    i = end + len(_THINK_CLOSE)
            else:
                start = text.find(_THINK_OPEN, i)
                if start == -1:
                    partial = -1
                    for offset in range(1, len(_THINK_OPEN)):
                        if text.endswith(_THINK_OPEN[:offset]):
                            partial = len(text) - offset
                            break
                    if partial != -1:
                        out.append(text[i:partial])
                        self.buffer = text[partial:]
                    else:
                        out.append(text[i:])
                    i = len(text)
                else:
                    out.append(text[i:start])
                    self.inside = True
                    i = start + len(_THINK_OPEN)
        return "".join(out)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", config.PORT), ChatHandler)
    print(f"CynoShield running on http://127.0.0.1:{config.PORT}  (fail mode: {config.FAIL_MODE})")
    server.serve_forever()


if __name__ == "__main__":
    main()
