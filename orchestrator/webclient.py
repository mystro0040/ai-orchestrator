"""
webclient.py — the LOCAL orchestrator's outbound HTTPS client to the remote web app (stdlib urllib).

Outbound-only: the local box never listens; it reaches OUT to fetch pending signed commands and push
logs up. Zero third-party deps (urllib). Auth is the orchestrator api_key header (from the web app's
config). TLS verification is on by default.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error


class WebClient:
    def __init__(self, base_url: str, api_key: str, timeout: int = 15):
        self.base = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("X-Api-Key", self.api_key)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            return {"error": f"http {e.code}", "detail": e.read().decode(errors="replace")[:300]}
        except urllib.error.URLError as e:
            return {"error": "network", "detail": str(e.reason)}

    def fetch_pending(self) -> list:
        r = self._req("GET", "/api/queue/pending")
        return r.get("pending", []) if isinstance(r, dict) else []

    def ack(self, ids: list) -> dict:
        return self._req("POST", "/api/queue/ack", {"ids": ids})

    def push_log(self, source: str, body: str, level: str = "info", engagement: str | None = None) -> dict:
        return self._req("POST", "/api/logs",
                         {"source": source, "body": body, "level": level, "engagement": engagement})

    def report_outcome(self, cmd_id: str, ok: bool, reason: str = "") -> dict:
        """Tell the web app whether a queued command actually VERIFIED, so the UI can show the
        real verdict instead of just 'queued'."""
        return self._req("POST", "/api/queue/outcome",
                         {"id": cmd_id, "ok": bool(ok), "reason": reason})

    def set_engagements(self, names: list) -> dict:
        return self._req("POST", "/api/engagements", {"engagements": list(names)})
