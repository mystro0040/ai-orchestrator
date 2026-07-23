"""
webserver.py — the remote web app, on Python's stdlib http.server (ZERO third-party deps).

Runs locally for testing and on any Python-capable host (VPS/PaaS) unchanged. It is a dumb, secure
RELAY: password-gates the UI, stores signed command envelopes for the orchestrator to pull, and holds
a log stream for the operator's phone. It never holds the device secret or PIN (see signing.py), so it
cannot forge commands. Put it behind TLS (nginx / the PaaS edge) in production.

Endpoints:
    GET  /                     mobile UI
    POST /api/login            {password} -> {token}          (UI auth)
    POST /api/queue            {envelope}  (X-Session)         -> {id}   enqueue signed command
    GET  /api/queue/pending    (X-Api-Key: orchestrator)       -> {pending:[...]}
    POST /api/queue/ack        {ids} (X-Api-Key)               mark delivered
    POST /api/logs             {source,body,level} (X-Api-Key|X-Session)
    GET  /api/logs             (X-Session)                     -> {logs:[...]}
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .webstore import WebStore
from .ui import page


def make_handler(store: WebStore):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ai-orchestrator/1.0"

        # ── helpers ──────────────────────────────────────────────────────────
        def _json(self, code: int, obj: dict):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, html: str):
            body = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            n = int(self.headers.get("Content-Length", 0) or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n).decode() or "{}")
            except ValueError:
                return {}

        def _session_ok(self) -> bool:
            return store.valid_session(self.headers.get("X-Session", ""))

        def _apikey_ok(self) -> bool:
            return store.check_api_key(self.headers.get("X-Api-Key", ""))

        def log_message(self, *a):  # silence default stderr spam
            pass

        # ── routing ────────────────────────────────────────────────────────────
        def do_GET(self):
            from urllib.parse import urlparse, parse_qs
            u = urlparse(self.path); path = u.path; q = parse_qs(u.query)
            if path == "/" or path.startswith("/index"):
                return self._html(page())
            if path == "/api/queue/pending":
                if not self._apikey_ok():
                    return self._json(401, {"error": "bad api key"})
                return self._json(200, {"pending": store.pending()})
            if path == "/api/engagements":
                if not (self._session_ok() or self._apikey_ok()):
                    return self._json(401, {"error": "unauthorized"})
                return self._json(200, {"engagements": store.engagements()})
            if path == "/api/logs":
                if not self._session_ok():
                    return self._json(401, {"error": "unauthorized"})
                return self._json(200, {"logs": store.fetch_logs(engagement=q.get("engagement", [None])[0])})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            body = self._read_json()
            if self.path == "/api/login":
                if store.verify_password(body.get("password", "")):
                    return self._json(200, {"token": store.create_session()})
                return self._json(401, {"error": "bad password"})
            if self.path == "/api/queue":
                if not self._session_ok():
                    return self._json(401, {"error": "unauthorized"})
                env = body.get("envelope")
                if not isinstance(env, dict):
                    return self._json(400, {"error": "missing envelope"})
                return self._json(200, {"id": store.enqueue(env)})
            if self.path == "/api/queue/ack":
                if not self._apikey_ok():
                    return self._json(401, {"error": "bad api key"})
                store.mark_delivered(body.get("ids", []))
                return self._json(200, {"ok": True})
            if self.path == "/api/logs":
                if not (self._apikey_ok() or self._session_ok()):
                    return self._json(401, {"error": "unauthorized"})
                store.push_log(body.get("source", "?"), body.get("body", ""), body.get("level", "info"),
                               engagement=body.get("engagement"))
                return self._json(200, {"ok": True})
            if self.path == "/api/engagements":
                if not self._apikey_ok():
                    return self._json(401, {"error": "bad api key"})
                store.set_engagements(body.get("engagements", []))
                return self._json(200, {"ok": True})
            return self._json(404, {"error": "not found"})

    return Handler


def run(store: WebStore, host: str = "127.0.0.1", port: int = 8787):
    httpd = ThreadingHTTPServer((host, port), make_handler(store))
    print(f"[ai-orchestrator] web app on http://{host}:{port}  (Ctrl+C to stop)")
    httpd.serve_forever()
