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
            # Never let a browser cache API state (account existence, logs, session validity) —
            # a stale /api/account made the UI show "Sign in" for an account that was deleted.
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, html: str):
            body = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            # The page embeds the JS, so a cached copy means stale code after every fix.
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
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
            if path == "/api/account":                       # first-run check (public)
                return self._json(200, {"exists": store.account_exists(),
                                        "username": store.account_username()})
            if path == "/api/salt":                          # public KDF salt so any device can
                u = q.get("u", [""])[0]                      # derive the same keys from the password
                s = store.kdf_salt(u)
                return self._json(200, {"kdf_salt": s} if s else {"error": "unknown user"})
            if path == "/api/mode":                          # which mode is a board actually in?
                if not self._session_ok():
                    return self._json(401, {"error": "unauthorized"})
                eng = q.get("engagement", [""])[0]
                try:
                    import os as _os
                    from .hub import slugify
                    root = _os.path.expanduser(
                        "~/Workspace/buckets/bug-bounty-workspace-bucket/.orchestrator/engagements")
                    sy = _os.path.join(root, slugify(eng), "state.yaml")
                    mode = 1
                    if _os.path.exists(sy):
                        for line in open(sy, encoding="utf-8"):
                            if line.startswith("mode:"):
                                mode = int(line.split(":", 1)[1].strip())
                    return self._json(200, {"mode": mode, "engagement": eng})
                except Exception as e:
                    return self._json(200, {"mode": None, "error": e.__class__.__name__})
            if path == "/api/queue/status":
                if not self._session_ok():
                    return self._json(401, {"error": "unauthorized"})
                return self._json(200, {"outcome": store.get_outcome(q.get("id", [""])[0])})
            if path == "/api/chat":                          # REAL per-agent transcript from the
                if not self._session_ok():                   # board's history (not just synced logs)
                    return self._json(401, {"error": "unauthorized"})
                eng = q.get("channel", [""])[0]
                limit = int(q.get("limit", ["120"])[0] or 120)
                try:
                    import os as _os, json as _json
                    from .hub import slugify
                    root = _os.path.expanduser(
                        "~/Workspace/buckets/bug-bounty-workspace-bucket/.orchestrator/engagements")
                    hp = _os.path.join(root, slugify(eng), "history.jsonl")
                    msgs = []
                    if _os.path.exists(hp):
                        with open(hp, encoding="utf-8") as fh:
                            for line in fh:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    d = _json.loads(line)
                                except ValueError:
                                    continue
                                msgs.append({"ts": d.get("ts"), "sender": d.get("sender"),
                                             "recipient": d.get("recipient"), "kind": d.get("kind"),
                                             "body": d.get("body", "")})
                    return self._json(200, {"messages": msgs[-limit:], "channel": eng})
                except Exception as e:
                    return self._json(200, {"messages": [], "error": e.__class__.__name__})
            if path == "/api/security":                       # unverified / rejected activity
                if not self._session_ok():
                    return self._json(401, {"error": "unauthorized"})
                try:
                    import os as _os, json as _json, time as _time
                    rej, last = [], None
                    if _os.path.exists(store.logs_path):
                        with open(store.logs_path, encoding="utf-8") as fh:
                            for line in fh:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    d = _json.loads(line)
                                except ValueError:
                                    continue
                                if "REJECTED" in (d.get("body") or ""):
                                    rej.append({"ts": d.get("ts"), "body": d.get("body")})
                    now = int(_time.time())
                    recent = [r for r in rej if now - (r.get("ts") or 0) < 3600]
                    return self._json(200, {"total": len(rej), "last_hour": len(recent),
                                            "recent": rej[-15:]})
                except Exception as e:
                    return self._json(200, {"total": 0, "last_hour": 0, "recent": [],
                                            "error": e.__class__.__name__})
            if path == "/api/session":                       # does my stored token still work?
                return self._json(200, {"valid": self._session_ok()})
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
            if self.path == "/api/register":                 # first-run account creation
                ok, why = store.register(body.get("username", "").strip(),
                                         body.get("auth_token", ""),
                                         body.get("kdf_salt", ""))
                if not ok:
                    return self._json(400, {"ok": False, "error": why})
                return self._json(200, {"ok": True, "token": store.create_session()})
            if self.path == "/api/login":
                # account login (username + client-derived auth token)
                if body.get("username") and body.get("auth_token"):
                    if store.verify_account(body["username"], body["auth_token"]):
                        return self._json(200, {"token": store.create_session()})
                    return self._json(401, {"error": "bad credentials"})
                if store.verify_password(body.get("password", "")):   # legacy single-password
                    return self._json(200, {"token": store.create_session()})
                return self._json(401, {"error": "bad password"})
            if self.path == "/api/queue":
                if not self._session_ok():
                    return self._json(401, {"error": "unauthorized"})
                env = body.get("envelope")
                if not isinstance(env, dict):
                    return self._json(400, {"error": "missing envelope"})
                return self._json(200, {"id": store.enqueue(env)})
            if self.path == "/api/queue/outcome":
                if not self._apikey_ok():
                    return self._json(401, {"error": "bad api key"})
                store.set_outcome(body.get("id", ""), body.get("ok", False), body.get("reason", ""))
                return self._json(200, {"ok": True})
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
