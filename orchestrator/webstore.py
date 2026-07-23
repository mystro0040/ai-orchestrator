"""
webstore.py — the web app's data layer (pure stdlib): an async command QUEUE + LOG store + auth.

Framework-agnostic on purpose: webserver.py (stdlib http.server) is a thin HTTP wrapper over this, so
the security-critical logic is unit-testable without any web framework, and a FastAPI wrapper could sit
on top later unchanged.

Security split (see signing.py): the web host is password-gated and only RELAYS signed envelopes — it
holds NO device secret and NO PIN, so it cannot forge commands. HMAC verification is the orchestrator's
job (local). Files under <root>:
    config.json    # password (pbkdf2) + orchestrator api_key
    queue.jsonl    # pending signed command envelopes (append-only; 'delivered' flips)
    logs.jsonl     # log stream the agents/orchestrator push up for the operator's phone
    sessions.json  # active UI session tokens
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time


class WebStore:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.config_path = os.path.join(self.root, "config.json")
        self.queue_path = os.path.join(self.root, "queue.jsonl")
        self.logs_path = os.path.join(self.root, "logs.jsonl")
        self.sessions_path = os.path.join(self.root, "sessions.json")

    # ── config / auth ──────────────────────────────────────────────────────────
    def _load_config(self) -> dict:
        if not os.path.exists(self.config_path):
            return {}
        with open(self.config_path, encoding="utf-8") as fh:
            return json.load(fh)

    def _save_config(self, cfg: dict) -> None:
        with open(self.config_path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
        try:
            os.chmod(self.config_path, 0o600)
        except OSError:
            pass

    def set_password(self, password: str, iterations: int = 200_000) -> None:
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations).hex()
        cfg = self._load_config()
        cfg["password"] = {"salt": salt, "hash": h, "iterations": iterations}
        cfg.setdefault("api_key", secrets.token_hex(24))
        self._save_config(cfg)

    def verify_password(self, password: str) -> bool:
        cfg = self._load_config().get("password")
        if not cfg:
            return False
        h = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                bytes.fromhex(cfg["salt"]), cfg["iterations"]).hex()
        return secrets.compare_digest(h, cfg["hash"])

    def api_key(self) -> str:
        cfg = self._load_config()
        if "api_key" not in cfg:
            cfg["api_key"] = secrets.token_hex(24)
            self._save_config(cfg)
        return cfg["api_key"]

    def check_api_key(self, key: str) -> bool:
        return bool(key) and secrets.compare_digest(str(key), self.api_key())

    # ── sessions (UI) ──────────────────────────────────────────────────────────
    def _load_sessions(self) -> dict:
        if not os.path.exists(self.sessions_path):
            return {}
        with open(self.sessions_path, encoding="utf-8") as fh:
            return json.load(fh)

    def create_session(self, ttl_s: int = 86400, now: int | None = None) -> str:
        now = int(now if now is not None else time.time())
        tok = secrets.token_hex(24)
        s = self._load_sessions()
        s[tok] = {"created": now, "expires": now + ttl_s}
        with open(self.sessions_path, "w", encoding="utf-8") as fh:
            json.dump(s, fh, indent=2)
        return tok

    def valid_session(self, token: str, now: int | None = None) -> bool:
        now = int(now if now is not None else time.time())
        s = self._load_sessions().get(str(token))
        return bool(s) and s.get("expires", 0) > now

    # ── queue ────────────────────────────────────────────────────────────────
    def enqueue(self, envelope: dict, ts: int | None = None, cmd_id: str | None = None) -> str:
        ts = int(ts if ts is not None else time.time())
        cmd_id = cmd_id or secrets.token_hex(8)
        rec = {"id": cmd_id, "ts_added": ts, "delivered": False, "envelope": envelope}
        with open(self.queue_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        return cmd_id

    def pending(self) -> list:
        out = []
        if not os.path.exists(self.queue_path):
            return out
        with open(self.queue_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rec = json.loads(line)
                    if not rec.get("delivered"):
                        out.append(rec)
        return out

    def mark_delivered(self, ids) -> None:
        ids = set(ids)
        if not os.path.exists(self.queue_path):
            return
        rows = []
        with open(self.queue_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("id") in ids:
                    rec["delivered"] = True
                rows.append(rec)
        with open(self.queue_path, "w", encoding="utf-8") as fh:
            for rec in rows:
                fh.write(json.dumps(rec) + "\n")

    # ── logs ────────────────────────────────────────────────────────────────
    def push_log(self, source: str, body: str, level: str = "info", ts: int | None = None) -> None:
        ts = int(ts if ts is not None else time.time())
        with open(self.logs_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": ts, "source": source, "level": level, "body": body}) + "\n")

    def fetch_logs(self, limit: int = 100) -> list:
        if not os.path.exists(self.logs_path):
            return []
        with open(self.logs_path, encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip()]
        return [json.loads(l) for l in lines[-limit:]]
