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

    # ── ACCOUNTS (username + password, with a client-derived signing key) ──────
    #
    # The browser derives TWO values from the password with PBKDF2 (different info strings):
    #   auth_token  -> sent here to log in.  We store only a salted hash of it.
    #   signing_key -> NEVER sent. Stays in the browser and signs commands.
    # So this host can verify a login but CANNOT derive the signing key, and therefore
    # still cannot forge a command — the same guarantee the pasted device-secret gave,
    # without the operator ever handling a 64-char key. The kdf_salt is public by design
    # (the client needs it before login to derive the same values on any device).

    def account_exists(self) -> bool:
        return bool(self._load_config().get("account"))

    def account_username(self) -> str | None:
        acc = self._load_config().get("account") or {}
        return acc.get("username")

    def kdf_salt(self, username: str) -> str | None:
        """Public per-account KDF salt so any device can derive the same keys from the password."""
        acc = self._load_config().get("account") or {}
        if acc.get("username") != username:
            return None
        return acc.get("kdf_salt")

    def register(self, username: str, auth_token: str, kdf_salt: str,
                 iterations: int = 200_000) -> tuple:
        """First-run account creation. Returns (ok, reason). Refuses to clobber an existing account."""
        if not username or not auth_token or not kdf_salt:
            return False, "username, auth_token and kdf_salt are required"
        cfg = self._load_config()
        if cfg.get("account"):
            return False, "an account already exists"
        vsalt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac("sha256", auth_token.encode(), bytes.fromhex(vsalt), iterations).hex()
        cfg["account"] = {"username": username, "kdf_salt": kdf_salt,
                          "verifier_salt": vsalt, "verifier": h, "iterations": iterations}
        cfg.setdefault("api_key", secrets.token_hex(24))
        self._save_config(cfg)
        return True, "ok"

    def verify_account(self, username: str, auth_token: str) -> bool:
        acc = self._load_config().get("account") or {}
        if not acc or acc.get("username") != username:
            return False
        h = hashlib.pbkdf2_hmac("sha256", auth_token.encode(),
                                bytes.fromhex(acc["verifier_salt"]), acc["iterations"]).hex()
        return secrets.compare_digest(h, acc["verifier"])

    def reset_account(self) -> None:
        """Wipe the account so the GUI shows first-run registration again."""
        cfg = self._load_config()
        cfg.pop("account", None)
        cfg.pop("password", None)
        self._save_config(cfg)

    def api_key(self) -> str:
        cfg = self._load_config()
        if "api_key" not in cfg:
            cfg["api_key"] = secrets.token_hex(24)
            self._save_config(cfg)
        return cfg["api_key"]

    def rotate_api_key(self) -> tuple:
        """Replace the relay api_key with a fresh one. Returns (old, new).

        This is the ONLY code path that changes an existing api_key, and it exists because there
        wasn't one. `set_password` and `register` both use `cfg.setdefault("api_key", ...)`, which
        writes only when the key is ABSENT — so on a store that already had a key, running
        set-password left it untouched while appearing to succeed. The documented rotation
        procedure ("set-password then show-apikey") therefore printed back the same key it started
        with. A remedy that reports success without doing the work is worse than no remedy, because
        it retires the task.

        Rotation is deliberately NOT a side effect of set_password: the key also lives in the
        orchestrator's config.yaml, and silently changing one half of a matched pair would break
        the orchestrate loop with no obvious cause. Rotating is an explicit act, and the caller is
        responsible for updating config.yaml to match — `cli.py rotate-apikey` says so out loud.
        """
        cfg = self._load_config()
        old = cfg.get("api_key")
        new = secrets.token_hex(24)
        cfg["api_key"] = new
        self._save_config(cfg)
        return old, new

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


    # ── command outcomes (so the UI can show the REAL verdict, not just "queued") ──────
    @property
    def outcomes_path(self) -> str:
        return os.path.join(self.root, "outcomes.json")

    def set_outcome(self, cmd_id: str, ok: bool, reason: str = "") -> None:
        try:
            with open(self.outcomes_path, encoding="utf-8") as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            d = {}
        d[str(cmd_id)] = {"ok": bool(ok), "reason": reason, "ts": int(time.time())}
        # keep it small
        if len(d) > 200:
            for k in sorted(d, key=lambda k: d[k]["ts"])[:100]:
                d.pop(k, None)
        with open(self.outcomes_path, "w", encoding="utf-8") as fh:
            json.dump(d, fh)

    def get_outcome(self, cmd_id: str):
        try:
            with open(self.outcomes_path, encoding="utf-8") as fh:
                return json.load(fh).get(str(cmd_id))
        except (OSError, ValueError):
            return None

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
    def push_log(self, source: str, body: str, level: str = "info", ts: int | None = None,
                 engagement: str | None = None) -> None:
        ts = int(ts if ts is not None else time.time())
        rec = {"ts": ts, "source": source, "level": level, "body": body}
        if engagement:
            rec["engagement"] = engagement
        with open(self.logs_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")

    def fetch_logs(self, limit: int = 100, engagement: str | None = None) -> list:
        if not os.path.exists(self.logs_path):
            return []
        with open(self.logs_path, encoding="utf-8") as fh:
            rows = [json.loads(l) for l in fh if l.strip()]
        if engagement:
            rows = [r for r in rows if r.get("engagement") == engagement]
        return rows[-limit:]

    # ── engagement registry (so the UI can list what's manageable) ──────────────
    def set_engagements(self, names) -> None:
        cfg = self._load_config()
        cfg["engagements"] = list(names)
        self._save_config(cfg)

    def engagements(self) -> list:
        return self._load_config().get("engagements", [])
