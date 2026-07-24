#!/usr/bin/env python3
"""
test_web_signing.py — end-to-end test of the operator web app's auth + command-signing chain.

This is the operator-facing security boundary rebuilt on 2026-07-23: log in with username + password
(no key to paste), sign a command in the browser with a password-derived key + PIN, and have the
orchestrator verify it locally. Proves a wrong password, wrong PIN, replayed nonce, and tampered
payload are all rejected, and that the web host (which never holds the signing key or PIN) cannot
forge a command. Runs a loopback server on an ephemeral port; no external network. Pure stdlib.

Run:  python3 test_web_signing.py   (exit 0 = all pass).
Covers: orchestrator/webstore.py, orchestrator/webserver.py, orchestrator/signing.py
"""
import hashlib
import hmac
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from orchestrator.webstore import WebStore  # noqa: E402
from orchestrator.webserver import make_handler  # noqa: E402
from orchestrator import signing  # noqa: E402

_PASS = _FAIL = 0


def chk(name, cond, extra=""):
    global _PASS, _FAIL
    ok = bool(cond)
    _PASS += ok
    _FAIL += not ok
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  -> " + str(extra)) if (extra and not ok) else ""))


def derive(pw, salt, info):
    return hashlib.pbkdf2_hmac("sha256", f"{pw}|{info}".encode(), bytes.fromhex(salt), 200_000, 32).hex()


def canon(o):
    if isinstance(o, list):
        return "[" + ",".join(canon(x) for x in o) + "]"
    if isinstance(o, dict):
        return "{" + ",".join(json.dumps(k) + ":" + canon(v) for k, v in sorted(o.items())) + "}"
    return json.dumps(o)


def main():
    root = tempfile.mkdtemp(prefix="ao-websign-")
    store = WebStore(root)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    B = f"http://127.0.0.1:{port}"

    def req(path, body=None, hdrs=None, method=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(B + path, data=data, method=method or ("POST" if data else "GET"))
        r.add_header("Content-Type", "application/json")
        for k, v in (hdrs or {}).items():
            r.add_header(k, v)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    try:
        pw, salt = "correct-horse-staple", os.urandom(16).hex()
        auth, key = derive(pw, salt, "ao-auth"), derive(pw, salt, "ao-sign")

        s, j = req("/api/account")
        chk("first run: no account", j.get("exists") is False)
        s, j = req("/api/register", {"username": "op", "auth_token": auth, "kdf_salt": salt})
        chk("register returns a session token", bool(j.get("token")))
        tok = j.get("token", "")
        s, j = req("/api/register", {"username": "op2", "auth_token": auth, "kdf_salt": salt})
        chk("register refuses to clobber an existing account", s == 400)
        s, j = req("/api/salt?u=op")
        chk("public KDF salt matches", j.get("kdf_salt") == salt)

        bad = derive("wrong-password", salt, "ao-auth")
        s, j = req("/api/login", {"username": "op", "auth_token": bad})
        chk("wrong password rejected", s == 401)
        s, j = req("/api/login", {"username": "op", "auth_token": auth})
        chk("relogin from another device works", bool(j.get("token")))

        PIN = "4821"
        payload = {"type": "agent.command", "engagement": "__manager__", "agent": "manager", "command": "hello"}
        nonce = os.urandom(16).hex()
        ts = int(time.time())
        sig = hmac.new(bytes.fromhex(key), f"{PIN}\n{nonce}\n{ts}\n{canon(payload)}".encode(),
                       hashlib.sha256).hexdigest()
        env = {"payload": payload, "nonce": nonce, "ts": ts, "sig": sig}

        s, j = req("/api/queue", {"envelope": env})
        chk("queue rejects without a session", s == 401)
        s, j = req("/api/queue", {"envelope": env}, {"X-Session": tok})
        chk("queue accepts a signed envelope", bool(j.get("id")))

        ok, _ = signing.verify(key, PIN, env, seen_nonces=set())
        chk("orchestrator verifies the real envelope", ok)
        ok2, _ = signing.verify(key, "0000", env, seen_nonces=set())
        chk("wrong PIN rejected", not ok2)
        ok3, _ = signing.verify(derive("other", salt, "ao-sign"), PIN, env, seen_nonces=set())
        chk("wrong signing key rejected (compromised web host cannot forge)", not ok3)
        ok4, _ = signing.verify(key, PIN, env, seen_nonces={nonce})
        chk("replayed nonce rejected", not ok4)
        tampered = json.loads(json.dumps(env))
        tampered["payload"]["command"] = "rm -rf /"
        ok5, _ = signing.verify(key, PIN, tampered, seen_nonces=set())
        chk("tampered payload rejected", not ok5)

        # served page carries the tabbed chat UI and no unreplaced template placeholders
        html = urllib.request.urlopen(B + "/").read().decode()
        chk("page serves the tabbed chat UI", 'id="tabs"' in html and 'id="chat"' in html)
        chk("no unreplaced placeholders in the page", "__GLOBAL__" not in html and "__GLABEL__" not in html)
    finally:
        srv.shutdown()
        shutil.rmtree(root, ignore_errors=True)

    print(f"\n{_PASS}/{_PASS + _FAIL} passed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
