"""
signing.py — cryptographic command signing (pure stdlib: hmac / hashlib / secrets).

Threat model & why this shape:
  A 4-digit PIN alone is NOT a signing key (10_000 guesses). So each command is signed with
  HMAC-SHA256 over (PIN + payload + nonce + timestamp) keyed by a HIGH-ENTROPY device secret that
  lives ONLY on the two trusted endpoints — the operator's browser (provisioned once into the phone)
  and the LOCAL orchestrator. The remote web app NEVER holds the secret or the PIN; it only relays
  the signed envelope. Therefore a fully-compromised web host still cannot FORGE a command the
  orchestrator will run — it lacks both the secret and the PIN. The PIN is the per-command human
  authorization gesture; the entropy is in the device secret.

Defense-in-depth on the low-entropy PIN:
  * password gate on the web UI (separate secret, server-side),
  * short signature validity window (max_age_s) + nonce replay rejection,
  * the orchestrator locks out after repeated bad signatures (caller-enforced).

Envelope = {"payload": {...}, "nonce": "...", "ts": <unix>, "sig": "<hex>"}.
"""
from __future__ import annotations

import hmac
import hashlib
import json
import os
import secrets
import time


def provision_secret(path: str) -> str:
    """Generate a 256-bit device secret and store it (chmod 600). Returns the hex secret.
    Provision ONCE per device pair (orchestrator + trusted browser); never send it to the web host."""
    sec = secrets.token_hex(32)
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(sec)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return sec


def load_secret(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


def new_nonce() -> str:
    return secrets.token_hex(16)


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _mac(secret_hex: str, pin: str, payload: dict, nonce: str, ts: int) -> str:
    key = bytes.fromhex(secret_hex)
    msg = f"{pin}\n{nonce}\n{ts}\n{_canonical(payload)}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def sign(secret_hex: str, pin: str, payload: dict, ts: int | None = None) -> dict:
    """Produce a signed envelope for `payload`. (In production the BROWSER does this in JS via Web
    Crypto; this is the reference/Python implementation the orchestrator and tests use.)"""
    nonce = new_nonce()
    ts = int(ts if ts is not None else time.time())
    return {"payload": payload, "nonce": nonce, "ts": ts, "sig": _mac(secret_hex, pin, payload, nonce, ts)}


def verify(secret_hex: str, pin: str, envelope: dict, *, max_age_s: int = 120,
           seen_nonces: set | None = None, now: int | None = None) -> tuple:
    """Authoritative verification (runs in the LOCAL orchestrator). Returns (ok: bool, reason: str).

    Checks: structural validity, timestamp freshness (± max_age_s), nonce not replayed, and a
    constant-time HMAC comparison over (pin, payload, nonce, ts). On success, records the nonce."""
    if not isinstance(envelope, dict):
        return False, "envelope not an object"
    for k in ("payload", "nonce", "ts", "sig"):
        if k not in envelope:
            return False, f"missing field: {k}"
    payload, nonce, ts, sig = envelope["payload"], envelope["nonce"], envelope["ts"], envelope["sig"]
    if not isinstance(payload, dict):
        return False, "payload not an object"
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return False, "bad timestamp"

    now = int(now if now is not None else time.time())
    if abs(now - ts) > max_age_s:
        return False, "stale or future-dated (outside validity window)"
    if seen_nonces is not None and nonce in seen_nonces:
        return False, "nonce replay"

    expected = _mac(secret_hex, str(pin), payload, str(nonce), ts)
    if not hmac.compare_digest(expected, str(sig)):
        return False, "bad signature (wrong PIN, secret, or tampered payload)"

    if seen_nonces is not None:
        seen_nonces.add(nonce)
    return True, "ok"
