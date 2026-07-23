"""
core.py — the local Orchestrator: the trusted middleman.

Flow: fetch signed command envelopes from the web app (outbound HTTPS) → VERIFY them locally (HMAC+PIN,
freshness, replay) → dispatch by command type (route to an agent's inbox / set the mode / privileged
system action) → push acks + logs back up. It is the SOLE authority that holds the device secret + PIN,
so a compromised web host cannot forge a runnable command.

Command payload types (inside a verified envelope's `payload`):
    {"type": "agent.command", "agent": "tester", "command": "<text>"}
    {"type": "broadcast", "body": "<text>"}
    {"type": "set_mode", "mode": 1|2|3}
    {"type": "system.shutdown", "delay_min": 0}     # privileged; see the guards below
"""
from __future__ import annotations

import json
import os
import subprocess

from . import signing
from .blackboard import Blackboard, Message, Mode


class Orchestrator:
    def __init__(self, secret_hex: str, pin: str, blackboard: Blackboard, adapters: dict,
                 web_client=None, *, allow_privileged: bool = False, dry_run: bool = True,
                 seen_nonces_path: str | None = None, shutdown_cmd=None):
        self.secret = secret_hex
        self.pin = str(pin)
        self.bb = blackboard
        self.adapters = adapters                      # {agent_name: AgentAdapter}
        self.web = web_client
        self.allow_privileged = allow_privileged      # master switch for system.* commands
        self.dry_run = dry_run                        # when True, privileged actions are logged, not run
        self.shutdown_cmd = shutdown_cmd or ["sudo", "shutdown", "-h"]
        self.seen_nonces_path = seen_nonces_path
        self.seen_nonces = self._load_nonces()

    # ── nonce persistence (replay protection across restarts) ──────────────────
    def _load_nonces(self) -> set:
        if self.seen_nonces_path and os.path.exists(self.seen_nonces_path):
            with open(self.seen_nonces_path, encoding="utf-8") as fh:
                return set(l.strip() for l in fh if l.strip())
        return set()

    def _persist_nonce(self, nonce: str) -> None:
        if self.seen_nonces_path:
            with open(self.seen_nonces_path, "a", encoding="utf-8") as fh:
                fh.write(nonce + "\n")

    # ── the trust boundary ─────────────────────────────────────────────────────
    def dispatch(self, envelope: dict, ts: str, msg_id: str, now: int | None = None) -> dict:
        ok, reason = signing.verify(self.secret, self.pin, envelope,
                                    seen_nonces=self.seen_nonces, now=now)
        if not ok:
            self._log("orchestrator", f"REJECTED command: {reason}", level="warn")
            return {"ok": False, "reason": reason}
        self._persist_nonce(envelope.get("nonce", ""))

        payload = envelope["payload"]
        ptype = payload.get("type")

        if ptype == "agent.command":
            agent = payload.get("agent")
            command = payload.get("command", "")
            if agent not in self.adapters:
                return {"ok": False, "reason": f"unknown agent: {agent}"}
            self.adapters[agent].deliver(command, ts=ts, msg_id=msg_id)
            self._log("orchestrator", f"delivered command to {agent}: {command[:80]}")
            return {"ok": True, "action": "delivered", "agent": agent}

        if ptype == "broadcast":
            self.bb.post(Message(id=msg_id, ts=ts, sender="operator", recipient="all",
                                 kind="note", body=payload.get("body", "")))
            return {"ok": True, "action": "broadcast"}

        if ptype == "set_mode":
            self.bb.set_mode(int(payload.get("mode", int(Mode.MINIMAL))))
            self._log("orchestrator", f"mode set to {int(self.bb.get_mode())}")
            return {"ok": True, "action": "set_mode", "mode": int(self.bb.get_mode())}

        if ptype == "system.shutdown":
            return self._handle_shutdown(payload)

        return {"ok": False, "reason": f"unknown command type: {ptype}"}

    # ── privileged: remote shutdown (guarded; NEVER runs in tests / dry-run) ────
    def _handle_shutdown(self, payload: dict) -> dict:
        delay = int(payload.get("delay_min", 0))
        cmd = list(self.shutdown_cmd) + ([f"+{delay}"] if delay else ["now"])
        if not self.allow_privileged:
            self._log("orchestrator", "shutdown requested but privileged actions are DISABLED", "warn")
            return {"ok": False, "reason": "privileged actions disabled (allow_privileged=False)"}
        if self.dry_run:
            self._log("orchestrator", f"[DRY-RUN] would execute: {' '.join(cmd)}", "warn")
            return {"ok": True, "action": "shutdown", "dry_run": True, "cmd": cmd}
        self._log("orchestrator", f"EXECUTING remote shutdown: {' '.join(cmd)}", "critical")
        try:
            subprocess.Popen(cmd)  # fire-and-forget; the box is going down
            return {"ok": True, "action": "shutdown", "dry_run": False, "cmd": cmd}
        except Exception as e:
            return {"ok": False, "reason": f"shutdown failed: {e.__class__.__name__}: {e}"}

    # ── polling / sync ─────────────────────────────────────────────────────────
    def poll_once(self, now_ts: str, now_unix: int | None = None) -> dict:
        """Fetch pending commands from the web app, verify+dispatch each, ack, and (in FULL) sync logs up."""
        if not self.web:
            return {"ok": False, "reason": "no web client configured (local-only mode)"}
        pending = self.web.fetch_pending()
        delivered, results = [], []
        for rec in pending:
            res = self.dispatch(rec["envelope"], ts=now_ts, msg_id=rec.get("id", ""), now=now_unix)
            results.append(res)
            delivered.append(rec.get("id"))
        if delivered:
            self.web.ack(delivered)
        if self.bb.get_mode() == Mode.FULL:
            self.sync_logs_up()
        return {"processed": len(pending), "results": results}

    def sync_logs_up(self) -> None:
        """FULL mode: push each agent's fresh outbox status up to the web app for the operator's phone."""
        if not self.web:
            return
        for name, adapter in self.adapters.items():
            for m in adapter.collect():
                self.web.push_log(name, m.body, level=("critical" if m.kind == "critical" else "info"))

    def _log(self, source: str, body: str, level: str = "info") -> None:
        if self.web:
            try:
                self.web.push_log(source, body, level=level)
            except Exception:
                pass
