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
from .adapters import BlackboardAgentAdapter
from .blackboard import Blackboard, Message, Mode


class Orchestrator:
    def __init__(self, secret_hex: str, pin: str, blackboard: Blackboard = None, adapters: dict = None,
                 web_client=None, *, hub=None, agent_names=None, known_engagements=None,
                 allow_privileged: bool = False, dry_run: bool = True,
                 seen_nonces_path: str | None = None, shutdown_cmd=None):
        self.secret = secret_hex
        self.pin = str(pin)
        self.bb = blackboard                          # single-engagement (legacy) mode
        self.adapters = adapters or {}                # {agent_name: AgentAdapter}  (single mode)
        self.hub = hub                                # EngagementHub -> MULTI-engagement mode
        self.agent_names = agent_names or ["manager", "tester"]
        self.known_engagements = set(known_engagements) if known_engagements else None
        self.web = web_client
        self.allow_privileged = allow_privileged      # master switch for system.* commands
        self.dry_run = dry_run                        # when True, privileged actions are logged, not run
        self.shutdown_cmd = shutdown_cmd or ["sudo", "shutdown", "-h"]
        self.seen_nonces_path = seen_nonces_path
        self.seen_nonces = self._load_nonces()
        self._adapter_cache = {}                       # {(engagement, agent): BlackboardAgentAdapter}

    # ── nonce persistence (replay protection across restarts) ──────────────────
    def _nonce_path(self) -> str | None:
        """Resolve the configured path: expand `~` and create the parent dir on demand.
        Without expansion a config value like `~/.config/.../nonces.txt` is taken LITERALLY and
        every verified command crashes with FileNotFoundError (the `~` dir does not exist)."""
        if not self.seen_nonces_path:
            return None
        p = os.path.expanduser(self.seen_nonces_path)
        d = os.path.dirname(p)
        if d:
            os.makedirs(d, exist_ok=True)
        return p

    def _load_nonces(self) -> set:
        p = self._nonce_path()
        if p and os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                return set(l.strip() for l in fh if l.strip())
        return set()

    def _persist_nonce(self, nonce: str) -> None:
        p = self._nonce_path()
        if p:
            with open(p, "a", encoding="utf-8") as fh:
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
            bb, eng, err = self._board_for(payload)
            if err:
                return {"ok": False, "reason": err}
            if self.hub is not None:
                if agent not in self.agent_names:
                    return {"ok": False, "reason": f"unknown agent: {agent}"}
                self._adapter(eng, agent).deliver(command, ts=ts, msg_id=msg_id)
            else:
                if agent not in self.adapters:
                    return {"ok": False, "reason": f"unknown agent: {agent}"}
                self.adapters[agent].deliver(command, ts=ts, msg_id=msg_id)
            self._log("orchestrator", f"[{eng or 'default'}] delivered to {agent}: {command[:80]}",
                      engagement=eng)
            return {"ok": True, "action": "delivered", "engagement": eng, "agent": agent}

        if ptype == "broadcast":
            bb, eng, err = self._board_for(payload)
            if err:
                return {"ok": False, "reason": err}
            bb.post(Message(id=msg_id, ts=ts, sender="operator", recipient="all",
                            kind="note", body=payload.get("body", "")))
            return {"ok": True, "action": "broadcast", "engagement": eng}

        if ptype == "set_mode":
            bb, eng, err = self._board_for(payload)
            if err:
                return {"ok": False, "reason": err}
            bb.set_mode(int(payload.get("mode", int(Mode.MINIMAL))))
            self._log("orchestrator", f"[{eng or 'default'}] mode set to {int(bb.get_mode())}",
                      engagement=eng)
            return {"ok": True, "action": "set_mode", "engagement": eng, "mode": int(bb.get_mode())}

        if ptype == "system.shutdown":
            return self._handle_shutdown(payload)

        return {"ok": False, "reason": f"unknown command type: {ptype}"}

    # ── engagement routing (multi-engagement mode) ──────────────────────────────
    def _board_for(self, payload):
        """Resolve which blackboard a command targets. Returns (blackboard, engagement_label, error)."""
        if self.hub is None:
            return self.bb, None, None                       # single-engagement (legacy) mode
        eng = payload.get("engagement")
        if not eng:
            return None, None, "no engagement specified (multi-engagement mode)"
        if self.known_engagements is not None and eng not in self.known_engagements:
            return None, eng, f"unknown/unregistered engagement: {eng}"
        return self.hub.blackboard(eng, agents=self.agent_names), eng, None

    def _adapter(self, engagement, agent):
        """Cached per-(engagement, agent) adapter so outbox read cursors persist."""
        key = (engagement, agent)
        if key not in self._adapter_cache:
            bb = self.hub.blackboard(engagement, agents=self.agent_names) if self.hub else self.bb
            self._adapter_cache[key] = BlackboardAgentAdapter(agent, bb)
        return self._adapter_cache[key]

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
            # Report the REAL verdict so the operator's UI can show verified vs rejected
            # (it previously only knew the command had been queued).
            try:
                self.web.report_outcome(rec.get("id", ""), bool(res.get("ok")),
                                        str(res.get("reason", "")))
            except Exception:
                pass
        if delivered:
            self.web.ack(delivered)
        self.sync_logs_up()
        return {"processed": len(pending), "results": results}

    def sync_logs_up(self) -> None:
        """Push each agent's fresh outbox status up to the web app — FULL-mode engagements only."""
        if not self.web:
            return
        if self.hub is not None:                                  # multi-engagement
            for eng in (self.known_engagements or set(self.hub.list())):
                bb = self.hub.blackboard(eng, agents=self.agent_names)
                if bb.get_mode() != Mode.FULL:
                    continue
                for agent in self.agent_names:
                    for m in self._adapter(eng, agent).collect():
                        self.web.push_log(agent, m.body, engagement=eng,
                                          level=("critical" if m.kind == "critical" else "info"))
        else:                                                     # single-engagement (legacy)
            if self.bb is None or self.bb.get_mode() != Mode.FULL:
                return
            for name, adapter in self.adapters.items():
                for m in adapter.collect():
                    self.web.push_log(name, m.body,
                                      level=("critical" if m.kind == "critical" else "info"))

    def _log(self, source: str, body: str, level: str = "info", engagement=None) -> None:
        if self.web:
            try:
                self.web.push_log(source, body, level=level, engagement=engagement)
            except Exception:
                pass
