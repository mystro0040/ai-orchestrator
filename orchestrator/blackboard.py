"""
blackboard.py — the file-based shared-memory buffer that local AI agents cross-talk through.

Design goals (from the architecture):
  * Agents NEVER talk via IPC — they read/write these files. The orchestrator only touches files too.
  * Token-cheap: a rolling "recent buffer" (recent.md) holds only the last N messages so agents read a
    small, pertinent window each cycle. A full append-only history (history.jsonl) is there for lookback.
  * Human-readable: recent.md is Markdown; state.yaml is YAML; history/inbox are JSONL.
  * Three modes gate how much cross-talk happens (see Mode) — the buffer enforces the routing policy.

Layout (rooted at a blackboard dir, e.g. an engagement's bucket folder):
    <root>/
      state.yaml            # mode, roles, per-agent read cursors
      recent.md             # rolling human/agent-readable window (last N messages)
      history.jsonl         # full append-only log (every message)
      inbox/<agent>.jsonl   # per-agent delivery queue (what THIS agent still needs to read)
      outbox/<agent>.jsonl  # what THIS agent has emitted (status/results)
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from enum import IntEnum

try:
    import yaml  # human-readable state; optional (falls back to json)
except Exception:  # pragma: no cover
    yaml = None


class Mode(IntEnum):
    MINIMAL = 1   # agents work independently; only CRITICAL messages hit the shared file; no cross-talk
    LOCAL = 2     # full Manager<->Tester cross-talk locally; web not involved
    FULL = 3      # + everything syncs up to the web app for the operator


RECENT_LIMIT_DEFAULT = 40
_KINDS = ("status", "log", "command", "result", "critical", "note")
_AUDIENCE_ALL = "all"


@dataclass
class Message:
    id: str                      # monotonic-ish id (caller-supplied; timestamps injected by caller/store)
    ts: str                      # ISO-8601 UTC (caller-supplied — Date is unavailable in some sandboxes)
    sender: str                  # agent/operator name
    recipient: str = _AUDIENCE_ALL   # agent name or "all"
    kind: str = "log"            # one of _KINDS
    mode: int = int(Mode.MINIMAL)
    ref: str | None = None       # optional correlation id (e.g. the command this result answers)
    body: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Message":
        return Message(**{k: d.get(k) for k in Message.__annotations__})


class Blackboard:
    def __init__(self, root: str, recent_limit: int = RECENT_LIMIT_DEFAULT):
        self.root = os.path.abspath(root)
        self.recent_limit = recent_limit
        self.inbox_dir = os.path.join(self.root, "inbox")
        self.outbox_dir = os.path.join(self.root, "outbox")
        self.state_path = os.path.join(self.root, "state.yaml")
        self.recent_path = os.path.join(self.root, "recent.md")
        self.history_path = os.path.join(self.root, "history.jsonl")

    # ── setup ────────────────────────────────────────────────────────────────
    def ensure(self, mode: int = int(Mode.MINIMAL), agents: list | None = None) -> None:
        os.makedirs(self.inbox_dir, exist_ok=True)
        os.makedirs(self.outbox_dir, exist_ok=True)
        if not os.path.exists(self.state_path):
            self._write_state({"mode": int(mode), "agents": agents or [], "cursors": {}})
        if not os.path.exists(self.recent_path):
            with open(self.recent_path, "w", encoding="utf-8") as fh:
                fh.write("# Recent buffer (rolling window — read this for pertinent context)\n\n")
        open(self.history_path, "a", encoding="utf-8").close()

    # ── state / mode ─────────────────────────────────────────────────────────
    def _read_state(self) -> dict:
        if not os.path.exists(self.state_path):
            return {"mode": int(Mode.MINIMAL), "agents": [], "cursors": {}}
        with open(self.state_path, encoding="utf-8") as fh:
            txt = fh.read()
        if yaml:
            return yaml.safe_load(txt) or {}
        return json.loads(txt or "{}")

    def _write_state(self, state: dict) -> None:
        with open(self.state_path, "w", encoding="utf-8") as fh:
            if yaml:
                yaml.safe_dump(state, fh, default_flow_style=False, sort_keys=False)
            else:
                json.dump(state, fh, indent=2)

    def get_mode(self) -> Mode:
        return Mode(int(self._read_state().get("mode", int(Mode.MINIMAL))))

    def set_mode(self, mode: int) -> None:
        st = self._read_state()
        st["mode"] = int(Mode(int(mode)))
        self._write_state(st)

    # ── posting ──────────────────────────────────────────────────────────────
    def post(self, msg: Message) -> Message:
        """Append to history always; update recent.md; deliver to a recipient's inbox subject to MODE.

        Mode gating (the core cross-talk policy):
          MINIMAL: only `critical` messages go to recent.md + inboxes; everything else is history-only
                   (agents work independently — matches the current baseline).
          LOCAL / FULL: all messages hit recent.md and route to the recipient's inbox.
        (Web sync — FULL — is handled by the orchestrator, not here.)
        """
        if msg.kind not in _KINDS:
            msg.kind = "log"
        mode = self.get_mode()
        msg.mode = int(mode)

        # history: always
        with open(self.history_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(msg.to_dict()) + "\n")

        # MINIMAL mode suppresses agent CROSS-TALK, but operator directives (`command`) and
        # `critical` messages ALWAYS route to the recipient's inbox regardless of mode.
        share = (mode != Mode.MINIMAL) or (msg.kind in ("critical", "command"))
        if not share:
            return msg

        self._append_recent(msg)

        # route to inbox(es)
        recipients = self._resolve_recipients(msg)
        for agent in recipients:
            if agent == msg.sender:
                continue
            with open(self._inbox(agent), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(msg.to_dict()) + "\n")
        return msg

    def write_status(self, agent: str, body: str, ts: str, msg_id: str,
                     kind: str = "status", ref: str | None = None) -> Message:
        """An agent emits status/result. Recorded in its outbox AND posted to the board."""
        m = Message(id=msg_id, ts=ts, sender=agent, recipient=_AUDIENCE_ALL, kind=kind, ref=ref, body=body)
        with open(self._outbox(agent), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(m.to_dict()) + "\n")
        return self.post(m)

    # ── reading ──────────────────────────────────────────────────────────────
    def read_recent(self, n: int | None = None) -> list:
        """Return the last n messages from history (token-cheap window). Default = recent_limit."""
        n = n or self.recent_limit
        out = []
        if not os.path.exists(self.history_path):
            return out
        with open(self.history_path, encoding="utf-8") as fh:
            lines = fh.readlines()
        for line in lines[-n:]:
            line = line.strip()
            if line:
                out.append(Message.from_dict(json.loads(line)))
        return out

    def read_history(self, since_id: str | None = None) -> list:
        out, hit = [], since_id is None
        if not os.path.exists(self.history_path):
            return out
        with open(self.history_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                m = Message.from_dict(json.loads(line))
                if hit:
                    out.append(m)
                elif m.id == since_id:
                    hit = True
        return out

    def read_inbox(self, agent: str, advance: bool = True) -> list:
        """Return NEW messages for `agent` since its cursor; advance the cursor when consumed."""
        path = self._inbox(agent)
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            all_msgs = [Message.from_dict(json.loads(l)) for l in fh if l.strip()]
        st = self._read_state()
        cursor = st.get("cursors", {}).get(agent, 0)
        fresh = all_msgs[cursor:]
        if advance and fresh:
            st.setdefault("cursors", {})[agent] = len(all_msgs)
            self._write_state(st)
        return fresh

    # ── internals ──────────────────────────────────────────────────────────────
    def _resolve_recipients(self, msg: Message) -> list:
        if msg.recipient and msg.recipient != _AUDIENCE_ALL:
            return [msg.recipient]
        agents = self._read_state().get("agents", [])
        return list(agents)

    def _append_recent(self, msg: Message) -> None:
        line = f"- `{msg.ts}` **{msg.sender}"
        line += f" → {msg.recipient}`" if msg.recipient != _AUDIENCE_ALL else "`"
        line += f" _[{msg.kind}]_ : {msg.body}\n"
        header = "# Recent buffer (rolling window — read this for pertinent context)\n\n"
        body_lines = []
        if os.path.exists(self.recent_path):
            with open(self.recent_path, encoding="utf-8") as fh:
                existing = fh.read()
            body_lines = [l for l in existing.splitlines() if l.startswith("- `")]
        body_lines.append(line.rstrip("\n"))
        body_lines = body_lines[-self.recent_limit:]
        with open(self.recent_path, "w", encoding="utf-8") as fh:
            fh.write(header + "\n".join(body_lines) + "\n")

    def _inbox(self, agent: str) -> str:
        return os.path.join(self.inbox_dir, f"{agent}.jsonl")

    def _outbox(self, agent: str) -> str:
        return os.path.join(self.outbox_dir, f"{agent}.jsonl")
