"""
adapters.py — how the orchestrator hands a verified command to a local agent, and reads its results.

Delivery is BLACKBOARD-PULL (the chosen model): the orchestrator only ever writes an agent's inbox
via the Blackboard; the agent reads it on its own cycle. No IPC, no keystroke injection. The abstract
AgentAdapter lets other delivery backends (tmux, headless spawn) be added later without touching core.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from .blackboard import Blackboard, Message


class AgentAdapter(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def deliver(self, command: str, ts: str, msg_id: str, ref: str | None = None) -> None:
        """Deliver a command to the agent."""

    @abstractmethod
    def collect(self) -> list:
        """Return any new status/result messages the agent has emitted."""


class BlackboardAgentAdapter(AgentAdapter):
    """Writes the command into the agent's inbox via the shared blackboard; reads its outbox."""

    def __init__(self, name: str, blackboard: Blackboard):
        super().__init__(name)
        self.bb = blackboard
        self._outbox_cursor = 0

    def deliver(self, command: str, ts: str, msg_id: str, ref: str | None = None) -> None:
        self.bb.post(Message(id=msg_id, ts=ts, sender="orchestrator", recipient=self.name,
                             kind="command", ref=ref, body=command))

    def collect(self) -> list:
        import json
        import os
        path = self.bb._outbox(self.name)
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            rows = [Message.from_dict(json.loads(l)) for l in fh if l.strip()]
        fresh = rows[self._outbox_cursor:]
        self._outbox_cursor = len(rows)
        return fresh
