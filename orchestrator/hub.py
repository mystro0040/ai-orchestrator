"""
hub.py — manage MULTIPLE engagements, each with its own isolated blackboard.

Phase 2 of the orchestrator: so you can run/manage several engagements at once (parallel testing),
the hub keeps one blackboard PER engagement under a hub root, keyed by a filesystem-safe slug of the
engagement name. Mirrors the scope-isolation model (each engagement is walled off) at the messaging
layer too — a command/log for engagement A never lands in engagement B's board.

    <hub_root>/<slug>/{state.yaml, recent.md, history.jsonl, inbox/, outbox/}

Slug: the engagement name (e.g. "programs/hackerone/bounty/remitly") with path separators flattened
to "__" so it's one directory — reversible and collision-free.
"""
from __future__ import annotations

import os

from .blackboard import Blackboard, Mode


# The MANAGER channel. Always registered, independent of any engagement, so the operator can reach
# the manager from anywhere without first selecting an engagement. Agents are engagement-scoped
# (they run inside one); the manager is not. Reserved name — never a real engagement.
GLOBAL_CHANNEL = "__manager__"
GLOBAL_LABEL = "Manager (no engagement)"


def is_global(name: str) -> bool:
    return (name or "").strip() == GLOBAL_CHANNEL


def slugify(engagement: str) -> str:
    return engagement.strip().strip("/").replace("\\", "/").replace("/", "__")


def unslug(slug: str) -> str:
    return slug.replace("__", "/")


class EngagementHub:
    def __init__(self, hub_root: str):
        self.root = os.path.abspath(os.path.expanduser(hub_root))
        os.makedirs(self.root, exist_ok=True)

    def blackboard(self, engagement: str, mode: int = int(Mode.MINIMAL),
                   agents: list | None = None) -> Blackboard:
        """Return (creating if needed) the blackboard for one engagement."""
        bb = Blackboard(os.path.join(self.root, slugify(engagement)))
        bb.ensure(mode=mode, agents=agents or ["manager", "tester"])
        return bb

    def has(self, engagement: str) -> bool:
        return os.path.isdir(os.path.join(self.root, slugify(engagement)))

    def list(self) -> list:
        """All engagements that have a blackboard here (as original names)."""
        out = []
        for name in sorted(os.listdir(self.root)):
            if os.path.isdir(os.path.join(self.root, name)):
                out.append(unslug(name))
        return out

    def register(self, engagement: str, agents: list | None = None) -> None:
        """Ensure an engagement's board exists (so it shows up + can receive commands)."""
        self.blackboard(engagement, agents=agents)
