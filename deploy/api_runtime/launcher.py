"""launcher.py — run a headless Claude Code agent against an API key, with the scope wall verified.

WHY CLAUDE CODE RATHER THAN THE RAW API
---------------------------------------
The scope wall that keeps this operation inside authorised targets is a Claude Code **PreToolUse
hook** (`.claude/hooks/enforce_scope.py`). Raw API tool-calls do not fire it. So the moment an agent
stops being a Claude Code session, the guardrail silently disappears — not with an error, but by
simply never running. Keeping Claude Code as the runtime keeps the wall for free.

That makes one thing non-negotiable, and it is what most of this file is about:

    NEVER launch an agent without first proving the hook is registered and will fire.

"The hook file exists" is not that proof. A file can exist and be unregistered, unreadable, or
registered under a matcher that does not cover the tool the agent will use. `preflight()` checks the
registration, not the filename, and `launch_agent()` refuses to run without it.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

#: The tool whose invocations must be gated. Bash is the one that reaches the network.
REQUIRED_HOOK_MATCHER = "Bash"
REQUIRED_HOOK_NAME = "enforce_scope.py"


class AgentLaunchError(RuntimeError):
    """Raised instead of launching when the runtime cannot be shown to be safe."""


def _settings_paths(project_dir: str) -> list:
    return [os.path.join(project_dir, ".claude", "settings.json"),
            os.path.join(project_dir, ".claude", "settings.local.json")]


def scope_hook_registered(project_dir: str) -> tuple:
    """Return (ok, reason). Does the project register the scope wall as a PreToolUse hook?

    Deliberately parses the settings and looks for the hook COMMAND under a PreToolUse matcher that
    covers the required tool. Checking that the .py file exists on disk would answer a different and
    much weaker question — one that stays 'yes' after the registration is deleted.
    """
    seen_any_settings = False
    for path in _settings_paths(project_dir):
        if not os.path.isfile(path):
            continue
        seen_any_settings = True
        try:
            with open(path, encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, ValueError) as e:
            return False, f"{path} could not be parsed ({e.__class__.__name__}) — cannot confirm the hook"

        for entry in (cfg.get("hooks", {}) or {}).get("PreToolUse", []) or []:
            matcher = str(entry.get("matcher", ""))
            if REQUIRED_HOOK_MATCHER not in matcher:
                continue
            for hook in entry.get("hooks", []) or []:
                if REQUIRED_HOOK_NAME in str(hook.get("command", "")):
                    return True, f"registered in {os.path.basename(path)} under matcher {matcher!r}"

    if not seen_any_settings:
        return False, f"no .claude/settings.json found under {project_dir}"
    return False, (f"settings exist but no PreToolUse hook running {REQUIRED_HOOK_NAME} is registered "
                   f"for matcher {REQUIRED_HOOK_MATCHER!r}")


def preflight(project_dir: str, env=None) -> list:
    """Return a list of blocking problems. Empty means it is safe to launch.

    Every item here is a refusal condition, not a warning. There is no severity ladder on purpose:
    a launcher that runs anyway after printing a warning is a launcher that runs anyway.
    """
    env = os.environ if env is None else env
    problems = []

    if not env.get("ANTHROPIC_API_KEY", "").strip():
        problems.append("ANTHROPIC_API_KEY is not set — this runtime has no credential and no fallback.")

    # A subscription reachable here would defeat the point of running on this host at all.
    if env.get("CLAUDE_CODE_OAUTH_TOKEN", "").strip():
        problems.append("CLAUDE_CODE_OAUTH_TOKEN is set — a subscription credential is reachable on "
                        "the agent host. Refusing to launch.")
    home = env.get("HOME") or os.path.expanduser("~")
    if os.path.isfile(os.path.join(home, ".claude", ".credentials.json")):
        problems.append("~/.claude/.credentials.json exists — a subscription credential is reachable "
                        "on the agent host. Refusing to launch.")

    if not shutil.which("claude"):
        problems.append("the `claude` binary is not on PATH — Claude Code is the runtime, and with it "
                        "absent the scope hook cannot fire at all.")

    if not os.path.isdir(project_dir):
        problems.append(f"project dir {project_dir} does not exist")
    else:
        ok, reason = scope_hook_registered(project_dir)
        if not ok:
            problems.append(f"the scope wall is not provably active: {reason}")

    return problems


def launch_agent(role: str, prompt: str, project_dir: str, session_id: str | None = None,
                 env=None, timeout_s: int = 1800, runner=None) -> dict:
    """Run one headless Claude Code turn as `role`. Raises AgentLaunchError rather than degrading.

    `runner` is injectable so tests can assert on the constructed command without executing it.
    """
    env = dict(os.environ if env is None else env)
    problems = preflight(project_dir, env)
    if problems:
        raise AgentLaunchError(
            "refusing to launch the %s agent:\n  - %s" % (role, "\n  - ".join(problems)))

    cmd = ["claude", "--print"]
    if session_id:
        cmd += ["--resume", session_id]
    cmd += [prompt]

    runner = runner or subprocess.run
    proc = runner(cmd, cwd=project_dir, env=env, capture_output=True, text=True, timeout=timeout_s)
    return {"role": role, "cmd": cmd, "returncode": proc.returncode,
            "stdout": proc.stdout, "stderr": proc.stderr}
