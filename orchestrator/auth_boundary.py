"""auth_boundary.py — which Anthropic credential this host may resolve, enforced rather than described.

THE PROBLEM THIS SOLVES
-----------------------
Two credentials can reach Claude: a consumer SUBSCRIPTION (an OAuth login) and an API KEY (metered,
billed per token). They have different risk profiles and belong on different machines:

  * subscription — fine on a personal machine. On a datacenter IP it resembles account sharing.
  * api key      — fine anywhere, including datacenters. Its risk is spend and theft, not location.

The dangerous states are the two crossings: a subscription resolving on a rented server, or an API
key resolving on a laptop where the flat-rate subscription already covers the work (silent metered
spend). Both are easy to reach by accident, because `ANTHROPIC_API_KEY` is an ENVIRONMENT VARIABLE —
ambient, inherited by every child process, and able to survive in a forgotten shell for days.

WHY A CONFIG FLAG ALONE WOULD BE THEATRE
----------------------------------------
Claude Code does not read this module. It reads the environment. So a mode setting can only ever
DESCRIBE intent — it cannot, by itself, stop anything. What makes the boundary real is that the
capability is physically absent on the wrong side:

  * On a subscription host, the `api_runtime` package IS NOT INSTALLED. There is no code present
    that can launch an agent against an API key. A key could be exported into the environment and
    still nothing here would use it.
  * On an API host, no subscription credential EXISTS to fall back to — no OAuth file, no token.

This module is the part that notices when that physical arrangement has been violated, and refuses
to run. It is a tripwire on a structural guarantee, not the guarantee itself. Stated plainly so
nobody later mistakes the check for the protection.

WHAT IT DOES NOT COVER
----------------------
It gates the orchestrator's own entrypoints. It does not gate a human opening a terminal and typing
`claude` directly — nothing in this process can. Only the absent-capability arrangement above, or a
separate OS user, covers that. Do not read this file as wider than it is.

DESIGN
------
Three steps, deliberately separated so the decision is a pure function:

    collect_signals()  — all environment/filesystem lookups, injectable for tests
    evaluate()         — pure: (mode, signals) -> list of violations. Where the tests live.
    assert_boundary()  — performs I/O, prints, and exits non-zero. No fallback branch.

MODES — exactly two legal values, and NO DEFAULT
------------------------------------------------
    subscription : an API key must NOT be resolvable, and api_runtime must NOT be installed.
    api          : an API key MUST be present, api_runtime MUST be installed, and EVERY
                   subscription signal must be absent.

An unset or unrecognised mode is a hard error, never a fallback. "I could not tell which host this
is" must never resolve to "proceed anyway" — that is the exact failure this file exists to prevent.
"""
from __future__ import annotations

import os
import sys

LEGAL_MODES = ("subscription", "api")

#: Read in this order; the first that exists wins. The system path is checked FIRST on purpose —
#: on a server it is root-owned, so an unprivileged service user cannot downgrade its own boundary.
MODE_FILES = (
    "/etc/ai-orchestrator/auth_mode",
    "~/.config/ai-orchestrator/auth_mode",
)

#: Deliberately NOT overridable by an environment variable. An env override would be a bypass, and
#: a bypass on the one control that separates a subscription from a datacenter is not a convenience.


class BoundaryError(Exception):
    """The declared mode is missing, unreadable, or not one of LEGAL_MODES."""


# ── step 1: collect ───────────────────────────────────────────────────────────
def read_declared_mode(mode_files=MODE_FILES) -> str:
    """Return the host's declared mode. Raises BoundaryError if absent or illegal.

    Absent is an ERROR, not a default. A machine that has not said what it is does not get to run.
    """
    tried = []
    for raw in mode_files:
        path = os.path.expanduser(raw)
        tried.append(path)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                value = fh.read().strip().lower()
        except OSError as e:
            raise BoundaryError(f"could not read the auth-mode declaration at {path}: {e}") from e
        if value not in LEGAL_MODES:
            raise BoundaryError(
                f"{path} declares auth_mode={value!r}, which is not one of {list(LEGAL_MODES)}. "
                "Refusing to guess."
            )
        return value
    raise BoundaryError(
        "no auth-mode declaration found. Looked in:\n  "
        + "\n  ".join(tried)
        + "\nWrite exactly one of "
        + " / ".join(LEGAL_MODES)
        + " into one of those paths. There is no default: a host that has not declared which "
          "credential it may use does not run."
    )


def api_runtime_installed(pkg_dir=None) -> bool:
    """Is the cloud-only agent-launch package physically present next to this module?

    Checked on the FILESYSTEM rather than with an import, on purpose. An import test answers "can
    Python find something by this name right now", which a stray sys.path entry or a leftover
    __pycache__ can influence. The question that matters is narrower and more physical: was this
    package shipped to this machine?
    """
    pkg_dir = pkg_dir or os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(pkg_dir, "api_runtime")
    return os.path.isdir(target) and os.path.isfile(os.path.join(target, "__init__.py"))


def collect_signals(env=None, home=None, pkg_dir=None) -> dict:
    """Gather every fact the decision depends on. All lookups injectable so tests need no real HOME."""
    env = os.environ if env is None else env
    home = home or os.path.expanduser("~")
    return {
        # API side
        "api_key": bool(env.get("ANTHROPIC_API_KEY", "").strip()),
        "auth_token": bool(env.get("ANTHROPIC_AUTH_TOKEN", "").strip()),
        "api_runtime": api_runtime_installed(pkg_dir),
        # subscription side
        "oauth_token_env": bool(env.get("CLAUDE_CODE_OAUTH_TOKEN", "").strip()),
        "oauth_cred_file": os.path.isfile(os.path.join(home, ".claude", ".credentials.json")),
        # Transcripts. Not a credential — a TELL. Their presence on an API host means somebody
        # copied a personal home directory onto a server wholesale, which almost certainly dragged
        # the OAuth file along with it, and separately spills conversation history onto a rented box.
        "transcripts": os.path.isdir(os.path.join(home, ".claude", "projects")),
    }


# ── step 2: evaluate (pure — this is where the tests live) ────────────────────
def evaluate(mode: str, signals: dict) -> list:
    """Return a list of violation strings. Empty list means the host is in a legal state.

    Pure: no I/O, no environment, no exit. Given the same inputs it always returns the same answer,
    which is what makes the enforcement rules straightforward to test exhaustively.
    """
    if mode not in LEGAL_MODES:
        return [f"auth_mode={mode!r} is not one of {list(LEGAL_MODES)}"]

    v = []

    # Applies in BOTH modes: the API rejects these two together, and a request that fails on
    # credential precedence is far more confusing than one that never leaves.
    if signals.get("api_key") and signals.get("auth_token"):
        v.append(
            "ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN are both set. The API rejects this "
            "combination; unset one."
        )

    if mode == "subscription":
        if signals.get("api_key"):
            v.append(
                "ANTHROPIC_API_KEY is set on a host declared 'subscription'. This host's work is "
                "already covered by the flat-rate subscription, so a key here means silent metered "
                "spend. Unset it in this shell (never in a shell profile)."
            )
        if signals.get("api_runtime"):
            v.append(
                "the api_runtime package is installed on a host declared 'subscription'. That "
                "package exists only to launch agents against an API key and must never ship here — "
                "its absence is what makes API use physically impossible on this machine. Remove it."
            )

    elif mode == "api":
        if not signals.get("api_key"):
            v.append(
                "ANTHROPIC_API_KEY is not set on a host declared 'api'. There is deliberately no "
                "fallback to a subscription, so there is no credential to run with."
            )
        if not signals.get("api_runtime"):
            v.append(
                "the api_runtime package is missing on a host declared 'api'. Nothing here can "
                "launch an agent. The deployment is incomplete."
            )
        if signals.get("oauth_cred_file"):
            v.append(
                "a subscription OAuth credential file (~/.claude/.credentials.json) exists on a host "
                "declared 'api'. STOP: a personal subscription is resolvable on this machine, which "
                "is the single condition this whole boundary exists to prevent. Delete it."
            )
        if signals.get("oauth_token_env"):
            v.append(
                "CLAUDE_CODE_OAUTH_TOKEN is set on a host declared 'api'. A subscription credential "
                "is reachable here. Unset it and find out what set it."
            )
        if signals.get("transcripts"):
            v.append(
                "~/.claude/projects exists on a host declared 'api'. That directory holds "
                "conversation transcripts and does not arrive by itself — somebody copied a personal "
                "home directory onto this machine, which very likely brought the OAuth credential "
                "with it. Treat this as a copy-the-whole-home-dir mistake and audit what else landed."
            )

    return v


# ── step 3: act ───────────────────────────────────────────────────────────────
def assert_boundary(entrypoint: str = "orchestrator", mode_files=MODE_FILES,
                    env=None, home=None, pkg_dir=None, exit_fn=None) -> str:
    """Enforce the boundary or terminate. Returns the mode on success. NO FALLBACK BRANCH.

    Call this on the FIRST line of an entrypoint, before any agent work, any network call, and any
    state mutation. Refusing to start is always the correct outcome when the credential arrangement
    cannot be confirmed — a run that proceeds under an unknown credential is the failure.
    """
    exit_fn = exit_fn or sys.exit

    try:
        mode = read_declared_mode(mode_files)
    except BoundaryError as e:
        print(f"[BOUNDARY] {entrypoint}: refusing to start.\n{e}", file=sys.stderr)
        exit_fn(1)
        return ""    # reached only when a test injects a non-exiting exit_fn

    signals = collect_signals(env=env, home=home, pkg_dir=pkg_dir)
    violations = evaluate(mode, signals)

    if violations:
        print(f"[BOUNDARY] {entrypoint}: refusing to start — host declares auth_mode={mode!r} "
              f"but its credential state contradicts that:", file=sys.stderr)
        for x in violations:
            print(f"  !! {x}", file=sys.stderr)
        print("\n  Nothing has been run. Fix the host, do not weaken the check.", file=sys.stderr)
        exit_fn(1)
        return ""

    return mode


def describe(mode_files=MODE_FILES, env=None, home=None, pkg_dir=None) -> str:
    """Human-readable boundary status. Used by `orchestrator auth-status`; never exits."""
    lines = []
    try:
        mode = read_declared_mode(mode_files)
        lines.append(f"  declared auth_mode : {mode}")
    except BoundaryError as e:
        return f"  declared auth_mode : (NONE)\n\n  {e}"

    s = collect_signals(env=env, home=home, pkg_dir=pkg_dir)
    yn = lambda b: "yes" if b else "no"      # noqa: E731
    lines += [
        f"  ANTHROPIC_API_KEY set          : {yn(s['api_key'])}",
        f"  ANTHROPIC_AUTH_TOKEN set       : {yn(s['auth_token'])}",
        f"  api_runtime installed          : {yn(s['api_runtime'])}",
        f"  subscription OAuth file        : {yn(s['oauth_cred_file'])}",
        f"  CLAUDE_CODE_OAUTH_TOKEN set    : {yn(s['oauth_token_env'])}",
        f"  ~/.claude/projects present     : {yn(s['transcripts'])}",
    ]
    violations = evaluate(mode, s)
    if violations:
        lines.append(f"\n  VERDICT : BLOCKED ({len(violations)} violation(s))")
        lines += [f"    !! {x}" for x in violations]
    else:
        lines.append("\n  VERDICT : OK — credential state matches the declared mode.")
    return "\n".join(lines)
