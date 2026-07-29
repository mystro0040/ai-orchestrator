#!/usr/bin/env bash
# install_agent_host.sh — turn a fresh server into a declared API-only agent host.
#
# RUN THIS ON THE AGENT HOST (the VPS). Never on a personal machine — it refuses there.
#
# WHAT IT DOES, IN ORDER
#   1. Refuses if this looks like a personal machine (a subscription credential is present).
#   2. Declares the host: /etc/ai-orchestrator/auth_mode = api   (root-owned, so an unprivileged
#      service user cannot downgrade its own boundary).
#   3. Installs the cloud-only api_runtime package into the orchestrator package.
#   4. Prompts for the Anthropic API key with HIDDEN input and writes it root-600.
#      The key is never passed as an argument, never echoed, and never enters shell history.
#   5. Verifies the result with `orchestrator auth-status` and fails loudly if it does not come
#      back clean.
#
# WHY THE KEY IS TYPED HERE RATHER THAN COPIED
#   Anything that transports the key — a scp, a paste into a chat, a file on the laptop — creates a
#   second copy that then has to be tracked and destroyed. Typing it once, into the machine that
#   will use it, means there is only ever one copy.

set -euo pipefail

ETC_DIR="/etc/ai-orchestrator"
MODE_FILE="$ETC_DIR/auth_mode"
ENV_FILE="$ETC_DIR/anthropic.env"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGED="$REPO_DIR/deploy/api_runtime"
TARGET="$REPO_DIR/orchestrator/api_runtime"

die() { echo "ABORT: $*" >&2; exit 1; }

echo "=== ai-orchestrator :: agent host installer ==="
echo "    repo: $REPO_DIR"
echo

# ── 1. refuse on anything that looks like a personal machine ──────────────────
# This is the guard that matters most. Running this script on a laptop would install the one
# component whose absence is what makes API use impossible there.
if [ -f "$HOME/.claude/.credentials.json" ]; then
  die "a subscription OAuth credential exists at ~/.claude/.credentials.json.
     This looks like a personal machine. An agent host must have NO subscription reachable.
     If this really is the server, whatever copied that file also copied more than it should have —
     find that out before continuing."
fi
if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
  die "CLAUDE_CODE_OAUTH_TOKEN is set in this environment. A subscription credential is reachable."
fi
if [ -d "$HOME/.claude/projects" ]; then
  die "~/.claude/projects exists — that directory holds conversation transcripts and does not
     appear on a server by itself. A home directory was copied here. Audit what else came with it."
fi
echo "[ok] no subscription credential reachable on this host"

[ "$(id -u)" -eq 0 ] || die "run as root (needed for $ETC_DIR)."

# ── 2. declare the host ──────────────────────────────────────────────────────
mkdir -p "$ETC_DIR"
chmod 755 "$ETC_DIR"
printf 'api\n' > "$MODE_FILE"
chmod 644 "$MODE_FILE"      # world-readable, root-writable: the service user reads it, cannot edit it
echo "[ok] declared auth_mode=api at $MODE_FILE (root-owned)"

# ── 3. install the cloud-only runtime ────────────────────────────────────────
[ -d "$STAGED" ] || die "staged runtime not found at $STAGED — is this the right repo?"
rm -rf "$TARGET"
cp -r "$STAGED" "$TARGET"
echo "[ok] installed api_runtime -> $TARGET"

# ── 4. the key: typed once, hidden, root-600 ─────────────────────────────────
if [ -f "$ENV_FILE" ]; then
  echo "[i] $ENV_FILE already exists."
  read -rp "    Replace the stored key? [y/N] " REPLACE
  [ "${REPLACE,,}" = "y" ] || { echo "[i] keeping the existing key."; SKIP_KEY=1; }
fi

if [ -z "${SKIP_KEY:-}" ]; then
  echo
  echo "    Paste the Anthropic API key. Input is hidden; it is not echoed and not stored in history."
  read -rs -p "    API key: " AKEY
  echo
  [ -n "$AKEY" ] || die "no key entered."
  case "$AKEY" in
    sk-ant-*) : ;;
    *) echo "    !! that does not start with 'sk-ant-'. Two things get pasted here by mistake:"
       echo "       the orchestrator's web-relay key, and a Claude Code OAuth token. Neither works."
       read -rp "    Continue anyway? [y/N] " CONT
       [ "${CONT,,}" = "y" ] || die "cancelled." ;;
  esac

  umask 077
  printf 'ANTHROPIC_API_KEY=%s\n' "$AKEY" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  chown root:root "$ENV_FILE"
  unset AKEY
  echo "[ok] key written to $ENV_FILE (root, 600). Load it via the systemd unit's EnvironmentFile=."
fi

# ── 5. verify, and fail loudly if it is not clean ────────────────────────────
echo
echo "=== verification ==="
cd "$REPO_DIR"
set +e
ANTHROPIC_API_KEY="$(sed -n 's/^ANTHROPIC_API_KEY=//p' "$ENV_FILE")" \
  python3 -m orchestrator.cli auth-status
RC=$?
set -e
[ $RC -eq 0 ] || die "auth-status did not come back clean (exit $RC). The host is NOT ready.
     Fix what it reported. Do not weaken the check to make this pass."

echo
echo "[DONE] this host is a declared API-only agent host."
echo "       Next: create the systemd units with EnvironmentFile=$ENV_FILE and nothing else auth-wise."
