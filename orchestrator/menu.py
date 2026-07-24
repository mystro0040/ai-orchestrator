"""
menu.py — interactive console for the orchestrator (same feel as the git/vault managers).

    python3 -m orchestrator.cli menu [config.yaml]

Everything you normally need is a numbered choice: start/stop the web app and orchestrator, see
status, reset the account, set a mode, install background services. No commands to memorise.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CFG = os.path.expanduser(
    "~/Workspace/Production_Ready/private/Offensive_Operations/ai-orchestrator-config/config.yaml")
DEFAULT_STORE = os.path.expanduser("~/.local/share/ao-webstore")


# ── small helpers ────────────────────────────────────────────────────────────
def _cfg(path):
    try:
        import yaml
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


def _pids(pattern):
    r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
    return [int(x) for x in r.stdout.split() if x.strip().isdigit()]


def _web_pids():
    return [p for p in _pids("orchestrator.cli web") if p != os.getpid()]


def _orch_pids():
    return [p for p in _pids("orchestrator.cli orchestrate") if p != os.getpid()]


def _http(url, timeout=3):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status
    except Exception:
        return None


def _kill(pids, name):
    if not pids:
        print(f"  [i] {name} is not running.")
        return
    for p in pids:
        try:
            os.kill(p, signal.SIGTERM)
        except OSError:
            pass
    time.sleep(1)
    still = [p for p in pids if os.path.exists(f"/proc/{p}")]
    for p in still:
        try:
            os.kill(p, signal.SIGKILL)
        except OSError:
            pass
    print(f"  [✓] stopped {name} ({len(pids)} process(es)).")


# ── actions ──────────────────────────────────────────────────────────────────
def show_status(cfg_path):
    cfg = _cfg(cfg_path)
    web, orch = _web_pids(), _orch_pids()
    url = cfg.get("web_url") or "http://127.0.0.1:8787"
    print("\n  ── STATUS ─────────────────────────────────────────────")
    print(f"  web app      : {'RUNNING pid ' + str(web[0]) if web else 'stopped'}   ({url})")
    print(f"  reachable    : {('HTTP ' + str(_http(url))) if _http(url) else 'no response'}")
    print(f"  orchestrator : {'RUNNING pid ' + str(orch[0]) if orch else 'stopped'}")
    store = DEFAULT_STORE
    try:
        sys.path.insert(0, HERE)
        from orchestrator.webstore import WebStore
        st = WebStore(store)
        print(f"  account      : {st.account_username() or '(none — create one in the web UI)'}")
    except Exception as e:
        print(f"  account      : (unreadable: {e.__class__.__name__})")
    engs = cfg.get("engagements") or []
    print(f"  engagements  : {len(engs)} configured")
    for e in engs:
        print(f"                 · {e}")
    hub = os.path.expanduser(cfg.get("hub_root", ""))
    if hub and os.path.isdir(hub):
        for d in sorted(os.listdir(hub)):
            sy = os.path.join(hub, d, "state.yaml")
            mode = "?"
            if os.path.exists(sy):
                for line in open(sy, encoding="utf-8"):
                    if line.startswith("mode:"):
                        mode = line.split(":", 1)[1].strip()
            print(f"  board {d[:38]:38} mode {mode}")
    print("  ───────────────────────────────────────────────────────\n")


def start_web(cfg_path):
    if _web_pids():
        print("  [i] web app already running.")
        return
    cfg = _cfg(cfg_path)
    url = cfg.get("web_url") or "http://127.0.0.1:8787"
    host, port = "127.0.0.1", "8787"
    if "://" in url:
        hp = url.split("://", 1)[1]
        host = hp.split(":")[0].split("/")[0] or host
        if ":" in hp:
            port = hp.split(":")[1].split("/")[0]
    log = os.path.expanduser("~/.local/share/ao-web.log")
    with open(log, "ab") as fh:
        subprocess.Popen([sys.executable, "-m", "orchestrator.cli", "web", DEFAULT_STORE,
                          "--host", host, "--port", port],
                         cwd=HERE, stdout=fh, stderr=fh, start_new_session=True)
    time.sleep(1.5)
    print(f"  [✓] web app started on {host}:{port}  (log: {log})")


def start_orch(cfg_path):
    """Start the listener in the BACKGROUND so this menu stays usable.

    The PIN is prompted here and handed to the child via its environment (never written to disk,
    never on the command line where `ps` would show it). Choose the SAME PIN each time — the browser
    signs commands with it and the two must match."""
    import getpass
    if _orch_pids():
        print("  [i] orchestrator already running.")
        return
    print("\n  The orchestrator verifies your signed commands and delivers them to agents.")
    # The browser signs with a key derived from the ACCOUNT PASSWORD, so the orchestrator must
    # derive the same key. The password is used locally only — it never reaches the web host.
    pw = ""
    try:
        sys.path.insert(0, HERE)
        from orchestrator.webstore import WebStore
        st = WebStore(DEFAULT_STORE)
        if st.account_exists():
            print(f"  Account '{st.account_username()}' — enter its password so the orchestrator can")
            print("  derive the same signing key your browser uses. (Stays on this machine.)")
            pw = getpass.getpass("  Account password: ")
            if not pw:
                print("  [!] cancelled — no password entered.")
                return
        else:
            print("  [!] No web account yet — create one in the web app first (option 2, then register).")
            return
    except Exception as e:
        print(f"  [!] could not read the account ({e.__class__.__name__}) — aborting.")
        return
    print("\n  Now the PIN — the SAME 4 digits you type in the web app.")
    print("  (Asked twice; a typo here silently rejects every command you send.)")
    pin = getpass.getpass("  Orchestrator PIN (hidden): ").strip()
    if not pin:
        print("  [!] cancelled — no PIN entered.")
        return
    if not (pin.isdigit() and len(pin) == 4):
        print("  [!] the web app sends a 4-DIGIT pin — that won't match. Cancelled.")
        return
    if pin != getpass.getpass("  Confirm PIN: ").strip():
        print("  [!] PINs do not match — cancelled, nothing started.")
        return
    log = os.path.expanduser("~/.local/share/ao-orchestrator.log")
    env = dict(os.environ, AO_PIN=pin, AO_PASSWORD=pw)
    with open(log, "ab") as fh:
        subprocess.Popen([sys.executable, "-m", "orchestrator.cli", "orchestrate", cfg_path],
                         cwd=HERE, env=env, stdout=fh, stderr=fh,
                         stdin=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2.5)
    if _orch_pids():
        print(f"  [✓] orchestrator running in the BACKGROUND (log: {log})")
        print("      This menu stays usable. Stop it with option 7.")
        try:
            tail = open(log, encoding="utf-8", errors="replace").read().strip().splitlines()[-1:]
            for line in tail:
                print(f"      {line}")
        except Exception:
            pass
    else:
        print(f"  [!] it exited immediately — check the log: {log}")


def reset_account():
    print("\n  This wipes the web account so the browser shows first-run registration again.")
    print("  Your engagements, boards and logs are NOT touched.")
    if input("  Type RESET to confirm: ").strip() != "RESET":
        print("  [i] cancelled.")
        return
    sys.path.insert(0, HERE)
    from orchestrator.webstore import WebStore
    WebStore(DEFAULT_STORE).reset_account()
    print("  [✓] account cleared — open the web app and create a new one.")


def set_mode(cfg_path):
    cfg = _cfg(cfg_path)
    hub = os.path.expanduser(cfg.get("hub_root", ""))
    if not hub or not os.path.isdir(hub):
        print("  [!] no hub_root found — start the orchestrator once first.")
        return
    boards = sorted(os.listdir(hub))
    print("\n  Boards:")
    for i, b in enumerate(boards, 1):
        print(f"    {i}) {b}")
    print("    a) ALL boards")
    which = input("  Which? ").strip()
    print("\n  1) Minimal — agents independent, only critical shared (least chatter)")
    print("  2) Local   — full agent<->agent cross-talk, web NOT involved")
    print("  3) Full    — everything also syncs to the web app (needed for live logs)")
    m = input("  Mode [1/2/3]: ").strip()
    if m not in ("1", "2", "3"):
        print("  [!] invalid.")
        return
    targets = boards if which.lower() == "a" else (
        [boards[int(which) - 1]] if which.isdigit() and 1 <= int(which) <= len(boards) else [])
    if not targets:
        print("  [!] invalid selection.")
        return
    for b in targets:
        p = os.path.join(hub, b, "state.yaml")
        lines, seen = [], False
        if os.path.exists(p):
            for line in open(p, encoding="utf-8"):
                if line.startswith("mode:"):
                    lines.append(f"mode: {m}\n"); seen = True
                else:
                    lines.append(line)
        if not seen:
            lines.insert(0, f"mode: {m}\n")
        with open(p, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        print(f"  [✓] {b} -> mode {m}")


def install_services(cfg_path):
    """systemd --user units so the web app + orchestrator survive a closed terminal / reboot."""
    d = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(d, exist_ok=True)
    web = f"""[Unit]
Description=AI Orchestrator web app
After=network.target

[Service]
Type=simple
WorkingDirectory={HERE}
ExecStart={sys.executable} -m orchestrator.cli web {DEFAULT_STORE} --host 127.0.0.1 --port 8787
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
"""
    orch = f"""[Unit]
Description=AI Orchestrator (command listener)
After=ao-web.service
Requires=ao-web.service

[Service]
Type=simple
WorkingDirectory={HERE}
Environment=AO_PIN_FILE=%h/.config/ai-orchestrator/pin
ExecStart={sys.executable} -m orchestrator.cli orchestrate {cfg_path}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"""
    open(os.path.join(d, "ao-web.service"), "w").write(web)
    open(os.path.join(d, "ao-orchestrator.service"), "w").write(orch)
    print(f"  [✓] wrote {d}/ao-web.service and ao-orchestrator.service")
    print("\n  Enable them with:")
    print("    systemctl --user daemon-reload")
    print("    systemctl --user enable --now ao-web.service")
    print("    loginctl enable-linger $USER      # keeps them running after you log out")
    print("\n  NOTE: the orchestrator service needs a PIN without a prompt. Either set")
    print("  `pin:` in config.yaml (less safe — it's then stored on disk), or keep running")
    print("  the orchestrator in the foreground (option 3). The web app service is safe to")
    print("  enable either way.")


def stop_all():
    _kill(_orch_pids(), "orchestrator")
    _kill(_web_pids(), "web app")


# ── menu loop ────────────────────────────────────────────────────────────────
MENU = """
1) Status (detail)
2) Start web app
3) Start orchestrator (background — asks for your PIN)
4) Set mode (per board)
5) Reset web account (delete it and register again)
6) Install boot services (systemd --user) — OPTIONAL
7) Stop everything

C) Clear screen
Q) Quit
"""


def _header(cfg_path):
    """Always-visible state banner: do I have an account, and is anything running?"""
    web, orch = _web_pids(), _orch_pids()
    url = (_cfg(cfg_path).get("web_url") or "http://127.0.0.1:8787")
    acct, who = None, None
    try:
        sys.path.insert(0, HERE)
        from orchestrator.webstore import WebStore
        st = WebStore(DEFAULT_STORE)
        acct, who = st.account_exists(), st.account_username()
    except Exception:
        pass
    if acct is None:
        a = "?  (store unreadable)"
    elif acct:
        a = f"✅ SET UP  (user: {who}) — you're good to go"
    else:
        a = "⚠️  NONE — open the web app and create one (first screen)"
    lines = [
        "",
        "==================== AI Orchestrator ====================",
        f"  account      : {a}",
        f"  web app      : {'✅ running  ' + url if web else '⛔ stopped   (menu 2 to start)'}",
        f"  orchestrator : {'✅ running' if orch else '⛔ stopped   (menu 3 to start)'}",
        "=========================================================",
    ]
    if acct is False:
        lines.append("  → No account yet: start the web app (2), open it, and register.")
    if acct and not orch:
        lines.append("  → Account ready, but commands need the orchestrator running (3).")
    return "\n".join(lines)


def main(argv):
    cfg_path = argv[1] if len(argv) > 1 else DEFAULT_CFG
    if not os.path.exists(cfg_path):
        print(f"[!] config not found: {cfg_path}")
        return 2
    print(f"config: {cfg_path}")
    while True:
        print(_header(cfg_path))
        print(MENU)
        c = input("> ").strip().lower()
        if c == "1":
            show_status(cfg_path)
        elif c == "2":
            start_web(cfg_path)
        elif c == "3":
            start_orch(cfg_path)
        elif c == "4":
            set_mode(cfg_path)
        elif c == "5":
            reset_account()
        elif c == "6":
            install_services(cfg_path)
        elif c == "7":
            stop_all()
        elif c == "c":
            os.system("clear")
        elif c == "q":
            return 0
        else:
            print("  [!] pick a number from the menu.")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
