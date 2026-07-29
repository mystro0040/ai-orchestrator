"""cli.py — operator entry point (stdlib argparse). Scriptable; the private config wraps it.

  python -m orchestrator.cli init-secret   <path>
  python -m orchestrator.cli set-password  <webstore_dir>
  python -m orchestrator.cli show-apikey    <webstore_dir>
  python -m orchestrator.cli web            <webstore_dir> [--host H --port P]
  python -m orchestrator.cli set-mode       <blackboard_dir> <1|2|3>
  python -m orchestrator.cli orchestrate    <config.yaml>          # poll loop
  python -m orchestrator.cli status         <blackboard_dir>
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time

from . import signing
from .blackboard import Blackboard, Mode
from .webstore import WebStore


def _load_yaml(path):
    import json
    try:
        import yaml
        with open(path) as fh:
            return yaml.safe_load(fh)
    except Exception:
        with open(path) as fh:
            return json.load(fh)


def cmd_init_secret(a):
    sec = signing.provision_secret(a.path)
    print(f"[+] device secret written to {a.path} (chmod 600).")
    print(f"    Provision this SAME secret into the trusted phone (one-time). Never send it to the web host.")
    print(f"    secret: {sec}")


def cmd_set_password(a):
    store = WebStore(a.dir)
    pw = getpass.getpass("New web UI password: ")
    if pw != getpass.getpass("Confirm: "):
        print("[!] mismatch"); return 1
    store.set_password(pw)
    print(f"[+] password set. Orchestrator api key: {store.api_key()}")


def cmd_show_apikey(a):
    print(WebStore(a.dir).api_key())


def cmd_rotate_apikey(a):
    """Rotate the relay api_key. The ONLY command that changes an existing one.

    `set-password` does NOT rotate it — it uses setdefault, so on a store that already has a key it
    leaves it alone while looking like it worked. If you are here because a key leaked, this is the
    command that actually replaces it.
    """
    store = WebStore(a.dir)
    old, new = store.rotate_api_key()
    if old is None:
        print("[i] no previous api_key in this store — one has been created.")
    else:
        print(f"[+] api_key rotated. old ...{old[-6:]}  ->  new ...{new[-6:]}")
    print(f"    new key: {new}")
    print()
    print("    NOT DONE YET — the key lives in TWO places and they must match:")
    print(f"      1. this store            {store.config_path}   (just updated)")
    print("      2. the orchestrator config  config.yaml -> api_key:   (update it now)")
    print("    Until both match, the orchestrate loop cannot talk to the web relay.")
    if old is not None:
        print()
        print("    Treat the old key as burned. If it reached a repo, rotating here does not remove")
        print("    it from git history — it only makes the copy in that history useless.")


def cmd_menu(a):
    from .menu import main as menu_main
    return menu_main([None, a.config] if getattr(a, "config", None) else [None])


def cmd_web(a):
    from . import auth_boundary
    auth_boundary.assert_boundary("web")      # FIRST LINE. Before any socket is opened.
    from .webserver import run
    run(WebStore(a.dir), host=a.host, port=a.port)


def cmd_auth_status(a):
    """Report the credential boundary without enforcing it. Safe to run anywhere, exits 0 or 1."""
    from . import auth_boundary
    print("\n-------- Anthropic credential boundary --------")
    out = auth_boundary.describe()
    print(out)
    print("-----------------------------------------------")
    return 1 if ("BLOCKED" in out or "(NONE)" in out) else 0


def cmd_set_mode(a):
    bb = Blackboard(a.dir); bb.ensure()
    bb.set_mode(int(a.mode))
    print(f"[+] mode = {int(bb.get_mode())} ({Mode(int(bb.get_mode())).name})")


def cmd_status(a):
    bb = Blackboard(a.dir)
    print(f"blackboard: {bb.root}")
    print(f"mode      : {int(bb.get_mode())} ({bb.get_mode().name})")
    recent = bb.read_recent(10)
    print(f"recent    : {len(recent)} msg(s)")
    for m in recent[-10:]:
        print(f"  {m.ts} {m.sender}->{m.recipient} [{m.kind}] {m.body[:70]}")


def cmd_orchestrate(a):
    from . import auth_boundary
    auth_boundary.assert_boundary("orchestrate")   # FIRST LINE. Before any agent work.
    from .adapters import BlackboardAgentAdapter
    from .core import Orchestrator
    from .webclient import WebClient
    from .hub import EngagementHub
    cfg = _load_yaml(a.config)
    # KEY SELECTION — must match whatever the BROWSER signs with.
    # If a web account exists, the browser derives its signing key from the account password, so the
    # orchestrator must derive the SAME key (it has local filesystem access to the salt). Falling
    # back to the device-secret file only when there is no account keeps older setups working.
    secret = None
    _store_dir = cfg.get("webstore_dir") or os.path.expanduser("~/.local/share/ao-webstore")
    try:
        _st = WebStore(_store_dir)
        if _st.account_exists():
            _user = _st.account_username()
            _salt = _st.kdf_salt(_user)
            print(f"[i] account '{_user}' found — the browser signs with a key derived from your")
            print("    password, so enter it here to derive the same key (it never leaves this host).")
            _pw = os.environ.get("AO_PASSWORD") or getpass.getpass("    Account password: ")
            secret = signing.derive_account_key(_pw, _salt)
    except Exception as _e:
        print(f"[!] account key derivation unavailable ({_e.__class__.__name__}); using secret file")
    if secret is None:
        secret = signing.load_secret(os.path.expanduser(cfg["secret_path"]))
    # PIN precedence: config (least safe, on disk) -> AO_PIN env (menu passes it to a background
    # child) -> interactive prompt. Env lets the orchestrator run detached without a tty.
    pin = cfg.get("pin") or os.environ.get("AO_PIN") or getpass.getpass("Orchestrator PIN: ")
    agents = cfg.get("agents", ["manager", "tester"])
    web = WebClient(cfg["web_url"], cfg["api_key"]) if cfg.get("web_url") else None
    common = dict(web_client=web, allow_privileged=cfg.get("allow_privileged", False),
                  dry_run=cfg.get("dry_run", True), seen_nonces_path=cfg.get("seen_nonces_path"),
                  shutdown_cmd=cfg.get("shutdown_cmd"))
    engagements = list(cfg.get("engagements") or [])
    if engagements:                                       # MULTI-engagement mode
        from .hub import GLOBAL_CHANNEL
        # The manager channel is ALWAYS available and is not an engagement — so the operator can
        # message the manager without selecting one. Registered first so it heads the UI list.
        if GLOBAL_CHANNEL not in engagements:
            engagements.insert(0, GLOBAL_CHANNEL)
        hub = EngagementHub(os.path.expanduser(cfg.get("hub_root", "./hub")))
        for e in engagements:
            hub.register(e, agents=agents)
        orch = Orchestrator(secret, pin, hub=hub, agent_names=agents,
                            known_engagements=engagements, **common)
        if web:
            web.set_engagements(engagements)              # so the web UI lists them
        print(f"[+] orchestrating (MULTI): {len(engagements)} engagement(s) {engagements} "
              f"agents={agents} web={'yes' if web else 'local-only'}")
    else:                                                 # single-engagement (legacy)
        bb = Blackboard(os.path.expanduser(cfg["blackboard"])); bb.ensure(mode=cfg.get("mode", 1), agents=agents)
        adapters = {name: BlackboardAgentAdapter(name, bb) for name in agents}
        orch = Orchestrator(secret, pin, bb, adapters, **common)
        print(f"[+] orchestrating (single): mode={int(bb.get_mode())} agents={agents} "
              f"web={'yes' if web else 'local-only'}")
    interval = int(cfg.get("poll_interval_s", 5))
    if not web:
        print("    (local-only: no web poll; agents cross-talk via the blackboard.)"); return 0
    try:
        while True:
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            res = orch.poll_once(now_ts=ts)
            if res.get("processed"):
                print(f"[{ts}] processed {res['processed']} command(s)")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[+] stopped.")


def main(argv=None):
    p = argparse.ArgumentParser(prog="orchestrator", description="AI orchestration / messaging (stdlib)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init-secret"); s.add_argument("path"); s.set_defaults(fn=cmd_init_secret)
    s = sub.add_parser("set-password"); s.add_argument("dir"); s.set_defaults(fn=cmd_set_password)
    s = sub.add_parser("show-apikey"); s.add_argument("dir"); s.set_defaults(fn=cmd_show_apikey)
    s = sub.add_parser("rotate-apikey", help="replace the relay api_key (set-password does NOT)")
    s.add_argument("dir"); s.set_defaults(fn=cmd_rotate_apikey)
    pm = sub.add_parser("menu"); pm.add_argument("config", nargs="?"); pm.set_defaults(fn=cmd_menu)
    s = sub.add_parser("web"); s.add_argument("dir"); s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787); s.set_defaults(fn=cmd_web)
    s = sub.add_parser("set-mode"); s.add_argument("dir"); s.add_argument("mode", choices=["1", "2", "3"])
    s.set_defaults(fn=cmd_set_mode)
    s = sub.add_parser("status"); s.add_argument("dir"); s.set_defaults(fn=cmd_status)
    s = sub.add_parser("orchestrate"); s.add_argument("config"); s.set_defaults(fn=cmd_orchestrate)
    s = sub.add_parser("auth-status", help="report the Anthropic credential boundary for this host")
    s.set_defaults(fn=cmd_auth_status)
    a = p.parse_args(argv)
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
