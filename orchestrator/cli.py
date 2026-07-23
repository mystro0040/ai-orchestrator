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


def cmd_web(a):
    from .webserver import run
    run(WebStore(a.dir), host=a.host, port=a.port)


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
    from .adapters import BlackboardAgentAdapter
    from .core import Orchestrator
    from .webclient import WebClient
    cfg = _load_yaml(a.config)
    bb = Blackboard(cfg["blackboard"]); bb.ensure(mode=cfg.get("mode", 1), agents=cfg.get("agents", []))
    secret = signing.load_secret(cfg["secret_path"])
    pin = cfg.get("pin") or getpass.getpass("Orchestrator PIN: ")
    web = None
    if cfg.get("web_url"):
        web = WebClient(cfg["web_url"], cfg["api_key"])
    adapters = {name: BlackboardAgentAdapter(name, bb) for name in cfg.get("agents", [])}
    orch = Orchestrator(secret, pin, bb, adapters, web_client=web,
                        allow_privileged=cfg.get("allow_privileged", False),
                        dry_run=cfg.get("dry_run", True),
                        seen_nonces_path=cfg.get("seen_nonces_path"),
                        shutdown_cmd=cfg.get("shutdown_cmd"))
    interval = int(cfg.get("poll_interval_s", 5))
    print(f"[+] orchestrating: mode={int(bb.get_mode())} agents={list(adapters)} "
          f"web={'yes' if web else 'local-only'} privileged={orch.allow_privileged} dry_run={orch.dry_run}")
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
    s = sub.add_parser("web"); s.add_argument("dir"); s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787); s.set_defaults(fn=cmd_web)
    s = sub.add_parser("set-mode"); s.add_argument("dir"); s.add_argument("mode", choices=["1", "2", "3"])
    s.set_defaults(fn=cmd_set_mode)
    s = sub.add_parser("status"); s.add_argument("dir"); s.set_defaults(fn=cmd_status)
    s = sub.add_parser("orchestrate"); s.add_argument("config"); s.set_defaults(fn=cmd_orchestrate)
    a = p.parse_args(argv)
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
