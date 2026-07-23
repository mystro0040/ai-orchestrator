# ai-orchestrator

A **stdlib-first** (zero required third-party deps) framework for orchestrating and messaging between
**local AI agents** via a file-based **blackboard**, with an optional **mobile web app** for remote,
cryptographically-signed control. General-purpose and reusable — a private config repo layers specific
agent roles/workflows on top.

## Architecture
```
   phone / browser ──HTTPS──► Web App (relay: password-gated queue + logs; holds NO secret/PIN)
                                   ▲  (outbound HTTPS only)
   Local Orchestrator ────────────┘   verifies HMAC+PIN locally, then:
        │  writes                     ── routes command → agent inbox (blackboard)
        ▼                             ── set mode / privileged system action (guarded)
   Blackboard (files)  ◄──read/write──►  Manager agent   ◄─recent buffer─►  Tester agent
     state.yaml · recent.md · history.jsonl · inbox/<agent>.jsonl · outbox/<agent>.jsonl
```
- **Agents never use IPC** — they read/write blackboard files; the orchestrator only touches files + the web app.
- **Outbound-only** from the local box: it polls the web app; nothing listens locally. No inbound exposure.
- **Security:** UI is password-gated; each command is HMAC-signed with a high-entropy **device secret**
  (only on the phone + orchestrator) keyed with a **4-digit PIN**. The web host never sees the secret or
  PIN, so a compromised host **cannot forge** a runnable command. Freshness window + nonce replay guard.

## Three modes (one toggle in `state.yaml`)
1. **Minimal** — agents work independently; only `critical` messages hit the shared file (baseline).
2. **Local continuous** — full Manager↔Tester cross-talk via the blackboard; web not involved.
3. **Full three-way** — + everything syncs up to the web app for the operator's phone.

## Modules (all stdlib)
`blackboard.py` buffers/modes · `signing.py` HMAC sign/verify · `webstore.py` queue+auth store ·
`webserver.py` stdlib http.server app · `ui.py` mobile UI (client-side signing) · `webclient.py`
outbound poller (urllib) · `adapters.py` agent delivery · `core.py` orchestrator + guarded shutdown ·
`cli.py` operator CLI.

## Quick start (local)
```bash
# 1. provision the device secret (put the SAME value into your phone once)
python3 -m orchestrator.cli init-secret ./secret.key
# 2. set the web password (prints the orchestrator api key)
python3 -m orchestrator.cli set-password ./webdata
# 3. run the web app locally
python3 -m orchestrator.cli web ./webdata --port 8787
# 4. run the orchestrator against a config (see config.example.yaml)
python3 -m orchestrator.cli orchestrate ./config.yaml
```

## Tests
```bash
python3 tests/test_all.py        # 17 tests: signing, blackboard modes, store, orchestrator trust boundary
```

## Deploy the web app remotely
It's plain `http.server`, so it runs on any Python host. Put it behind TLS (nginx / PaaS edge) and keep
`init-secret` + the PIN **off** that host. A FastAPI wrapper can replace `webserver.py` later without
touching the store — the security logic lives in `webstore.py`/`signing.py`, not the HTTP layer.

> Remote shutdown (`system.shutdown`) is **off by default** (`allow_privileged: false`, `dry_run: true`)
> and needs passwordless sudo for the shutdown command to actually run headless. See config.
