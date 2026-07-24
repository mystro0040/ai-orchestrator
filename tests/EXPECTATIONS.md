# Test expectations (auto-generated — do not edit by hand)

Regenerate with `workspace.py test --write-expectations`. This lists the suites whose tests live in THIS directory, what each covers, how to run it, and the expected result.

> **Directive:** Tests are a REGRESSION FLOOR, not a substitute for exercising the real tool. When you change or upgrade a tool you MUST do BOTH: (1) drive the actual application to confirm the change works, and (2) run AND update its suite here. Green tests on unchanged code prove nothing about code you just changed. Never skip the live app because tests pass; never skip updating tests because the app works.

## orchestrator-unit  ·  unit

- **Run:** `python3 -m pytest tests/test_all.py -q` (from this directory)
- **Expected:** exit 0, all checks pass. Orchestrator unit suite (blackboard, hub routing, dispatch, signing). Runs from the repo root via pytest. 22 tests.
- **Covers:** orchestrator/core.py, orchestrator/blackboard.py, orchestrator/hub.py, orchestrator/adapters.py
- **Isolation:** isolated (temp dirs, no writes to tracked files).
- **Needs:** pytest (absent → the suite SKIPS, it does not fail).

## web-signing  ·  web  ·  CRITICAL

- **Run:** `python3 test_web_signing.py` (from this directory)
- **Expected:** exit 0, all checks pass. Operator web app auth + command-signing chain end to end on a loopback server: register/login, signed-envelope verify, wrong-password/PIN/replay/tamper all rejected, compromised host cannot forge. ~15 checks.
- **Covers:** orchestrator/webstore.py, orchestrator/webserver.py, orchestrator/signing.py, orchestrator/ui.py
- **Isolation:** isolated (temp dirs, no writes to tracked files).
