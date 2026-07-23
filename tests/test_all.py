"""Zero-dependency test suite (stdlib unittest). Run: python3 tests/test_all.py

Covers the security-critical + core paths WITHOUT any network or web framework, and WITHOUT ever
executing a real privileged action (shutdown is asserted to stay in dry-run / blocked).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator import (Blackboard, Message, Mode, BlackboardAgentAdapter,  # noqa: E402
                          Orchestrator, signing, WebStore)

TS = "2026-07-22T20:00:00Z"      # fixed timestamps (no Date dependency)
NOW = 1_753_200_000              # fixed unix "now" for signing freshness


class TestSigning(unittest.TestCase):
    def setUp(self):
        self.sec = "ab" * 32
        self.pin = "4271"
        self.payload = {"type": "agent.command", "agent": "tester", "command": "recon"}

    def test_roundtrip_ok(self):
        env = signing.sign(self.sec, self.pin, self.payload, ts=NOW)
        ok, reason = signing.verify(self.sec, self.pin, env, now=NOW)
        self.assertTrue(ok, reason)

    def test_wrong_pin_fails(self):
        env = signing.sign(self.sec, self.pin, self.payload, ts=NOW)
        ok, reason = signing.verify(self.sec, "9999", env, now=NOW)
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_tampered_payload_fails(self):
        env = signing.sign(self.sec, self.pin, self.payload, ts=NOW)
        env["payload"]["command"] = "rm -rf /"     # attacker edits the command
        ok, _ = signing.verify(self.sec, self.pin, env, now=NOW)
        self.assertFalse(ok)

    def test_stale_fails(self):
        env = signing.sign(self.sec, self.pin, self.payload, ts=NOW - 10_000)
        ok, reason = signing.verify(self.sec, self.pin, env, now=NOW)
        self.assertFalse(ok)
        self.assertIn("stale", reason)

    def test_replay_fails(self):
        seen = set()
        env = signing.sign(self.sec, self.pin, self.payload, ts=NOW)
        ok1, _ = signing.verify(self.sec, self.pin, env, now=NOW, seen_nonces=seen)
        ok2, reason = signing.verify(self.sec, self.pin, env, now=NOW, seen_nonces=seen)
        self.assertTrue(ok1)
        self.assertFalse(ok2)
        self.assertIn("replay", reason)


class TestBlackboard(unittest.TestCase):
    def _bb(self, mode):
        d = tempfile.mkdtemp()
        bb = Blackboard(d)
        bb.ensure(mode=mode, agents=["manager", "tester"])
        return bb

    def test_minimal_mode_history_only_for_noncritical(self):
        bb = self._bb(Mode.MINIMAL)
        bb.post(Message(id="1", ts=TS, sender="tester", recipient="manager", kind="log", body="hi"))
        self.assertEqual(bb.read_inbox("manager"), [])          # not routed in MINIMAL
        self.assertEqual(len(bb.read_history()), 1)             # but still logged

    def test_minimal_mode_routes_critical(self):
        bb = self._bb(Mode.MINIMAL)
        bb.post(Message(id="1", ts=TS, sender="tester", recipient="manager", kind="critical", body="!!"))
        self.assertEqual(len(bb.read_inbox("manager")), 1)

    def test_local_mode_routes_and_cursor_advances(self):
        bb = self._bb(Mode.LOCAL)
        bb.post(Message(id="1", ts=TS, sender="tester", recipient="manager", kind="log", body="a"))
        first = bb.read_inbox("manager")
        self.assertEqual(len(first), 1)
        self.assertEqual(bb.read_inbox("manager"), [])          # cursor advanced -> nothing new
        bb.post(Message(id="2", ts=TS, sender="tester", recipient="manager", kind="log", body="b"))
        self.assertEqual(len(bb.read_inbox("manager")), 1)

    def test_recent_buffer_written(self):
        bb = self._bb(Mode.LOCAL)
        bb.post(Message(id="1", ts=TS, sender="tester", recipient="all", kind="log", body="ping"))
        self.assertTrue(os.path.exists(bb.recent_path))
        with open(bb.recent_path) as fh:
            self.assertIn("ping", fh.read())


class TestWebStore(unittest.TestCase):
    def setUp(self):
        self.store = WebStore(tempfile.mkdtemp())

    def test_password(self):
        self.store.set_password("hunter2")
        self.assertTrue(self.store.verify_password("hunter2"))
        self.assertFalse(self.store.verify_password("nope"))

    def test_queue_lifecycle(self):
        cid = self.store.enqueue({"payload": {"x": 1}}, ts=NOW, cmd_id="c1")
        self.assertEqual(cid, "c1")
        self.assertEqual(len(self.store.pending()), 1)
        self.store.mark_delivered(["c1"])
        self.assertEqual(len(self.store.pending()), 0)

    def test_sessions_and_apikey(self):
        self.store.set_password("pw")
        tok = self.store.create_session(now=NOW)
        self.assertTrue(self.store.valid_session(tok, now=NOW))
        self.assertFalse(self.store.valid_session("bogus", now=NOW))
        self.assertTrue(self.store.check_api_key(self.store.api_key()))


class TestOrchestrator(unittest.TestCase):
    def _setup(self, mode=Mode.LOCAL, allow_privileged=False, dry_run=True):
        d = tempfile.mkdtemp()
        bb = Blackboard(os.path.join(d, "bb"))
        bb.ensure(mode=mode, agents=["manager", "tester"])
        adapters = {"tester": BlackboardAgentAdapter("tester", bb),
                    "manager": BlackboardAgentAdapter("manager", bb)}
        orch = Orchestrator("cd" * 32, "1234", bb, adapters,
                            allow_privileged=allow_privileged, dry_run=dry_run,
                            seen_nonces_path=os.path.join(d, "nonces.txt"))
        return bb, orch

    def test_valid_command_delivered_to_agent(self):
        bb, orch = self._setup()
        env = signing.sign("cd" * 32, "1234", {"type": "agent.command", "agent": "tester",
                                               "command": "run recon"}, ts=NOW)
        res = orch.dispatch(env, ts=TS, msg_id="c1", now=NOW)
        self.assertTrue(res["ok"], res)
        self.assertEqual(len(bb.read_inbox("tester")), 1)

    def test_forged_command_rejected(self):
        bb, orch = self._setup()
        env = signing.sign("cd" * 32, "0000", {"type": "agent.command", "agent": "tester",
                                               "command": "x"}, ts=NOW)   # wrong PIN
        res = orch.dispatch(env, ts=TS, msg_id="c1", now=NOW)
        self.assertFalse(res["ok"])
        self.assertEqual(bb.read_inbox("tester"), [])

    def test_replayed_command_rejected(self):
        bb, orch = self._setup()
        env = signing.sign("cd" * 32, "1234", {"type": "set_mode", "mode": 2}, ts=NOW)
        self.assertTrue(orch.dispatch(env, ts=TS, msg_id="c1", now=NOW)["ok"])
        self.assertFalse(orch.dispatch(env, ts=TS, msg_id="c1", now=NOW)["ok"])   # replay

    def test_shutdown_blocked_when_not_privileged(self):
        bb, orch = self._setup(allow_privileged=False)
        env = signing.sign("cd" * 32, "1234", {"type": "system.shutdown"}, ts=NOW)
        res = orch.dispatch(env, ts=TS, msg_id="c1", now=NOW)
        self.assertFalse(res["ok"])
        self.assertIn("disabled", res["reason"])

    def test_shutdown_dryrun_when_privileged(self):
        # allow_privileged=True but dry_run=True -> reports intent, does NOT execute.
        bb, orch = self._setup(allow_privileged=True, dry_run=True)
        env = signing.sign("cd" * 32, "1234", {"type": "system.shutdown"}, ts=NOW)
        res = orch.dispatch(env, ts=TS, msg_id="c1", now=NOW)
        self.assertTrue(res["ok"])
        self.assertTrue(res["dry_run"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
