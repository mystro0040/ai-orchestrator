"""Zero-dependency tests for relay api_key ROTATION. Run: python3 tests/test_apikey_rotation.py

WHY THIS FILE EXISTS
The project's documented rotation procedure was "run set-password, then show-apikey" — and it did
not rotate anything. `set_password` and `register` both use `cfg.setdefault("api_key", ...)`, which
writes only when the key is ABSENT. On a store that already had a key, the command succeeded, printed
a key, and changed nothing. An operator following the documented remedy for a leaked key would have
read back the leaked key and believed the leak was closed.

So these tests do two jobs:
  1. Prove `rotate_api_key()` genuinely replaces the key.
  2. PIN THE SETDEFAULT BEHAVIOUR IN PLACE with an explicit test, so that if someone later "fixes"
     set_password to rotate as a side effect, this suite fails loudly and they have to decide that
     deliberately. Silent rotation would desync the store from config.yaml and break the orchestrate
     loop with no obvious cause. The bug was never that setdefault is wrong — it is that nothing
     else offered rotation, and the docs claimed this did.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator import WebStore  # noqa: E402


class TestApiKeyRotation(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = WebStore(self.dir)

    # ── the fix ────────────────────────────────────────────────────────────────
    def test_rotate_changes_the_key(self):
        before = self.store.api_key()
        old, new = self.store.rotate_api_key()
        self.assertEqual(old, before, "rotate should report the key it replaced")
        self.assertNotEqual(old, new, "rotate must produce a DIFFERENT key")
        self.assertEqual(self.store.api_key(), new, "the new key must be what is persisted")

    def test_rotate_persists_across_a_fresh_store_object(self):
        _, new = self.store.rotate_api_key()
        reopened = WebStore(self.dir)
        self.assertEqual(reopened.api_key(), new, "rotation must survive a reload, not just the object")

    def test_rotate_on_an_empty_store_reports_no_previous_key(self):
        old, new = WebStore(tempfile.mkdtemp()).rotate_api_key()
        self.assertIsNone(old, "an untouched store has no previous key to report")
        self.assertTrue(new)

    def test_repeated_rotations_never_repeat_a_key(self):
        seen = {self.store.api_key()}
        for _ in range(20):
            _, new = self.store.rotate_api_key()
            self.assertNotIn(new, seen, "a rotation returned a key that had already been issued")
            seen.add(new)

    def test_rotated_key_is_full_length(self):
        _, new = self.store.rotate_api_key()
        self.assertEqual(len(new), 48, "token_hex(24) is 48 hex chars — a short key means a weakened rotation")

    def test_rotation_does_not_disturb_the_password(self):
        self.store.set_password("correct horse battery staple")
        self.store.rotate_api_key()
        self.assertTrue(self.store.verify_password("correct horse battery staple"),
                        "rotating the relay key must not lock the operator out of the web UI")

    def test_check_api_key_follows_the_rotation(self):
        old = self.store.api_key()
        _, new = self.store.rotate_api_key()
        self.assertFalse(self.store.check_api_key(old), "the OLD key must stop being accepted")
        self.assertTrue(self.store.check_api_key(new))

    # ── the regression pin: prove the ORIGINAL bug is still the documented shape ──
    def test_set_password_does_NOT_rotate(self):
        """Pinned deliberately. This is the behaviour that made the docs wrong.

        If this test ever fails, someone made set_password rotate as a side effect. That is a
        breaking change, not a fix: the key is half of a matched pair with config.yaml, and
        changing it silently breaks the orchestrate loop. Make that choice on purpose or not at all.
        """
        first = self.store.api_key()
        self.store.set_password("one")
        self.store.set_password("two-completely-different")
        self.assertEqual(self.store.api_key(), first,
                         "set_password changed the api_key — see this test's docstring before 'fixing' it")

    def test_reset_account_does_NOT_rotate(self):
        """Same reasoning. Wiping the GUI account is not a credential rotation."""
        first = self.store.api_key()
        self.store.set_password("one")
        self.store.reset_account()
        self.assertEqual(self.store.api_key(), first)

    def test_rotation_is_the_only_path_that_changes_an_existing_key(self):
        """The point of the whole file, stated as one assertion.

        Exercise every other public mutator and prove the key is untouched; then rotate and prove it
        moves. If a new mutator is added that silently rotates, this fails.
        """
        original = self.store.api_key()
        self.store.set_password("pw")
        self.store.register("user", "auth-token", "aa" * 16)
        self.store.reset_account()
        self.assertEqual(self.store.api_key(), original,
                         "some path other than rotate_api_key() changed the key")
        _, new = self.store.rotate_api_key()
        self.assertNotEqual(new, original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
