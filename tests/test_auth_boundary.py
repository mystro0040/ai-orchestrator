"""Zero-dependency tests for the Anthropic credential boundary.
Run: python3 tests/test_auth_boundary.py

The boundary decides whether this host may resolve a consumer SUBSCRIPTION or an API KEY, and
refuses to run when the host's actual credential state contradicts what it declared. Getting this
wrong in the permissive direction is the expensive failure — a subscription resolving on a rented
server, or an API key quietly metering work a flat-rate plan already covers.

So these tests are written around one question: WHAT DOES IT DO WHEN SOMETHING IS WRONG OR ABSENT?
A check that passes on good input and also passes on missing input is not a check. Most of what
follows is therefore negative cases, and several assert on *refusal* rather than on success.

No test touches a real HOME, a real /etc, or the real environment — every lookup is injected.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator import auth_boundary as ab  # noqa: E402


# ── helpers ───────────────────────────────────────────────────────────────────
def fake_home(oauth_file=False, transcripts=False):
    """Build a throwaway HOME with the requested subscription artefacts present."""
    h = tempfile.mkdtemp()
    os.makedirs(os.path.join(h, ".claude"), exist_ok=True)
    if oauth_file:
        with open(os.path.join(h, ".claude", ".credentials.json"), "w") as fh:
            fh.write("{}")
    if transcripts:
        os.makedirs(os.path.join(h, ".claude", "projects"), exist_ok=True)
    return h


def fake_pkg(with_api_runtime=False):
    """Build a throwaway package dir, optionally containing the cloud-only api_runtime package."""
    d = tempfile.mkdtemp()
    if with_api_runtime:
        rt = os.path.join(d, "api_runtime")
        os.makedirs(rt, exist_ok=True)
        with open(os.path.join(rt, "__init__.py"), "w") as fh:
            fh.write("")
    return d


def mode_file(value, filename="auth_mode"):
    """Write a declaration file and return a MODE_FILES-style tuple pointing at it."""
    d = tempfile.mkdtemp()
    p = os.path.join(d, filename)
    with open(p, "w") as fh:
        fh.write(value)
    return (p,), p


class Exited(Exception):
    """Raised by the injected exit_fn so a test can assert refusal without killing the runner."""
    def __init__(self, code):
        super().__init__(f"exit({code})")
        self.code = code


def boom(code):
    raise Exited(code)


# ── the declaration: absent and malformed must both be errors ─────────────────
class TestDeclaredMode(unittest.TestCase):
    def test_reads_a_valid_declaration(self):
        files, _ = mode_file("api")
        self.assertEqual(ab.read_declared_mode(files), "api")

    def test_whitespace_and_case_are_tolerated(self):
        files, _ = mode_file("  SUBSCRIPTION \n")
        self.assertEqual(ab.read_declared_mode(files), "subscription")

    def test_missing_declaration_is_an_error_not_a_default(self):
        """The single most important test in this file.

        If a host that never declared itself were allowed to proceed, every other rule here would be
        optional in practice — you would simply never write the file.
        """
        with self.assertRaises(ab.BoundaryError) as cm:
            ab.read_declared_mode(("/nonexistent/a", "/nonexistent/b"))
        self.assertIn("no auth-mode declaration", str(cm.exception))

    def test_unrecognised_value_is_an_error(self):
        files, _ = mode_file("prod")
        with self.assertRaises(ab.BoundaryError):
            ab.read_declared_mode(files)

    def test_empty_file_is_an_error(self):
        files, _ = mode_file("")
        with self.assertRaises(ab.BoundaryError):
            ab.read_declared_mode(files)

    def test_a_near_miss_value_is_still_rejected(self):
        """'apikey' is not 'api'. Close is not a match — refuse rather than interpret."""
        files, _ = mode_file("apikey")
        with self.assertRaises(ab.BoundaryError):
            ab.read_declared_mode(files)

    def test_system_path_wins_over_user_path(self):
        """On a server /etc is root-owned, so an unprivileged service user must not be able to
        downgrade its own boundary by writing a file in its home directory."""
        sysd = tempfile.mkdtemp(); userd = tempfile.mkdtemp()
        sysp = os.path.join(sysd, "auth_mode"); userp = os.path.join(userd, "auth_mode")
        with open(sysp, "w") as fh:
            fh.write("api")
        with open(userp, "w") as fh:
            fh.write("subscription")
        self.assertEqual(ab.read_declared_mode((sysp, userp)), "api")

    def test_falls_through_to_user_path_when_system_absent(self):
        userd = tempfile.mkdtemp()
        userp = os.path.join(userd, "auth_mode")
        with open(userp, "w") as fh:
            fh.write("subscription")
        self.assertEqual(ab.read_declared_mode(("/nonexistent/auth_mode", userp)), "subscription")


# ── api_runtime presence: the physical guarantee ──────────────────────────────
class TestApiRuntimeDetection(unittest.TestCase):
    def test_absent_when_not_shipped(self):
        self.assertFalse(ab.api_runtime_installed(fake_pkg(False)))

    def test_present_when_shipped(self):
        self.assertTrue(ab.api_runtime_installed(fake_pkg(True)))

    def test_a_bare_directory_without_init_does_not_count(self):
        """An empty leftover directory is not an installed package. Requiring __init__.py stops a
        stale mkdir from being read as 'the capability is here'."""
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "api_runtime"), exist_ok=True)
        self.assertFalse(ab.api_runtime_installed(d))


# ── evaluate(): the pure decision table ───────────────────────────────────────
class TestEvaluateSubscriptionHost(unittest.TestCase):
    BASE = {"api_key": False, "auth_token": False, "api_runtime": False,
            "oauth_token_env": False, "oauth_cred_file": True, "transcripts": True}

    def test_clean_subscription_host_passes(self):
        """A normal personal machine: OAuth file and transcripts present, no key, no api_runtime."""
        self.assertEqual(ab.evaluate("subscription", dict(self.BASE)), [])

    def test_api_key_present_is_a_violation(self):
        s = dict(self.BASE, api_key=True)
        out = ab.evaluate("subscription", s)
        self.assertEqual(len(out), 1)
        self.assertIn("ANTHROPIC_API_KEY is set", out[0])

    def test_api_runtime_installed_is_a_violation(self):
        s = dict(self.BASE, api_runtime=True)
        out = ab.evaluate("subscription", s)
        self.assertTrue(any("api_runtime" in x for x in out))

    def test_both_wrong_reports_both(self):
        s = dict(self.BASE, api_key=True, api_runtime=True)
        self.assertEqual(len(ab.evaluate("subscription", s)), 2)

    def test_oauth_artifacts_are_NOT_violations_here(self):
        """The subscription is what this host is FOR. Flagging its own credential would train the
        operator to ignore the output, which is how a check stops working."""
        s = dict(self.BASE, oauth_cred_file=True, oauth_token_env=True, transcripts=True)
        self.assertEqual(ab.evaluate("subscription", s), [])


class TestEvaluateApiHost(unittest.TestCase):
    BASE = {"api_key": True, "auth_token": False, "api_runtime": True,
            "oauth_token_env": False, "oauth_cred_file": False, "transcripts": False}

    def test_clean_api_host_passes(self):
        self.assertEqual(ab.evaluate("api", dict(self.BASE)), [])

    def test_missing_key_is_a_violation(self):
        out = ab.evaluate("api", dict(self.BASE, api_key=False))
        self.assertTrue(any("not set" in x for x in out))

    def test_missing_api_runtime_is_a_violation(self):
        out = ab.evaluate("api", dict(self.BASE, api_runtime=False))
        self.assertTrue(any("api_runtime package is missing" in x for x in out))

    def test_oauth_credential_file_is_a_violation(self):
        """The headline case: a personal subscription reachable on a rented server."""
        out = ab.evaluate("api", dict(self.BASE, oauth_cred_file=True))
        self.assertTrue(any("credentials.json" in x for x in out))

    def test_oauth_env_token_is_a_violation(self):
        out = ab.evaluate("api", dict(self.BASE, oauth_token_env=True))
        self.assertTrue(any("CLAUDE_CODE_OAUTH_TOKEN" in x for x in out))

    def test_transcripts_are_a_violation(self):
        """Transcripts do not arrive alone. Their presence means a home directory was copied here."""
        out = ab.evaluate("api", dict(self.BASE, transcripts=True))
        self.assertTrue(any("projects" in x for x in out))

    def test_a_wholesale_home_dir_copy_reports_every_signal(self):
        """The realistic bad deployment: someone rsync'd ~ to the server. Report all of it, because
        a single line would understate what happened."""
        out = ab.evaluate("api", dict(self.BASE, oauth_cred_file=True,
                                      oauth_token_env=True, transcripts=True))
        self.assertEqual(len(out), 3)


class TestEvaluateBothModes(unittest.TestCase):
    def test_key_and_auth_token_together_is_always_a_violation(self):
        for mode, base in (("api", {"api_key": True, "api_runtime": True}),
                           ("subscription", {"api_key": False, "api_runtime": False})):
            s = {"api_key": True, "auth_token": True, "api_runtime": base["api_runtime"],
                 "oauth_token_env": False, "oauth_cred_file": False, "transcripts": False}
            out = ab.evaluate(mode, s)
            self.assertTrue(any("both set" in x for x in out), f"mode={mode}")

    def test_illegal_mode_never_returns_clean(self):
        for bad in ("", "prod", "vps", "API", None, "default"):
            out = ab.evaluate(bad, {"api_key": True, "api_runtime": True, "auth_token": False,
                                    "oauth_token_env": False, "oauth_cred_file": False,
                                    "transcripts": False})
            self.assertTrue(out, f"{bad!r} evaluated clean — an unknown mode must never pass")

    def test_empty_signals_dict_does_not_pass_in_api_mode(self):
        """Defensive: if signal collection ever returned nothing, the answer must be 'refuse', not
        'nothing was wrong'. Absence of evidence must not read as evidence of absence."""
        self.assertTrue(ab.evaluate("api", {}))


# ── assert_boundary(): does it actually stop? ─────────────────────────────────
class TestAssertBoundary(unittest.TestCase):
    def test_passes_on_a_clean_subscription_host(self):
        files, _ = mode_file("subscription")
        mode = ab.assert_boundary("test", mode_files=files, env={},
                                  home=fake_home(oauth_file=True, transcripts=True),
                                  pkg_dir=fake_pkg(False), exit_fn=boom)
        self.assertEqual(mode, "subscription")

    def test_passes_on_a_clean_api_host(self):
        files, _ = mode_file("api")
        mode = ab.assert_boundary("test", mode_files=files,
                                  env={"ANTHROPIC_API_KEY": "sk-ant-x"},
                                  home=fake_home(), pkg_dir=fake_pkg(True), exit_fn=boom)
        self.assertEqual(mode, "api")

    def test_exits_when_no_declaration_exists(self):
        with self.assertRaises(Exited) as cm:
            ab.assert_boundary("test", mode_files=("/nonexistent/x",), env={},
                               home=fake_home(), pkg_dir=fake_pkg(False), exit_fn=boom)
        self.assertEqual(cm.exception.code, 1)

    def test_exits_when_a_key_is_set_on_a_subscription_host(self):
        files, _ = mode_file("subscription")
        with self.assertRaises(Exited):
            ab.assert_boundary("test", mode_files=files,
                               env={"ANTHROPIC_API_KEY": "sk-ant-x"},
                               home=fake_home(oauth_file=True), pkg_dir=fake_pkg(False), exit_fn=boom)

    def test_exits_when_a_subscription_is_reachable_on_an_api_host(self):
        """The condition the whole boundary exists for."""
        files, _ = mode_file("api")
        with self.assertRaises(Exited):
            ab.assert_boundary("test", mode_files=files,
                               env={"ANTHROPIC_API_KEY": "sk-ant-x"},
                               home=fake_home(oauth_file=True), pkg_dir=fake_pkg(True), exit_fn=boom)

    def test_exits_when_api_host_has_no_key(self):
        files, _ = mode_file("api")
        with self.assertRaises(Exited):
            ab.assert_boundary("test", mode_files=files, env={},
                               home=fake_home(), pkg_dir=fake_pkg(True), exit_fn=boom)

    def test_exits_when_api_runtime_shipped_to_a_subscription_host(self):
        files, _ = mode_file("subscription")
        with self.assertRaises(Exited):
            ab.assert_boundary("test", mode_files=files, env={},
                               home=fake_home(oauth_file=True), pkg_dir=fake_pkg(True), exit_fn=boom)


# ── describe(): the read-only reporter must never lie about a blocked host ────
class TestDescribe(unittest.TestCase):
    def test_reports_ok_on_a_clean_host(self):
        files, _ = mode_file("subscription")
        out = ab.describe(mode_files=files, env={}, home=fake_home(oauth_file=True),
                          pkg_dir=fake_pkg(False))
        self.assertIn("VERDICT : OK", out)

    def test_reports_blocked_when_violated(self):
        files, _ = mode_file("subscription")
        out = ab.describe(mode_files=files, env={"ANTHROPIC_API_KEY": "sk-ant-x"},
                          home=fake_home(oauth_file=True), pkg_dir=fake_pkg(False))
        self.assertIn("BLOCKED", out)

    def test_reports_missing_declaration_without_raising(self):
        out = ab.describe(mode_files=("/nonexistent/x",), env={}, home=fake_home(),
                          pkg_dir=fake_pkg(False))
        self.assertIn("(NONE)", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
