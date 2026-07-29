"""Tests for the cloud-only api_runtime and the absence guarantee it depends on.
Run: python3 tests/test_api_runtime.py

Two separate jobs here, and the first is the unusual one:

  1. REPO HYGIENE — assert that `orchestrator/api_runtime/` does NOT exist in the source tree.
     The security property is "a subscription host has no code that can consume an API key". That
     holds only while the package stays in `deploy/` and is copied into place by the VPS installer.
     The day somebody moves it under `orchestrator/` for convenience, the guarantee silently becomes
     a promise. This test is what notices.

  2. LAUNCHER BEHAVIOUR — the launcher must refuse rather than degrade. Every check below asserts a
     REFUSAL, because the failure that costs something is launching an agent with the scope wall
     unproven, not failing to launch one.

The launcher is imported from its staged location, since (by 1) it is deliberately not installed.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

# import the staged launcher directly — it is intentionally NOT on the package path
_spec = importlib.util.spec_from_file_location(
    "staged_launcher", os.path.join(REPO, "deploy", "api_runtime", "launcher.py"))
launcher = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(launcher)


def project_with_hook(matcher="Bash", command="python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/enforce_scope.py",
                      settings_name="settings.json", raw=None):
    """Build a throwaway project dir with a .claude/settings.json describing a PreToolUse hook."""
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, ".claude"), exist_ok=True)
    body = raw if raw is not None else json.dumps(
        {"hooks": {"PreToolUse": [{"matcher": matcher,
                                   "hooks": [{"type": "command", "command": command}]}]}})
    with open(os.path.join(d, ".claude", settings_name), "w") as fh:
        fh.write(body)
    return d


class TestAbsenceGuarantee(unittest.TestCase):
    def test_api_runtime_is_NOT_installed_in_the_package(self):
        """The whole security property, as one assertion.

        If this fails, the cloud-only runtime has been committed into the importable package, and
        every machine with a checkout now carries the ability to spend against an API key. Move it
        back to deploy/ rather than deleting this test.
        """
        installed = os.path.join(REPO, "orchestrator", "api_runtime")
        self.assertFalse(
            os.path.exists(installed),
            "orchestrator/api_runtime exists in the source tree. It must live in deploy/ and be "
            "installed only by deploy/install_agent_host.sh on the agent host.")

    def test_it_is_staged_where_the_installer_expects(self):
        staged = os.path.join(REPO, "deploy", "api_runtime")
        self.assertTrue(os.path.isfile(os.path.join(staged, "__init__.py")))
        self.assertTrue(os.path.isfile(os.path.join(staged, "launcher.py")))

    def test_auth_boundary_agrees_this_host_has_no_runtime(self):
        """Cross-check: the boundary's own detector must see what the filesystem sees."""
        from orchestrator import auth_boundary as ab
        self.assertFalse(ab.api_runtime_installed(os.path.join(REPO, "orchestrator")))


class TestScopeHookDetection(unittest.TestCase):
    def test_detects_a_correctly_registered_hook(self):
        ok, reason = launcher.scope_hook_registered(project_with_hook())
        self.assertTrue(ok, reason)

    def test_missing_settings_is_not_ok(self):
        ok, reason = launcher.scope_hook_registered(tempfile.mkdtemp())
        self.assertFalse(ok)
        self.assertIn("no .claude/settings.json", reason)

    def test_hook_registered_for_the_wrong_tool_is_not_ok(self):
        """A hook on Read does not gate Bash. Registration alone is not coverage."""
        ok, _ = launcher.scope_hook_registered(project_with_hook(matcher="Read"))
        self.assertFalse(ok)

    def test_a_different_hook_on_the_right_matcher_is_not_ok(self):
        """ram_guard is registered on Bash too. Finding *a* hook is not finding *the* hook."""
        ok, _ = launcher.scope_hook_registered(
            project_with_hook(command="python3 .claude/hooks/ram_guard.py"))
        self.assertFalse(ok)

    def test_unparseable_settings_is_not_ok(self):
        """Malformed JSON must read as 'cannot confirm', never as 'fine'."""
        ok, reason = launcher.scope_hook_registered(project_with_hook(raw="{ this is not json"))
        self.assertFalse(ok)
        self.assertIn("could not be parsed", reason)

    def test_settings_local_also_counts(self):
        ok, _ = launcher.scope_hook_registered(project_with_hook(settings_name="settings.local.json"))
        self.assertTrue(ok)

    def test_the_file_existing_on_disk_does_not_substitute_for_registration(self):
        """The point of checking registration rather than the filename.

        Put a real enforce_scope.py on disk, register nothing, and the answer must still be no.
        """
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, ".claude", "hooks"), exist_ok=True)
        with open(os.path.join(d, ".claude", "hooks", "enforce_scope.py"), "w") as fh:
            fh.write("# a real-looking hook that nothing invokes\n")
        with open(os.path.join(d, ".claude", "settings.json"), "w") as fh:
            fh.write("{}")
        ok, _ = launcher.scope_hook_registered(d)
        self.assertFalse(ok, "an unregistered hook file was read as an active guardrail")


class TestPreflight(unittest.TestCase):
    def _env(self, **over):
        e = {"ANTHROPIC_API_KEY": "sk-ant-x", "HOME": tempfile.mkdtemp()}
        e.update(over)
        return e

    def test_missing_key_blocks(self):
        p = launcher.preflight(project_with_hook(), self._env(ANTHROPIC_API_KEY=""))
        self.assertTrue(any("ANTHROPIC_API_KEY is not set" in x for x in p))

    def test_oauth_token_blocks(self):
        p = launcher.preflight(project_with_hook(), self._env(CLAUDE_CODE_OAUTH_TOKEN="tok"))
        self.assertTrue(any("CLAUDE_CODE_OAUTH_TOKEN" in x for x in p))

    def test_oauth_credential_file_blocks(self):
        home = tempfile.mkdtemp()
        os.makedirs(os.path.join(home, ".claude"), exist_ok=True)
        with open(os.path.join(home, ".claude", ".credentials.json"), "w") as fh:
            fh.write("{}")
        p = launcher.preflight(project_with_hook(), self._env(HOME=home))
        self.assertTrue(any("credentials.json" in x for x in p))

    def test_unregistered_scope_wall_blocks(self):
        p = launcher.preflight(tempfile.mkdtemp(), self._env())
        self.assertTrue(any("scope wall is not provably active" in x for x in p))

    def test_nonexistent_project_dir_blocks(self):
        p = launcher.preflight("/nonexistent/project", self._env())
        self.assertTrue(any("does not exist" in x for x in p))


class TestLaunchRefusal(unittest.TestCase):
    def test_launch_raises_when_the_scope_wall_is_unproven(self):
        """The single most important refusal: no wall, no agent."""
        calls = []
        with self.assertRaises(launcher.AgentLaunchError) as cm:
            launcher.launch_agent("tester", "recon", tempfile.mkdtemp(),
                                  env={"ANTHROPIC_API_KEY": "sk-ant-x", "HOME": tempfile.mkdtemp()},
                                  runner=lambda *a, **k: calls.append(a))
        self.assertIn("scope wall", str(cm.exception))
        self.assertEqual(calls, [], "the runner was invoked despite the refusal")

    def test_launch_raises_when_no_key_is_present(self):
        calls = []
        with self.assertRaises(launcher.AgentLaunchError):
            launcher.launch_agent("tester", "recon", project_with_hook(),
                                  env={"HOME": tempfile.mkdtemp()},
                                  runner=lambda *a, **k: calls.append(a))
        self.assertEqual(calls, [])

    def test_refusal_message_lists_every_problem_not_just_the_first(self):
        """An operator fixing one thing at a time, three runs in a row, is a worse outcome than
        being told all three at once."""
        with self.assertRaises(launcher.AgentLaunchError) as cm:
            launcher.launch_agent("tester", "recon", "/nonexistent/project",
                                  env={"HOME": tempfile.mkdtemp()},
                                  runner=lambda *a, **k: None)
        msg = str(cm.exception)
        self.assertIn("ANTHROPIC_API_KEY", msg)
        self.assertIn("does not exist", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
