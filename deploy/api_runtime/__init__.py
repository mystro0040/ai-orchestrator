"""api_runtime — launches agents against an Anthropic API key. INSTALLED ON THE AGENT HOST ONLY.

READ THIS BEFORE MOVING THE FILE
--------------------------------
This package lives in `deploy/api_runtime/` in the repository and is copied to
`orchestrator/api_runtime/` **only by the VPS installer**. That is not an accident of packaging —
it is the entire security property:

    On a subscription host, no code capable of using an API key is present.

A credential rule enforced by a check can be defeated by editing the check. A credential rule
enforced by the *absence of the capability* cannot: you can export ANTHROPIC_API_KEY on the home
machine all day and nothing there will consume it, because the consumer was never shipped.

`auth_boundary.evaluate()` therefore treats the presence of this package on a host declared
`subscription` as a violation in its own right, independent of whether a key is set. If you find
this installed on a personal machine, something went wrong in a deploy — remove it, then work out
what copied it.

Do not "simplify" this by moving the package under `orchestrator/` and gating it with a flag. The
flag would then be the only thing standing between a laptop and metered spend, and flags are edited.
"""
from .launcher import AgentLaunchError, launch_agent, preflight

__all__ = ["launch_agent", "preflight", "AgentLaunchError"]
