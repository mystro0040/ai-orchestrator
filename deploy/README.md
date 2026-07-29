# Deployment — which files go to which host, and why it matters

Three roles, three different credential postures. What makes the separation real is **what is
physically installed**, not what a config file says.

| Role | Where it runs | Anthropic credential | Gets `api_runtime`? |
|---|---|---|---|
| **State** — blackboard files, engagement artifacts | the shared bucket | none | n/a |
| **Control plane** — engine + web console | Linode *or* Railway *or* local | **none. It never calls Claude.** | **no** |
| **Agent runtime** — the sessions doing the work | the agent host only | **API key, and only here** | **yes** |

## The one rule

> `orchestrator/api_runtime/` must exist on the agent host and **nowhere else.**

It is stored in this repo at `deploy/api_runtime/` and copied into place by
`deploy/install_agent_host.sh`. It is gitignored at its installed path so it cannot be committed by
accident, and `tests/test_api_runtime.py` fails if it ever appears in the source tree.

Why go to that trouble instead of a flag: a rule enforced by a check can be defeated by editing the
check. A rule enforced by the **absence of the capability** cannot. On a personal machine you can
export `ANTHROPIC_API_KEY` and nothing will consume it, because the consumer was never shipped.

## Host declaration

Every host declares itself in a file, read in this order — first hit wins:

1. `/etc/ai-orchestrator/auth_mode` — root-owned, so a service user cannot downgrade its own boundary
2. `~/.config/ai-orchestrator/auth_mode`

Legal values: `subscription` or `api`. **There is no default.** A host that has not declared itself
does not run — `assert_boundary()` exits before any work. Deliberately not overridable by an
environment variable; an override on this particular control would be a bypass, not a convenience.

Check any host with:

    python3 -m orchestrator.cli auth-status

## Installing an agent host

On the server, as root:

    bash deploy/install_agent_host.sh

It refuses if a subscription credential is reachable, declares `auth_mode=api`, installs
`api_runtime`, prompts for the API key with **hidden input** (never an argument, never echoed, never
in shell history), writes it root-600 to `/etc/ai-orchestrator/anthropic.env`, and verifies with
`auth-status` — failing loudly rather than leaving a half-configured host.

The key is typed directly into the machine that will use it. Anything that *transports* it — scp, a
paste into a chat, a file on a laptop — creates a second copy that then has to be tracked and
destroyed. One copy is easier to reason about than two.

## Systemd

The unit's environment should contain the key and **nothing else auth-related**:

    [Service]
    EnvironmentFile=/etc/ai-orchestrator/anthropic.env
    ExecStart=/usr/bin/python3 -m orchestrator.cli orchestrate /etc/ai-orchestrator/config.yaml

`systemd-creds` is the stronger option if you want the stored blob to be useless when copied off the
box — worth doing once the host is otherwise stable.

## Moving the control plane (Linode ↔ Railway)

The control plane holds no Anthropic credential, so relocating it is a deploy, not a security event.
What it does need is somewhere to keep state.

**Open question, not yet solved — read before attempting a split deployment.** The blackboard is
local files plus an S3 sync. That is not shared storage: S3 has no locking and is eventually
consistent, so two writers on different hosts will lose writes. A Railway control plane driving
agents on the Linode therefore needs one of:

- the control plane calling the Linode over an authenticated HTTP API, so the Linode remains the
  single writer, **or**
- the blackboard behind a store interface with compare-and-swap semantics.

Until one of those exists, run the control plane and the agents on the **same host**, and treat the
existing "only one agent runtime per engagement at a time" rule as load-bearing rather than advisory.
