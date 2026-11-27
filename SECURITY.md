# Security Policy

## Status: Experimental

agentmetry-guard is a phase-1 spike. The loopback proxy and the `wrap`
subcommand are smoke-tested in CI on Linux, macOS and Windows, but the
Seatbelt (macOS) and Bubblewrap (Linux) sandbox paths have not yet been
exercised against a live agent session, and there are no release binaries.
Do not rely on it as a containment boundary yet. It is a visibility layer;
see the README for what the proxy can and cannot see.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's [private vulnerability reporting](https://github.com/blitzcrieg1/agentmetry-guard/security/advisories/new)
(Security → Report a vulnerability).

Please include: what you found, how to reproduce it, and what an attacker
gains. We aim to acknowledge within 7 days. As an unfunded experimental
project we cannot offer a bounty.

## Scope

In scope:

- Proxy bypasses that are not documented as limitations in the README
  (a cooperative-client bypass is a known limitation, not a bug).
- Sandbox escapes: a wrapped child reading `~/.ssh`, `~/.aws`, `~/.gnupg`,
  `~/.kube`, `~/.docker`, `~/.azure`, `~/.gcloud`, `~/.netrc`,
  `~/.git-credentials`, `~/.npmrc`, `~/.pypirc` under Seatbelt or Bubblewrap.
- Anything in the event path that leaks a secret into the JSONL file or the
  ingest POST.
- Denylist evasion (e.g. a `CONNECT` authority form that dodges suffix
  matching).

Out of scope:

- A non-cooperative client ignoring the proxy env vars and connecting
  directly. That is the documented reason the sandbox layer exists.
- DNS exfiltration. The proxy never sees DNS unless the client is configured
  to route it through the proxy.
