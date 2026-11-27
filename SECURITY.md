# Security Policy

## Status: Experimental

Guard is an experimental visibility layer. The loopback proxy observes
cooperating clients. Windows uses proxy environment variables only. Seatbelt
and Bubblewrap can hide selected home credential paths while leaving the
network stack available. The requested launch mode is not evidence that a
real agent session was contained. See [the README](README.md) for coverage.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's [private vulnerability reporting](https://github.com/blitzcrieg1/agentmetry-guard/security/advisories/new)
(Security → Report a vulnerability).

Please include: what you found, how to reproduce it, and what an attacker
gains. We aim to acknowledge within 7 days. As an unfunded experimental
project we cannot offer a bounty.

## Scope

In scope:

- A client that follows proxy configuration reaching an unexpected destination.
- Sandbox escapes: a wrapped child reading `~/.ssh`, `~/.aws`, `~/.gnupg`,
  `~/.kube`, `~/.docker`, `~/.azure`, `~/.gcloud`, `~/.netrc`,
  `~/.git-credentials`, `~/.npmrc`, `~/.pypirc` under Seatbelt or Bubblewrap.
- Anything in the event path that leaks a secret into the JSONL file or the
  ingest POST.
- An unintended destination being permitted by an active proxy policy.
- Startup proceeding with an invalid or unreadable configured policy.

Out of scope:

- Direct connections by clients that ignore the proxy environment.
- DNS traffic outside the proxy.
