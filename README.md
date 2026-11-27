# agentmetry-guard

User-space egress visibility sidecar for [Agentmetry](https://github.com/blitzcrieg1/agentmetry).
It closes the child-process blind spot: when an AI agent runs a shell tool call
(`./script.sh`, `python run.py`), child processes can open network connections
that never pass through the agent's MCP/hook boundary. `agentmetry-guard`
wraps the command, routes its traffic through a loopback proxy, and records
every destination as a `network_egress` event in the same Agentmetry trail,
joined to the tool call by `correlation_id`.

Zero dependencies, pure `std`. The binary runs inside every wrapped command,
so startup cost (~1 ms) and supply-chain surface are part of the product.

## What it is, and is not

- **Visibility, not containment.** The proxy is cooperative: a client that
  honours `HTTP_PROXY`/`HTTPS_PROXY` is logged (and optionally blocked by a
  denylist); one that bypasses it is not seen. DNS queries made without the
  proxy are invisible, and a `CONNECT` tunnel reveals the host, not the path.
- **Containment comes from the OS-native user-space sandbox**, not from a
  kernel extension: on macOS the wrap runs under a generated Seatbelt profile
  that denies reads to `~/.ssh`, `~/.aws`, `~/.gnupg`, etc.; on Linux under
  Bubblewrap with a tmpfs (or `/dev/null`) over those paths. On Windows or
  when neither tool exists, it falls back to proxy env injection only, and
  says so on stderr (`sandbox mode: env-only`).
- No root, no sudo, no eBPF, no kernel module.

## Usage

```
agentmetry-guard wrap [--events-file PATH] [--deny host,...] -- <command...>
agentmetry-guard proxy [--events-file PATH] [--deny host,...]
```

`wrap` starts the proxy on an ephemeral `127.0.0.1` port, injects
`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` (and lowercase) plus
`NO_PROXY=localhost,127.0.0.1,::1` into the child, runs the command inside
the sandbox wrapper when available, and exits with the child's exit code.

`proxy` runs standalone and prints the chosen port on stdout.

## Events

Every intercepted request becomes one JSONL event, appended to
`--events-file` (default `<data dir>/guard-events.jsonl`) and POSTed to
Agentmetry's local ingest when a token is available:

```json
{"source_app":"agentmetry","adapter":"guard","event_type":"network_egress",
 "correlation_id":"<AGENTMETRY_CORRELATION_ID>","session_id":"<AGENTMETRY_SESSION_ID>",
 "timestamp_utc":"...","outcome":"success|denied",
 "tool":{"qualified":"guard.egress","server":"guard",
         "command":"CONNECT example.com:443",
         "arguments":{"scheme":"https","method":"CONNECT","host":"example.com","port":443,"path":""}}}
```

Configuration is read from the same environment the Agentmetry hook uses:
`AGENTMETRY_DATA_DIR`, `AGENTMETRY_AUDIT_INGEST_URL` (default
`http://127.0.0.1:8000`), `AGENTMETRY_API_KEY` or `<data dir>/ingest-token` /
`api-token`, `AGENTMETRY_CORRELATION_ID`, `AGENTMETRY_SESSION_ID`.

On ingest these become canonical events with `action.type = network_egress`
and `source.adapter = "guard"`. They join the agent session by
`correlation_id` in the trail, the dashboard session view and the SIEM
forwarders, but they are not `tool_called`, so the tool-sequence detection
rules do not count them.

## Denylist

`--deny evil.example.com,10.0.0.0/8`-style entries (host or domain suffix,
comma-separated) make the proxy answer `403` to matching `CONNECT` or HTTP
requests and record the attempt with `outcome: "denied"`.

## Status

Phase 1 spike: loopback proxy, `wrap` with Seatbelt/Bubblewrap fallback,
JSONL + HTTP ingest emission. Not yet wired into the Python hook layer as an
automatic wrapper of shell tool calls; that integration is the next step.

License: Apache-2.0.
