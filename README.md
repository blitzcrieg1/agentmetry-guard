# agentmetry-guard

**Experimental.** Guard records destinations observed by a cooperative local
HTTP proxy. Its optional OS wrappers hide selected home credential paths.
Read [SECURITY.md](SECURITY.md) before depending on it.

Guard is a zero-dependency Rust sidecar for
[Agentmetry](https://github.com/blitzcrieg1/agentmetry). It adds visibility into
child-process requests that reach the proxy and can correlate them to an agent
session with `correlation_id`. Direct sockets and DNS outside the proxy remain
outside its view. Windows uses proxy environment variables only.

## Install

See [Releases](https://github.com/blitzcrieg1/agentmetry-guard/releases) for
available binaries, or build from source.

```sh
cargo install --git https://github.com/blitzcrieg1/agentmetry-guard
```

## Usage

```sh
agentmetry-guard wrap [--events-file PATH] [--deny hosts] [--allow hosts] -- <command...>
agentmetry-guard proxy [--events-file PATH] [--deny hosts] [--allow hosts]
```

`proxy` listens on an ephemeral loopback port and prints it on stdout.
`wrap` sets the child's `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and
lowercase equivalents. `NO_PROXY` excludes loopback by default. The child
exit code is returned to the caller.

The requested launch mode is printed on stderr. On macOS, Guard can use
Seatbelt through `/usr/bin/sandbox-exec`. On Linux, it can use Bubblewrap
from a standard system path. If the selected launcher fails, Guard does not
retry the command outside it. When neither launcher is available, Guard
reports `env-only`. A mode label describes the requested launcher. Verify
actual credential isolation separately before relying on it.

Agentmetry can opt into wrapping configured stdio MCP servers with Guard.
That integration applies to those configured processes. Other tool paths
still depend on how the application launches them.

## Events

Guard writes `network_egress` observations with the method, destination host
and port. It omits URL user information, paths, query strings, headers, and
bodies from destination evidence. Hostnames are visible, so treat them as
potentially sensitive operational metadata.

- `success` with `tool.arguments.connection_established: true` records an
  upstream connection. It does not establish how much data was transferred.
- `denied` with `connection_established: false` records a proxy policy refusal.
  `tool.arguments.policy` identifies the denylist or allowlist.
- `error` with `connection_established: false` records an unsuccessful proxy
  attempt. It is separate from a policy refusal.

The default local JSONL file is `<data dir>/guard-events.jsonl`.
With a configured token, Guard can also post to Agentmetry ingest using
`AGENTMETRY_AUDIT_INGEST_URL` or `AGENTMETRY_URL`.
`AGENTMETRY_API_KEY` takes precedence over `ingest-token` and `api-token` in
the data directory. `AGENTMETRY_CORRELATION_ID` and `AGENTMETRY_SESSION_ID`
carry session attribution supplied by the caller.

On ingest, these observations have `action.type: network_egress` and
`source.adapter: guard`. They are separate from `tool_called` events.

## Policy

Allow and deny entries are exact hosts or domain suffixes. Matching ignores
case and a final dot. Use unbracketed IPv6 addresses in policy entries. A
nonempty allowlist permits only matching destinations. The denylist wins
when both lists match.

Each list resolves in this order: command-line flag, environment
(`AGENTMETRY_GUARD_DENY` or `AGENTMETRY_GUARD_ALLOW`), then the policy file.
`--events-file` and `AGENTMETRY_GUARD_EVENTS_FILE` override the policy path
for event output.

```json
{"deny": ["blocked.invalid"], "allow": ["api.example.com"], "events_file": "guard-events.jsonl"}
```

The default policy is `<data dir>/guard.json`. `AGENTMETRY_GUARD_CONFIG` names
an explicit policy file. A missing default file is optional. A missing explicit
file, an unreadable present file, or invalid policy prevents startup. Guard
checks the file even when the command line supplies both lists. Keep the policy
and launch settings under operator control if enforcement depends on them.

## Verification

The smoke script uses test endpoints on ephemeral loopback ports and a
temporary profile. CI and release builds call it to check valid and invalid
policy startup, successful proxy requests, policy refusals, unestablished
connections, and destination-only evidence. Its Windows check also exercises
environment injection and child exit-code propagation. These fixtures
exercise proxy behavior. OS sandbox protection in a real agent session
requires separate validation.

```sh
cargo build --offline --locked --release
bash scripts/smoke.sh ./target/release/agentmetry-guard
```

License: Apache-2.0.
