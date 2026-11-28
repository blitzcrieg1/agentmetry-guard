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
carry session attribution supplied by the caller. Ingest hostnames resolve
(`http://localhost:8000` works, not just IP literals), the POST runs on a
background worker with a bounded queue so a stalled recorder never delays a
tunnel, and undelivered posts are retried twice before they stay file-only.
The JSONL file is the authority.

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
{"deny": ["blocked.invalid"], "allow": ["api.example.com"], "events_file": "guard-events.jsonl", "ssrf_guard": "metadata", "writable_paths": ["~/.cache"], "writable_defaults": true}
```

The default policy is `<data dir>/guard.json`. `AGENTMETRY_GUARD_CONFIG` names
an explicit policy file. A missing default file is optional. A missing explicit
file, an unreadable present file, or invalid policy prevents startup. Guard
checks the file even when the command line supplies both lists. Keep the policy
and launch settings under operator control if enforcement depends on them.

### Egress guardrails

The lists above match the destination name the client asked for. After DNS
resolution, Guard also checks the address it is about to dial, so alternate
IP encodings and DNS rebinding cannot reach an endpoint the lists never
named. `ssrf_guard` (or `AGENTMETRY_GUARD_SSRF`) selects the mode:

- `metadata` (default): refuse link-local destinations, which is where cloud
  metadata services live (AWS/GCP/Azure IMDS at 169.254.169.254, ECS at
  169.254.170.2), plus the AWS IPv6 IMDS endpoint.
- `strict`: also refuse loopback, RFC1918 private ranges, IPv6 ULA and the
  unspecified address. This also blocks a wrapped child from reaching the
  recorder's own ingest port through the proxy.
- `off`: no address checks; the lists are the whole policy.

Denials under a guardrail are `denied` with `tool.arguments.policy:
"ssrf-guard"`, and a guardrail cannot be voted away by allowlisting a name.
Loopback and private ranges stay reachable in the default mode because local
tools (a local LLM, an internal API) legitimately use them, and `NO_PROXY`
already sends localhost traffic direct, around the proxy. A client that
ignores the proxy environment bypasses all of this; network isolation is the
wrapper's job, not the proxy's.

### Writable workspace (Linux Bubblewrap)

The Bubblewrap wrapper binds the host root read-only, which makes every
wrapped server or build fail with EROFS the moment it writes a file or cache.
By default (`writable_defaults: true`) Guard binds the current directory
writable and mounts a fresh `/tmp`. `writable_paths` lists extra writable
paths, with `~` expanded against the home directory. Credential directories
are overlaid after the writable binds, so hiding always wins: a writable path
inside a hidden credential directory is skipped with a warning instead of
silently re-exposing it. Paths that do not exist are skipped with a warning;
set `writable_defaults: false` to keep the root fully read-only.

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
