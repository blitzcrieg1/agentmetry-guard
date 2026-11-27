#!/usr/bin/env bash
# Test the built binary with synthetic traffic on ephemeral loopback sockets.
set -euo pipefail

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) python=python ;;
  *) python=python3 ;;
esac
if [ "$#" -eq 0 ]; then
  set -- ./target/release/agentmetry-guard
fi

"$python" - "$1" <<'PY'
import contextlib
import http.client
import http.server
import json
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def proxy(binary, env, cwd, *args):
    with subprocess.Popen(
        [str(binary), "proxy", *args],
        cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) as process:
        try:
            ready = queue.Queue()
            threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
            line = ready.get(timeout=10).strip()
            assert line.isdigit(), "Guard did not publish its proxy port"
            yield int(line)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def get(port, target):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        connection.request("GET", target, headers={"Connection": "close"})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def connect(port, target, verify_tunnel=False):
    with socket.create_connection(("127.0.0.1", port), timeout=8) as connection:
        connection.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
        with connection.makefile("rb") as stream:
            status = int(stream.readline().split()[1])
            if verify_tunnel and status == 200:
                for line in stream:
                    if line == b"\r\n":
                        break
                connection.sendall(b"GET /private-smoke-tunnel HTTP/1.0\r\n\r\n")
                connection.shutdown(socket.SHUT_WR)
                reply = stream.read()
                assert reply.startswith(b"HTTP/1.0 200 ") and reply.endswith(b"ok")
            return status


def events_at_least(path, count):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            if len(events) >= count:
                return events
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(0.05)
    raise AssertionError("Guard did not write all expected events")


def require_policy_error(binary, root, env, expected):
    result = subprocess.run(
        [str(binary), "wrap", "--deny", "blocked.invalid", "--allow", "127.0.0.1", "--",
         sys.executable, "-c", "print('unexpected-child-start')"],
        cwd=root, env=env, capture_output=True, text=True, timeout=8,
    )
    assert result.returncode != 0 and expected in result.stderr, "Expected a policy error"
    assert not result.stdout and "private-smoke-policy-marker" not in result.stderr, (
        "Policy startup errors must precede the child and omit policy content"
    )


binary = Path(sys.argv[1]).resolve()
if os.name == "nt" and not binary.is_file():
    binary = binary.with_suffix(".exe")
assert binary.is_file(), "Guard binary not found"

with tempfile.TemporaryDirectory(prefix="agentmetry-guard-smoke-") as folder:
    root = Path(folder)
    env = {
        key: value for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC"}
    }
    env.update(
        HOME=str(root), USERPROFILE=str(root), LOCALAPPDATA=str(root), XDG_DATA_HOME=str(root),
        TMP=str(root), TEMP=str(root), PYTHONDONTWRITEBYTECODE="1",
        AGENTMETRY_DATA_DIR=str(root), AGENTMETRY_URL="http://127.0.0.1:9",
        AGENTMETRY_AUDIT_INGEST_URL="http://127.0.0.1:9",
        AGENTMETRY_CORRELATION_ID="ci-smoke", AGENTMETRY_SESSION_ID="ci-smoke",
    )

    with proxy(binary, env, root):
        pass  # The missing default config is allowed.
    require_policy_error(
        binary, root,
        {**env, "AGENTMETRY_GUARD_CONFIG": str(root / "missing.json")},
        "configured guard policy file is missing",
    )
    config = root / "guard.json"
    config.mkdir()
    require_policy_error(binary, root, env, "guard policy must be a regular file")
    config.rmdir()
    config.write_text('{"private-smoke-policy-marker": []}', encoding="utf-8")
    require_policy_error(binary, root, env, "invalid guard policy")
    config.write_text(json.dumps({"deny": ["127.0.0.2"], "allow": ["127.0.0.1"]}), encoding="utf-8")

    events_path = root / "events.jsonl"
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin, socket.socket() as closed:
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        try:
            # Reserved without listen(), so this endpoint deterministically refuses connections.
            closed.bind(("127.0.0.1", 0))
            good = f"127.0.0.1:{origin.server_port}"
            unavailable = f"127.0.0.1:{closed.getsockname()[1]}"
            with proxy(binary, env, root, "--events-file", str(events_path)) as port:
                assert get(port, f"http://{good}/private-smoke-path?private-smoke-query=1") == (200, b"ok")
                assert connect(port, good, verify_tunnel=True) == 200
                assert connect(port, "127.0.0.2:443") == 403
                assert connect(port, "127.0.0.3:443") == 403
                assert connect(port, unavailable) == 502

                events = events_at_least(events_path, 5)
                assert len(events) == 5
                by_command = {event["tool"]["command"]: event for event in events}
                expected = {
                    f"GET {good}": ("success", True, None),
                    f"CONNECT {good}": ("success", True, None),
                    "CONNECT 127.0.0.2:443": ("denied", False, "denylist"),
                    "CONNECT 127.0.0.3:443": ("denied", False, "allowlist"),
                    f"CONNECT {unavailable}": ("error", False, None),
                }
                for command, (outcome, established, policy) in expected.items():
                    event = by_command[command]
                    args = event["tool"]["arguments"]
                    assert event["event_type"] == "network_egress"
                    assert event["correlation_id"] == "ci-smoke"
                    assert event["outcome"] == outcome and args["connection_established"] is established
                    assert args.get("policy") == policy
                assert "private-smoke-" not in events_path.read_text(encoding="utf-8")
        finally:
            origin.shutdown()
            thread.join(timeout=5)

    # Exercise environment injection and exit-code propagation on Windows,
    # where an OS-native sandbox is unavailable.
    if os.name == "nt":
        result = subprocess.run(
            [str(binary), "wrap", "--", sys.executable, "-c",
             "import os, sys; assert os.environ['HTTP_PROXY'].startswith('http://127.0.0.1:'); sys.exit(23)"],
            cwd=root, env=env, capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 23 and "requested launch mode: env-only" in result.stderr

print("smoke: OK (loopback, strict policy, destination-only evidence)")
PY
