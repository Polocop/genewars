"""Minimal DOSBox-X debugger MCP client used by W3-056. Accepts DOSBox-X's TCP connection."""
from __future__ import annotations
import argparse
import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

# L-DISK-GUARD: repo root (mcp_capture.py lives in tools/dosboxx_oracle/).
ROOT = Path(__file__).resolve().parents[2]


def _staging_from_conf(conf: Path) -> str | None:
    """Parse the guest C: mount dir from a DOSBox-X conf (`mount C <dir>`).
    Returns the dir (absolute) or None if not found. This is the staging dir
    the oracle_guard monitor must watch -- the exact path the guest's C: writes
    to (and where runaway c:\\ADDRESS.TXT / GW.ERR land)."""
    try:
        text = conf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = re.search(r"^\s*mount\s+C\s+(\"[^\"]+\"|\S+)", text, re.IGNORECASE | re.MULTILINE)
    if not m:
        return None
    p = m.group(1).strip().strip('"')
    return str(Path(p))


def recv_response(conn: socket.socket, request_id: int, timeout: float = 60.0) -> str:
    conn.settimeout(timeout)
    data = bytearray()
    begin = f"BEGIN {request_id} ".encode()
    end = f"END {request_id}".encode()
    started = False
    while not started or end not in data:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("DOSBox-X closed debugger MCP connection")
        data.extend(chunk)
        if not started:
            pos = data.find(begin)
            if pos >= 0:
                data = data[pos:]
                started = True
    return data.decode("utf-8", errors="replace")


def execute(conn: socket.socket, request_id: int, command: str) -> str:
    normalized = command.strip().upper()
    if normalized in {"BREAK", "STOPSTATE"}:
        verb = normalized
    else:
        verb = f"EXEC {command}"
    conn.sendall(f"REQ {request_id} {verb}\n".encode("ascii"))
    return recv_response(conn, request_id)


def wait_for_debugger_stop(conn: socket.socket, timeout: float) -> str:
    """Wait until DOSBox-X confirms the debugger is stopped before sampling registers."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        request_id = time.time_ns() & 0x7FFFFFFF
        response = execute(conn, request_id, "STOPSTATE")
        if "STOPPED" in response:
            return response
        if "RUNNING" not in response:
            raise RuntimeError(f"Unexpected STOPSTATE response: {response}")
        time.sleep(0.05)
    raise TimeoutError("Timed out waiting for a confirmed DOSBox-X debugger stop")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=58991)
    ap.add_argument("--wait-seconds", type=int, default=90)
    ap.add_argument("--output", type=Path, default=Path("evidence/dosbox_debugger_initial_capture_work3.json"))
    ap.add_argument("--exe", type=Path, help="DOSBox-X heavy-debug executable; when supplied, launch it after binding")
    ap.add_argument("--config", type=Path, default=Path("build/dosboxx_oracle/dosbox-x.debug.conf"))
    ap.add_argument("--run", action="store_true", help="send RUN after recording initial CPU/GDT/LDT state")
    ap.add_argument("--command", action="append", help="execute this debugger command; may be repeated")
    ap.add_argument("--timeout", type=float, default=60.0, help="per-command response timeout")
    ap.add_argument("--pause-after-run", type=float, default=0.0, help="seconds to let DOSBox execute after RUN before sending the next command")
    ap.add_argument("--interactive", action="store_true", help="keep the MCP connection open and read debugger commands from stdin until QUIT")
    ap.add_argument("--guard-max-file-mib", type=int, default=64)
    ap.add_argument("--guard-max-run-gib", type=float, default=1.0)
    ap.add_argument("--guard-timeout-s", type=int, default=180)
    args = ap.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.port))
    server.listen(1)
    server.settimeout(args.wait_seconds)
    child = None
    captures = []
    address = None
    def persist(process_state=None):
        args.output.parent.mkdir(parents=True, exist_ok=True)
        payload = {"peer": address[0] if address else None, "captures": captures}
        if process_state is not None:
            payload["dosbox_process"] = process_state
        args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.exe:
        guard = ROOT / "tools" / "oracle_guard.py"
        stage = _staging_from_conf(args.config)
        if not stage or not guard.is_file():
            print("Refusing oracle launch: guard or guest-C mount is unavailable.", file=sys.stderr)
            return 2
        # The guard owns DOSBox-X from process creation through watchdog exit.
        # In particular, there is no direct-launch-then-best-effort-monitor gap.
        gargs = [sys.executable, str(guard), "run", "--exe", str(args.exe.resolve()),
                 "--config", str(args.config.resolve()), "--extra=-console",
                 "--staging-dir", stage, "--host-drive", "E:",
                 "--operation", "replay-original-mcp",
                 "--max-file-mib", str(args.guard_max_file_mib),
                 "--max-run-gib", str(args.guard_max_run_gib),
                 "--host-floor-gib", "100",
                 "--timeout-s", str(args.guard_timeout_s)]
        child = subprocess.Popen(gargs, cwd=str(ROOT), stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        time.sleep(0.25)
        if child.poll() is not None:
            print("Refusing oracle capture: oracle_guard preflight failed (see evidence/oracle_runs).", file=sys.stderr)
            return 2
    try:
        conn, address = server.accept()
        with conn:
            request_base = time.time_ns() & 0x7FFFFFFF
            commands = args.command or ([] if args.interactive else ["HELP", "CPU", "GDT", "LDT", "BPLIST"])
            for offset, command in enumerate(commands, 1):
                request_id = request_base + offset
                response = execute(conn, request_id, command)
                captures.append({"id": request_id, "command": command, "response": response})
                persist()
                print(f"[{request_id} {command}]\n{response}", flush=True)
                if command.strip().upper() == "RUN" and args.pause_after_run > 0:
                    time.sleep(args.pause_after_run)
                if command.strip().upper() == "RUN":
                    stop_response = wait_for_debugger_stop(conn, args.timeout)
                    captures.append({"command": "STOPSTATE_WAIT", "response": stop_response})
                    persist()
                    print(f"[STOPSTATE_WAIT]\n{stop_response}", flush=True)
            if args.run:
                request_id = request_base + len(captures) + 1
                captures.append({"id": request_id, "command": "RUN", "response": execute(conn, request_id, "RUN")})
                persist()
                stop_response = wait_for_debugger_stop(conn, args.timeout)
                captures.append({"command": "STOPSTATE_WAIT", "response": stop_response})
                persist()
            if args.interactive:
                for raw_command in sys.stdin:
                    command = raw_command.strip()
                    if not command:
                        continue
                    if command.upper() == "QUIT":
                        break
                    request_id = time.time_ns() & 0x7FFFFFFF
                    response = execute(conn, request_id, command)
                    captures.append({"id": request_id, "command": command, "response": response})
                    persist()
                    print(f"[{request_id} {command}]\n{response}", flush=True)
                    if command.upper() == "RUN":
                        stop_response = wait_for_debugger_stop(conn, args.timeout)
                        captures.append({"command": "STOPSTATE_WAIT", "response": stop_response})
                        persist()
                        print(f"[STOPSTATE_WAIT]\n{stop_response}", flush=True)
        return 0
    finally:
        server.close()
        if child:
            persist({"pid": child.pid, "returncode": child.poll(), "state": "guard_running" if child.poll() is None else "guard_exited"})


if __name__ == "__main__":
    raise SystemExit(main())
