"""Start or stop the whole local stack (S3 emulator + HDG services + hospital services).

    python demo/stack.py start      # add --fresh to wipe var/ first
    python demo/stack.py stop
    python demo/stack.py portal     # patient portal, after `scenes.py setup`

`start` first stops anything left over from an earlier run (even if var/ was
deleted), checks that every port is free, and if a service fails to start it
prints the end of that service's log instead of a bare timeout.

Ports can be moved with environment variables if something else on the machine
already uses them, e.g. NEXUS_S3_PORT=9070 make up.

On the k3s deployment the same services run as pods (see deploy/), with Garage
as the S3 backend. Locally an S3 emulator (moto) stands in for Garage.
"""
import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
VAR = ROOT / "var"
PIDS = VAR / "pids.json"
LOGS = VAR / "logs"

S3_PORT = int(os.environ.get("NEXUS_S3_PORT", "9000"))
SERVICES = [
    ("audit (HDG)", "nexus.hdg.audit:app", 8101),
    ("consent (HDG)", "nexus.hdg.consent:app", 8102),
    ("data API (HDG)", "nexus.hdg.data_api:app", 8103),
    ("key broker (hospital)", "nexus.hospital.keybroker:app", 8201),
]
PORTAL_PORT = 8301

class StartError(RuntimeError):
    pass


def env():
    e = dict(os.environ)
    e.setdefault("NEXUS_DATA_DIR", str(VAR))
    e.setdefault("NEXUS_S3_ENDPOINT", f"http://127.0.0.1:{S3_PORT}")
    e["PYTHONPATH"] = str(ROOT) + os.pathsep + e.get("PYTHONPATH", "")
    return e


def log_path(name: str) -> Path:
    return LOGS / f"{name.split()[0]}.log"


def log_tail(name: str, lines: int = 15) -> str:
    path = log_path(name)
    if not path.exists():
        return "  (no log)"
    return "\n".join("  | " + line for line in path.read_text(errors="replace").splitlines()[-lines:])


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True


def who_listens(port: int) -> str:
    try:
        out = subprocess.run(["ss", "-ltnpH", f"sport = :{port}"], capture_output=True, text=True, timeout=5).stdout
        return out.strip() or "unknown process"
    except (OSError, subprocess.SubprocessError):
        return "unknown process (install iproute2 'ss' to see which)"


def _process_table():
    """(pid, argv) for every process we can see. Exact argv from /proc on Linux, `ps` elsewhere."""
    proc = Path("/proc")
    if proc.is_dir():
        for entry in proc.iterdir():
            if entry.name.isdigit():
                try:
                    raw = (entry / "cmdline").read_bytes()
                except OSError:
                    continue
                if raw:
                    yield int(entry.name), [a.decode(errors="replace") for a in raw.split(b"\0") if a]
        return
    out = subprocess.run(["ps", "-axo", "pid=,args="], capture_output=True, text=True).stdout
    for line in out.splitlines():
        pid, _, args = line.strip().partition(" ")
        if pid.isdigit():
            yield int(pid), args.split()


def _is_nexus(argv: list[str]) -> bool:
    """True only for the exact commands this script launches."""
    def module_after_m():
        return argv[argv.index("-m") + 1] if "-m" in argv and argv.index("-m") + 1 < len(argv) else ""
    module = module_after_m()
    if module == "uvicorn":
        i = argv.index("uvicorn")
        return i + 1 < len(argv) and argv[i + 1].startswith(("nexus.hdg.", "nexus.hospital."))
    if module in ("nexus.hospital.anchor", "nexus.patient.agent"):
        return True
    return any(a.endswith("moto_server") for a in argv[:2]) and "-H" in argv and "127.0.0.1" in argv


def kill_orphans(exclude: set = frozenset()) -> int:
    """Stop NEXUS processes from earlier runs, even when var/pids.json is gone."""
    me = os.getpid()
    killed = 0
    for pid, argv in _process_table():
        if pid != me and pid not in exclude and _is_nexus(argv):
            try:
                os.kill(pid, signal.SIGTERM)
                killed += 1
            except (ProcessLookupError, PermissionError):
                pass
    if killed:
        time.sleep(1.0)
    return killed


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    try:  # a zombie counts as gone
        return "State:\tZ" not in Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return True


def wait(name: str, proc: subprocess.Popen, url: str, seconds: float = 60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if proc.poll() is not None:
            raise StartError(f"{name} exited with code {proc.returncode}. End of its log:\n{log_tail(name)}")
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    raise StartError(f"{name} did not answer on {url} within {seconds:.0f} s. End of its log:\n{log_tail(name)}")


def spawn(name: str, cmd: list[str]) -> subprocess.Popen:
    LOGS.mkdir(parents=True, exist_ok=True)
    log = open(log_path(name), "ab")
    try:
        return subprocess.Popen(cmd, cwd=ROOT, env=env(), stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    except FileNotFoundError:
        raise StartError(f"cannot run {cmd[0]!r}: is the virtualenv active and `make install` done?")


def save_pids(pids: dict):
    PIDS.write_text(json.dumps(pids, indent=2))


def start(fresh: bool):
    if kill_orphans():
        print("  stopped processes left over from an earlier run")
    if fresh and VAR.exists():
        shutil.rmtree(VAR)
    VAR.mkdir(exist_ok=True)

    busy = [(port, who_listens(port)) for port in [S3_PORT] + [p for _, _, p in SERVICES] if port_in_use(port)]
    if busy:
        lines = "\n".join(f"  port {port}: {who}" for port, who in busy)
        raise StartError(f"ports already in use by another program:\n{lines}\n"
                         f"Stop that program, or move the S3 emulator with e.g. NEXUS_S3_PORT=9070 make up")

    pids = {}
    try:
        s3 = spawn("s3 emulator", ["moto_server", "-H", "127.0.0.1", "-p", str(S3_PORT)])
        pids["s3"] = s3.pid
        save_pids(pids)
        wait("s3 emulator", s3, f"http://127.0.0.1:{S3_PORT}")
        import boto3
        boto3.client("s3", endpoint_url=f"http://127.0.0.1:{S3_PORT}", aws_access_key_id="nexus-admin",
                     aws_secret_access_key="nexus-admin-secret", region_name="us-east-1").create_bucket(Bucket="nexus-objects")
        print(f"  up   S3 emulator (Garage stand-in) http://127.0.0.1:{S3_PORT}")

        procs = {}
        for name, target, port in SERVICES:
            procs[name] = spawn(name, [sys.executable, "-m", "uvicorn", target, "--host", "127.0.0.1",
                                       "--port", str(port), "--log-level", "warning"])
            pids[name] = procs[name].pid
        save_pids(pids)
        for name, _, port in SERVICES:
            wait(name, procs[name], f"http://127.0.0.1:{port}/health")
            print(f"  up   {name:<24} http://127.0.0.1:{port}")

        anchor = spawn("anchor (hospital)", [sys.executable, "-m", "nexus.hospital.anchor", "run", "--interval", "2"])
        pids["anchor"] = anchor.pid
        save_pids(pids)
        print("  up   anchor (hospital)        every 2 s")
    except StartError:
        stop(quiet=True)
        raise


def start_portal(profile: str, port: int = PORTAL_PORT):
    if not PIDS.exists():
        raise StartError("the stack is not running: run `make up` and `make setup` first")
    if port_in_use(port):
        raise StartError(f"port {port} already in use: {who_listens(port)}")
    pids = json.loads(PIDS.read_text())
    portal = spawn("portal (patient)", [sys.executable, "-m", "nexus.patient.agent", "serve",
                                        "--profile", profile, "--port", str(port)])
    pids["portal"] = portal.pid
    save_pids(pids)
    wait("portal (patient)", portal, f"http://127.0.0.1:{port}/api/me")
    print(f"  up   patient portal           http://127.0.0.1:{port}")


def stop(quiet: bool = False):
    stopped = False
    ours = set()
    if PIDS.exists():
        for name, pid in json.loads(PIDS.read_text()).items():
            ours.add(pid)
            try:
                os.killpg(pid, signal.SIGTERM)
                stopped = True
                if not quiet:
                    print(f"  stop {name}")
            except (ProcessLookupError, PermissionError):
                pass
        PIDS.unlink()
        deadline = time.time() + 3
        while time.time() < deadline and any(_alive(pid) for pid in ours):
            time.sleep(0.1)
    if kill_orphans(exclude=ours):
        stopped = True
        if not quiet:
            print("  stopped leftover NEXUS processes")
    if not stopped and not quiet:
        print("  nothing running")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", choices=["start", "stop", "portal"])
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--profile", default=str(VAR / "patient"))
    args = parser.parse_args()
    try:
        if args.cmd == "start":
            start(args.fresh)
        elif args.cmd == "portal":
            start_portal(args.profile)
        else:
            stop()
    except StartError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
