"""Bounded connection supervision. Never retries or sends application writes."""

import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import socket
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 1024 * 1024


class Failure(Exception):
    """A classified failure, safe to show without credentials or response bodies."""

    def __init__(self, code, detail):
        self.code = code
        super().__init__(detail)


def read_json(path, default=None):
    try:
        with open(path) as stream:
            return json.load(stream)
    except FileNotFoundError:
        if default is not None:
            return default
        raise Failure("missing_config", "Configuration does not exist; run ce-net init")
    except (OSError, ValueError):
        raise Failure("invalid_json", "Cannot read JSON configuration or state")


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextlib.contextmanager
def exclusive(path, timeout=30):
    """Cross-process fencing shared by CLI and watcher; never deletes a lock inode."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    until = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= until:
                    raise Failure("busy", "Another ce-net operation holds this state lock")
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def local_url(value):
    if not isinstance(value, str):
        raise Failure("unsafe_node_url", "CE API URL must be a string")
    try:
        u = urllib.parse.urlsplit(value)
        local = ipaddress.ip_address(u.hostname).is_loopback
        u.port
    except (ValueError, TypeError):
        raise Failure("unsafe_node_url", "CE API must be an HTTP loopback IP origin")
    if u.scheme != "http" or not local or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        raise Failure("unsafe_node_url", "CE API must be an HTTP loopback IP origin")
    return value.rstrip("/")


def config(path):
    doc = read_json(path)
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise Failure("invalid_config", "Expected configuration version 1")
    local_url(doc.get("node_url", "http://127.0.0.1:8844"))
    services = doc.get("services")
    if not isinstance(services, dict) or len(services) > 128:
        raise Failure("invalid_config", "services must be an object with at most 128 entries")
    ports = set()
    for name, service in services.items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}", name) or not isinstance(service, dict):
            raise Failure("invalid_config", "Invalid service name or record")
        if not isinstance(service.get("node_id"), str) or not re.fullmatch(r"[0-9a-f]{64}", service["node_id"]):
            raise Failure("invalid_config", "Each service requires an explicit CE node identity")
        if not isinstance(service.get("cap_file"), str) or not service["cap_file"]:
            raise Failure("invalid_config", "Each service requires a local capability file path")
        for key in ("local_port", "remote_port"):
            if type(service.get(key)) is not int or not 1024 <= service[key] <= 65535:
                if key != "remote_port" or type(service.get(key)) is not int or not 1 <= service[key] <= 65535:
                    raise Failure("invalid_config", "Invalid port")
        if service["local_port"] in ports:
            raise Failure("invalid_config", "Two services cannot claim one local port")
        ports.add(service["local_port"])
        probe = service.get("probe", {})
        if not isinstance(probe, dict) or probe.get("kind") not in ("http", "banner"):
            raise Failure("invalid_config", "Declare an HTTP marker or server-first banner probe")
        marker = probe.get("contains")
        if not isinstance(marker, str) or not marker or len(marker.encode()) > 4096:
            raise Failure("invalid_config", "Probe needs a nonempty expected marker")
        if probe["kind"] == "http":
            for key in ("path", "negative_path"):
                v = probe.get(key, "")
                if not isinstance(v, str) or not v.startswith("/") or v.startswith("//") or any(ord(c) < 32 for c in v) or "#" in v:
                    raise Failure("invalid_config", "HTTP probe requires a path and a negative-control path")
        timeout = service.get("timeout", 3)
        if type(timeout) not in (int, float) or not 0.1 <= timeout <= 15:
            raise Failure("invalid_config", "Probe timeout must be 0.1..15 seconds")
    return doc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def request(url, method="GET", body=None, token=None, timeout=5):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with OPENER.open(req, timeout=timeout) as response:
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise Failure("oversized_response", "Response exceeds one MiB")
            return response.status, data
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (OSError, ValueError):
        raise Failure("unreachable", "Endpoint did not answer within its connection deadline")


def secret_file(path):
    try:
        p = Path(path).expanduser()
        if p.stat().st_mode & 0o077:
            raise Failure("unsafe_secret_permissions", "Credential file must be private (chmod 600)")
        value = p.read_text().strip()
        if not value or len(value) > 65536:
            raise ValueError()
        return value
    except (OSError, ValueError):
        raise Failure("missing_credential", "Credential file unavailable or empty")


class Node:
    def __init__(self, doc):
        self.url = local_url(doc.get("node_url", "http://127.0.0.1:8844"))
        self.token_file = doc.get("token_file", str(Path.home() / ".local/share/ce/api.token"))

    def call(self, path, method="GET", body=None):
        token = secret_file(self.token_file)
        status, data = request(self.url + path, method, body, token, timeout=5)
        if status in (401, 403):
            raise Failure("denied", "CE API refused authorization")
        if status == 404:
            raise Failure("unsupported", "CE node does not implement " + path)
        if status != 200:
            raise Failure("node_error", "CE API returned HTTP " + str(status))
        try:
            return json.loads(data)
        except ValueError:
            raise Failure("invalid_response", "CE API did not return JSON")

    def tunnels(self):
        rows = self.call("/tunnels")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise Failure("invalid_response", "CE tunnel registry must be a list")
        return rows

    def open(self, service):
        return self.call("/tunnel", "POST", {
            "node_id": service["node_id"], "local_port": service["local_port"],
            "remote_port": service["remote_port"], "caps": secret_file(service["cap_file"])})


def bound(port):
    with socket.socket() as sock:
        # Tokio's TCP listener uses SO_REUSEADDR. TIME_WAIT after a stopped
        # connection is not a foreign live listener and must not block recovery.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True


def probe(service):
    """Only configured read-only probes. No payload or command gets replayed."""
    p = service["probe"]
    timeout = service.get("timeout", 3)
    try:
        if p["kind"] == "banner":
            with socket.create_connection(("127.0.0.1", service["local_port"]), timeout) as sock:
                sock.settimeout(timeout)
                raw = sock.recv(4096)
            ok = p["contains"].encode() in raw
        else:
            base = "http://127.0.0.1:%d" % service["local_port"]
            status, raw = request(base + p["path"], timeout=timeout)
            negative, _ = request(base + p["negative_path"], timeout=timeout)
            ok = status == 200 and p["contains"].encode() in raw and negative == 404
        return ("up", "Expected upstream marker received") if ok else ("down", "Upstream identity or negative-control probe failed")
    except (Failure, OSError):
        return "down", "Upstream did not answer the declared read-only probe"


def fingerprint(service):
    return {k: service[k] for k in ("node_id", "local_port", "remote_port")}


class Manager:
    def __init__(self, doc, state_dir, node=None, clock=time.time):
        self.doc = doc
        self.home = Path(state_dir)
        self.node = node or Node(doc)
        self.clock = clock

    def _load(self):
        state = read_json(self.home / "state.json", {"version": 1, "services": {}})
        if not isinstance(state, dict) or state.get("version") != 1 or not isinstance(state.get("services"), dict):
            raise Failure("invalid_state", "State is corrupt; refusing to discard ownership records")
        return state

    def _save(self, state):
        atomic_json(self.home / "state.json", state)

    def _ensure(self, name, entry):
        service = self.doc["services"][name]
        if entry.get("identity") and entry["identity"] != fingerprint(service):
            raise Failure("config_changed", "Active endpoint configuration changed; reconcile before reuse")
        # The registry, when available, rules out an unrelated listener. A receipt on old
        # nodes is not sufficient to identify a process after restart; fail closed there.
        rows = self.node.tunnels()
        held = [r for r in rows if r.get("local_port") == service["local_port"]]
        if held:
            if any(any(r.get(k) != v for k, v in fingerprint(service).items()) for r in held):
                raise Failure("port_conflict", "Local port belongs to another CE endpoint")
        else:
            if bound(service["local_port"]):
                raise Failure("port_conflict", "Local port is held outside the CE tunnel registry")
            # Desired state was persisted before sending. The next pass reconciles the
            # registry before considering another create after an interrupted request.
            result = self.node.open(service)
            if not isinstance(result, dict) or any(result.get(k) != v for k, v in fingerprint(service).items()):
                raise Failure("invalid_response", "CE returned a different tunnel identity")
        entry["identity"] = fingerprint(service)
        return probe(service)

    def tick(self, names=None, enable=False, force=False):
        with exclusive(self.home / "state.lock"):
            state = self._load()
            requested = names if names is not None else list(self.doc["services"])
            if any(n not in self.doc["services"] for n in requested):
                raise Failure("unknown_service", "Requested service is not configured")
            for name in requested:
                entry = state["services"].setdefault(name, {"desired": False, "failures": 0})
                if enable:
                    entry["desired"] = True
            self._save(state)
            for name in requested:
                entry = state["services"][name]
                if not entry["desired"] or (not force and self.clock() < entry.get("retry_at", 0)):
                    continue
                start = time.monotonic()
                try:
                    verdict, detail = self._ensure(name, entry)
                    code = "ok" if verdict == "up" else "upstream_down"
                except Failure as exc:
                    verdict, code, detail = "unknown" if exc.code == "unsupported" else "down", exc.code, str(exc)
                entry.update(status=verdict, code=code, detail=detail, observed_at=self.clock(),
                             elapsed_ms=round((time.monotonic() - start) * 1000, 1))
                entry["failures"] = 0 if verdict == "up" else min(20, entry.get("failures", 0) + 1)
                delay = 5 if verdict == "up" else min(60, 2 ** entry["failures"]) * random.uniform(0.8, 1.2)
                entry["retry_at"] = self.clock() + delay
                self._save(state)
            return state

    def status(self):
        # Atomic replacement makes a snapshot consistent without waiting behind
        # network probes. Status must remain available during an upstream outage.
        state = self._load()
        for entry in state["services"].values():
            entry["stale"] = self.clock() - entry.get("observed_at", 0) > 90
            if entry["stale"]:
                entry["status"] = "unknown"
        return state

    def down(self, names):
        """Withdraw desired state only. Never terminate a shared node's tunnel."""
        with exclusive(self.home / "state.lock"):
            state = self._load()
            for name in names:
                if name not in self.doc["services"]:
                    raise Failure("unknown_service", "Requested service is not configured")
                entry = state["services"].setdefault(name, {})
                entry.update(desired=False, status="unmanaged", detail="Recovery disabled; shared CE tunnel left intact")
            self._save(state)
            return state
