"""Exercise real HTTP/socket failures; no hardware, accounts or CE node required."""
import contextlib
from concurrent.futures import ThreadPoolExecutor
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from ce_tailnet.core import (Failure, Manager, Node, atomic_json, config, exclusive,
                             local_url, probe, request)


@contextlib.contextmanager
def http_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


class Upstream(BaseHTTPRequestHandler):
    healthy = True
    catchall = False

    def log_message(self, *args):
        pass

    def do_GET(self):
        ok = type(self).healthy and (self.path == "/health" or type(self).catchall)
        self.send_response(200 if ok else 404)
        self.end_headers()
        self.wfile.write(b'example.app' if ok else b'not found')


class Backend:
    """Registry fixture; upstream checks still use real sockets."""
    def __init__(self, service):
        self.rows = [dict((k, service[k]) for k in ("node_id", "local_port", "remote_port"))]
        self.opens = 0
        self.failure = None

    def tunnels(self):
        if self.failure:
            raise Failure(*self.failure)
        return list(self.rows)

    def open(self, service):
        self.opens += 1
        row = {k: service[k] for k in ("node_id", "local_port", "remote_port")}
        self.rows.append(row)
        return row


class Recovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.context = http_server(Upstream)
        self.server = self.context.__enter__()
        Upstream.healthy = True
        Upstream.catchall = False
        self.service = {"node_id": "a" * 64, "cap_file": str(self.home / "cap"),
                        "local_port": self.server.server_port, "remote_port": 8080,
                        "timeout": 0.2, "probe": {"kind": "http", "path": "/health",
                        "negative_path": "/missing", "contains": "example.app"}}
        self.doc = {"version": 1, "services": {"device.health": self.service}}
        self.backend = Backend(self.service)
        self.manager = Manager(self.doc, self.home / "state", node=self.backend)

    def tearDown(self):
        self.context.__exit__(None, None, None)
        self.tmp.cleanup()

    def row(self, result):
        return result["services"]["device.health"]

    def test_upstream_failure_is_not_hidden_by_live_listener_and_recovers(self):
        self.assertEqual(self.row(self.manager.tick(enable=True, force=True))["status"], "up")
        Upstream.healthy = False
        down = self.row(self.manager.tick(force=True))
        self.assertEqual(down["status"], "down")
        self.assertGreater(down["retry_at"], down["observed_at"])
        Upstream.healthy = True
        self.assertEqual(self.row(self.manager.tick(force=True))["status"], "up")
        self.assertEqual(self.backend.opens, 0, "Do not recreate a listener merely because its peer is down")

    def test_catchall_spa_is_not_health(self):
        Upstream.catchall = True
        self.assertEqual(probe(self.service)[0], "down")

    def test_node_restart_lost_registry_reopens_once(self):
        # Use a vacant endpoint: the fixture verifies creation, the real probe must fail.
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.service["local_port"] = sock.getsockname()[1]
        self.backend.rows = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.manager.tick(enable=True, force=True), range(4)))
        self.assertEqual(self.backend.opens, 1)
        self.assertTrue(all(self.row(r)["status"] == "down" for r in results))

    def test_foreign_listener_is_never_adopted(self):
        self.backend.rows = []
        result = self.row(self.manager.tick(enable=True, force=True))
        self.assertEqual(result["code"], "port_conflict")
        self.assertEqual(self.backend.opens, 0)

    def test_registry_identity_conflict(self):
        self.backend.rows[0]["node_id"] = "b" * 64
        self.assertEqual(self.row(self.manager.tick(enable=True, force=True))["code"], "port_conflict")

    def test_old_node_is_unknown_not_healthy(self):
        self.backend.failure = ("unsupported", "No tunnel registry")
        self.assertEqual(self.row(self.manager.tick(enable=True, force=True))["status"], "unknown")

    def test_denial_and_node_outage_recover_without_replay(self):
        for code in ("denied", "unreachable"):
            self.backend.failure = (code, "failure")
            self.assertEqual(self.row(self.manager.tick(enable=True, force=True))["status"], "down")
        self.backend.failure = None
        self.assertEqual(self.row(self.manager.tick(force=True))["status"], "up")

    def test_restart_persists_desire_without_credentials(self):
        self.manager.tick(enable=True, force=True)
        other = Manager(self.doc, self.home / "state", node=self.backend)
        self.assertTrue(self.row(other.status())["desired"])
        raw = (self.home / "state/state.json").read_text()
        self.assertNotIn("cap_file", raw)
        self.assertNotIn("token", raw)

    def test_stale_observation_becomes_unknown(self):
        self.manager.tick(enable=True, force=True)
        self.manager.clock = lambda: time.time() + 100
        self.assertEqual(self.row(self.manager.status())["status"], "unknown")

    def test_down_does_not_kill_shared_connection(self):
        self.manager.tick(enable=True, force=True)
        self.manager.down(["device.health"])
        self.assertFalse(self.row(self.manager.status())["desired"])
        self.assertEqual(probe(self.service)[0], "up")

    def test_changed_identity_refused(self):
        self.manager.tick(enable=True, force=True)
        self.service["remote_port"] = 8081
        self.assertEqual(self.row(self.manager.tick(force=True))["code"], "config_changed")

    def test_corrupt_state_preserved(self):
        target = self.home / "state/state.json"
        target.parent.mkdir()
        target.write_text("broken")
        with self.assertRaises(Failure):
            self.manager.tick(enable=True)
        self.assertEqual(target.read_text(), "broken")

    def test_backoff_skips_before_deadline(self):
        self.backend.failure = ("unreachable", "failure")
        first = self.row(self.manager.tick(enable=True, force=True))
        second = self.row(self.manager.tick())
        self.assertEqual(first["observed_at"], second["observed_at"])

    def test_lost_create_response_reconciles_without_second_create(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.service["local_port"] = sock.getsockname()[1]
        self.backend.rows = []
        original = self.backend.open
        def lost(service):
            original(service)
            raise Failure("unreachable", "Create acknowledgement lost")
        self.backend.open = lost
        self.manager.tick(enable=True, force=True)
        self.manager.tick(force=True)
        self.assertEqual(self.backend.opens, 1)

    def test_malformed_config_values_are_typed_failures(self):
        path = self.home / "config.json"
        for key, value in (("node_id", 3), ("probe", []), ("timeout", float("nan")), ("local_port", True)):
            previous = self.service[key]
            self.service[key] = value
            atomic_json(path, self.doc)
            with self.assertRaises(Failure):
                config(path)
            self.service[key] = previous

    def test_lock_has_deadline(self):
        path = self.home / "lock"
        with exclusive(path):
            with self.assertRaises(Failure):
                with exclusive(path, timeout=0):
                    pass

    def test_config_rejects_duplicate_ports(self):
        self.doc["services"]["other"] = dict(self.service)
        path = self.home / "config.json"
        atomic_json(path, self.doc)
        with self.assertRaises(Failure):
            config(path)


class Wire(unittest.TestCase):
    def test_node_bearer_auth_and_no_secret_echo(self):
        class API(BaseHTTPRequestHandler):
            authorized = False
            def log_message(self, *args):
                pass
            def do_GET(self):
                type(self).authorized = self.headers.get("Authorization") == "Bearer private-token"
                self.send_response(200 if type(self).authorized else 403)
                self.end_headers()
                self.wfile.write(b"[]")
        with tempfile.TemporaryDirectory() as tmp, http_server(API) as server:
            token = Path(tmp) / "token"
            token.write_text("private-token")
            token.chmod(0o600)
            node = Node({"node_url": "http://127.0.0.1:%d" % server.server_port, "token_file": str(token)})
            self.assertEqual(node.tunnels(), [])
            self.assertTrue(API.authorized)
            token.chmod(0o644)
            with self.assertRaises(Failure) as error:
                node.tunnels()
            self.assertNotIn("private-token", str(error.exception))

    def test_non_loopback_control_plane_refused(self):
        for url in ("http://example.com", "http://127.0.0.1@evil.example", "https://127.0.0.1", "http://localhost"):
            with self.assertRaises(Failure):
                local_url(url)

    def test_redirect_not_followed(self):
        class Redirect(BaseHTTPRequestHandler):
            hits = 0
            def log_message(self, *args):
                pass
            def do_GET(self):
                type(self).hits += 1
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
                self.end_headers()
        with http_server(Redirect) as server:
            self.assertEqual(request("http://127.0.0.1:%d/" % server.server_port)[0], 302)
            self.assertEqual(Redirect.hits, 1)


if __name__ == "__main__":
    unittest.main()
