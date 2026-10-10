"""Run the native binary against the same real wire fixture as the reference client."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler

from ce_tailnet.core import atomic_json, exclusive
from test_recovery import http_server
from test_wire_recovery import EndToEnd

BIN = Path(os.environ.get("CE_NET_BIN", "target/debug/ce-net")).resolve()


class RustManager:
    def __init__(self, doc, directory):
        self.directory = directory
        self.config = directory.parent / "native-config.json"
        atomic_json(self.config, doc)

    def tick(self, enable=False, force=False):
        result = subprocess.run([str(BIN), "--config", str(self.config), "--state-dir", str(self.directory),
                                 "up" if enable else "check"], capture_output=True, text=True, timeout=15)
        if result.returncode not in (0, 1, 2) or not result.stdout:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)


@unittest.skipUnless(BIN.exists(), "Build native ce-net first")
class RustWire(EndToEnd):
    def make_manager(self, doc, directory):
        return RustManager(doc, directory)

    def test_lost_create_reply_does_not_replay(self):
        self.drop_ack = True
        self.test_authenticated_creation_peer_outage_and_lost_forward_recovery()


@unittest.skipUnless(BIN.exists(), "Build native ce-net first")
class RustCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.config = self.home / "config.json"
        self.state = self.home / "state"
        self.args = [str(BIN), "--config", str(self.config), "--state-dir", str(self.state)]
        self.run_cli("init")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        return subprocess.run(self.args + list(args), capture_output=True, text=True, timeout=10)

    def test_init_preserves_existing_config(self):
        before = self.config.read_bytes()
        result = self.run_cli("init")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr)["code"], "config_exists")
        self.assertEqual(before, self.config.read_bytes())

    def test_status_does_not_block_behind_network_operation(self):
        with exclusive(self.state / "state.lock"):
            start = time.monotonic()
            result = self.run_cli("status")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLess(time.monotonic() - start, 1)

    def test_corrupt_state_refused(self):
        self.state.mkdir()
        (self.state / "state.json").write_text("broken")
        result = self.run_cli("status")
        self.assertEqual(json.loads(result.stderr)["code"], "invalid_json")

    def test_remote_control_api_rejected(self):
        doc = json.loads(self.config.read_text())
        doc["node_url"] = "http://example.com"
        atomic_json(self.config, doc)
        self.assertEqual(json.loads(self.run_cli("doctor").stderr)["code"], "unsafe_node_url")

    def test_old_node_is_explicitly_unsupported(self):
        class OldNode(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                self.send_response(404 if self.path == "/tunnels" else 200)
                self.end_headers()
                self.wfile.write(b"{}")
        with http_server(OldNode) as server:
            token = self.home / "token"
            token.write_text("test-token")
            token.chmod(0o600)
            doc = json.loads(self.config.read_text())
            doc.update(node_url="http://127.0.0.1:%d" % server.server_port, token_file=str(token))
            atomic_json(self.config, doc)
            result = self.run_cli("doctor")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stderr)["code"], "unsupported")

    def test_watch_singleton_and_graceful_signal(self):
        process = subprocess.Popen(self.args + ["watch"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            # The initial line is a completed tick and proves the watcher owns its lock.
            import select
            self.assertTrue(select.select([process.stdout], [], [], 5)[0])
            self.assertIn("services", process.stdout.readline())
            other = self.run_cli("watch")
            self.assertEqual(json.loads(other.stderr)["code"], "busy")
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=3), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main()
