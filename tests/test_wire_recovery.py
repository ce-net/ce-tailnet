"""Full Manager -> authenticated node API -> real TCP forward -> upstream fixture."""
import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import select
import socket
import socketserver
import tempfile
import threading
import unittest

from ce_tailnet.core import Manager, Node
from test_recovery import Upstream, http_server


class Forward(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Relay(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.create_connection(self.server.destination, timeout=1) as remote:
            sockets = [self.request, remote]
            while True:
                ready, _, _ = select.select(sockets, [], [], 2)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (remote if source is self.request else self.request).sendall(data)


class EndToEnd(unittest.TestCase):
    def test_authenticated_creation_peer_outage_and_lost_forward_recovery(self):
        forwards, rows, opened = [], [], []
        class API(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def respond(self, status, value):
                self.send_response(status)
                self.end_headers()
                self.wfile.write(json.dumps(value).encode())
            def authorized(self):
                return self.headers.get("Authorization") == "Bearer test-local-api"
            def do_GET(self):
                self.respond(200, rows) if self.authorized() else self.respond(401, {})
            def do_POST(self):
                if not self.authorized():
                    return self.respond(401, {})
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if body.get("caps") != "test-scoped-capability":
                    return self.respond(403, {})
                forward = Forward(("127.0.0.1", body["local_port"]), Relay)
                forward.destination = ("127.0.0.1", body["remote_port"])
                thread = threading.Thread(target=forward.serve_forever, daemon=True)
                thread.start()
                forwards.append((forward, thread))
                row = {key: body[key] for key in ("node_id", "local_port", "remote_port")}
                rows.append(row)
                opened.append(row)
                self.respond(200, row)
        with tempfile.TemporaryDirectory() as tmp, http_server(Upstream) as upstream, http_server(API) as api:
            Upstream.healthy, Upstream.catchall = True, False
            home = Path(tmp)
            for name, value in (("token", "test-local-api"), ("cap", "test-scoped-capability")):
                (home / name).write_text(value)
                (home / name).chmod(0o600)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                local = sock.getsockname()[1]
            service = {"node_id": "a" * 64, "local_port": local,
                       "remote_port": upstream.server_port, "cap_file": str(home / "cap"),
                       "timeout": 1, "probe": {"kind": "http", "path": "/health",
                       "negative_path": "/missing", "contains": "example.app"}}
            doc = {"version": 1, "node_url": "http://127.0.0.1:%d" % api.server_port,
                   "token_file": str(home / "token"), "services": {"test": service}}
            manager = Manager(doc, home / "state", node=Node(doc))
            try:
                self.assertEqual(manager.tick(enable=True, force=True)["services"]["test"]["status"], "up")
                self.assertEqual(len(opened), 1)
                Upstream.healthy = False
                self.assertEqual(manager.tick(force=True)["services"]["test"]["status"], "down")
                Upstream.healthy = True
                self.assertEqual(manager.tick(force=True)["services"]["test"]["status"], "up")
                self.assertEqual(len(opened), 1, "Peer outage must not replay tunnel creation")
                forward, thread = forwards.pop()
                forward.shutdown()
                forward.server_close()
                thread.join(2)
                rows.clear()
                recovered = Manager(doc, home / "state", node=Node(doc))
                self.assertEqual(recovered.tick(force=True)["services"]["test"]["status"], "up")
                self.assertEqual(len(opened), 2, "Lost listener recreated once after registry reconciliation")
            finally:
                for forward, thread in forwards:
                    forward.shutdown()
                    forward.server_close()
                    thread.join(2)


if __name__ == "__main__":
    unittest.main()
