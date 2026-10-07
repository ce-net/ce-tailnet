"""ce-net: configure, inspect and supervise CE device connections."""

import argparse
import json
import os
from pathlib import Path
import signal
import sys
import threading

from . import __version__
from .core import Failure, Manager, Node, atomic_json, config, exclusive


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", default=os.path.expanduser("~/.config/ce-tailnet/config.json"))
    parser.add_argument("--state-dir", default=os.path.expanduser("~/.local/state/ce-tailnet"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Create an empty configuration without credentials")
    sub.add_parser("doctor", help="Check configuration, node and safe tunnel lifecycle support")
    sub.add_parser("status", help="Show last observations; stale results become unknown")
    sub.add_parser("check", help="Run one fresh read-only check of desired connections")
    sub.add_parser("watch", help="Supervise desired connections with bounded backoff")
    for name in ("up", "down", "port"):
        cmd = sub.add_parser(name)
        cmd.add_argument("services", nargs="+" if name == "port" else "*")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            with exclusive(str(args.config) + ".lock"):
                if Path(args.config).exists():
                    raise Failure("config_exists", "Existing configuration preserved")
                data = Path.home() / ("Library/Application Support/ce" if sys.platform == "darwin" else ".local/share/ce")
                atomic_json(args.config, {"version": 1, "node_url": "http://127.0.0.1:8844",
                                         "token_file": str(data / "api.token"), "services": {}})
            result = {"config": args.config, "services": 0}
        else:
            doc = config(args.config)
            manager = Manager(doc, args.state_dir)
            if args.command == "doctor":
                node = Node(doc)
                node.call("/status")
                node.tunnels()
                result = {"status": "ready", "services": len(doc["services"]),
                          "detail": "CE API and tunnel registry answered; run up to measure configured upstreams"}
            elif args.command == "status":
                result = manager.status()
            elif args.command == "check":
                result = manager.tick(force=True)
            elif args.command == "up":
                result = manager.tick(args.services or None, enable=True, force=True)
            elif args.command == "down":
                result = manager.down(args.services or list(doc["services"]))
            elif args.command == "port":
                result = manager.tick(args.services, enable=True, force=True)
                for name in args.services:
                    if result["services"][name]["status"] != "up":
                        raise Failure("not_ready", "Requested service has not passed its upstream probe")
                for name in args.services:
                    print("127.0.0.1:%d" % doc["services"][name]["local_port"])
                return 0
            else:
                stop = threading.Event()
                for sig in (signal.SIGTERM, signal.SIGINT):
                    signal.signal(sig, lambda *_: stop.set())
                with exclusive(Path(args.state_dir) / "watch.lock", timeout=0):
                    while not stop.is_set():
                        manager.doc = config(args.config)
                        manager.node = Node(manager.doc)
                        result = manager.tick()
                        print(json.dumps(result), flush=True)
                        stop.wait(1)
                return 0
        print(json.dumps(result, indent=2))
        values = result.get("services", {})
        if isinstance(values, dict):
            active = [e for e in values.values() if e.get("desired")]
            if any(e.get("status") == "unknown" for e in active):
                return 2
            if any(e.get("status") != "up" for e in active):
                return 1
        return 0
    except Failure as exc:
        print(json.dumps({"status": "unknown" if exc.code == "unsupported" else "failed",
                          "code": exc.code, "detail": str(exc)}), file=sys.stderr)
        return 2 if exc.code == "unsupported" else 1
    except OSError as exc:
        print(json.dumps({"status": "failed", "code": "local_io", "detail": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
