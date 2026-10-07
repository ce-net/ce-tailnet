# ce-tailnet

`ce-net` manages named connections over the existing CE mesh. It checks the service at the far end of a tunnel, saves which connections should stay available, and recreates missing forwards after a node restart.

Experimental TCP service networking for a CE-based Tailscale alternative. Virtual IP interfaces, transparent DNS, subnet routes, exit nodes and mobile clients remain future work.

## Install

Python 3.9 or newer on macOS or Linux, plus a running [CE node](https://github.com/ce-net/ce) that implements `GET /tunnels` and `POST /tunnel`.

```sh
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/ce-net init
.venv/bin/ce-net doctor
```

For a source checkout, `bin/ce-net` runs without third-party Python dependencies. Put that executable on your command path to use `ce-net` directly.

## Configure

`ce-net init` creates `~/.config/ce-tailnet/config.json` with no services. Add records based on [examples/config.json](examples/config.json). Replace the example node identity, port numbers and health marker with verified values for your device. The all-zero example identity is a placeholder.

Each service declares a CE node identity, a local port, a remote port and the path to a scoped CE capability file. Keep credentials outside the repository with mode `0600`. The CE node still authenticates and authorizes the remote connection; this package does not issue grants or implement cryptography.

HTTP probes require both an expected response marker and a nonexistent route that returns 404. This prevents a catch-all web page from passing as a healthy service. For SSH, use a `banner` probe with `contains` set to `SSH-`; it reads the server banner and sends no command. Banner health proves protocol availability, not host identity: the SSH client must still verify its host key.

Use read-only health routes. Do not configure a route that moves hardware or changes application state as a probe.

```sh
ce-net up example.health
ce-net status
ce-net check
ce-net port example.health
ce-net watch
ce-net down example.health
```

`up` saves desired state before requesting a forward. `watch` restores that state after restarting and checks it with exponential backoff and jitter. Healthy connections are checked every five seconds. Failed checks back off to at most 72 seconds including jitter. Each network operation has a socket timeout.

`port` prints an address only after its upstream passes the configured probe. It exits unsuccessfully when the connection is down or cannot be verified. JSON status carries the observation time; observations older than 90 seconds become `unknown`.

`down` disables automatic recovery. It deliberately leaves the shared CE tunnel and any existing application connections intact. It does **not** revoke access or claim to close the tunnel. Tunnel deletion needs stronger ownership and close-completion semantics in the node API.

## Recovery and boundaries

The manager reads the CE tunnel registry before creating a listener. An endpoint with a different node identity or remote port is a conflict. A listener outside the registry is also a conflict. Neither is terminated. A missing registry is reported as `unknown` with exit code 2; an old node is never reported healthy based only on a bound port.

If a remote service goes away while its tunnel stays bound, the upstream probe fails. The tool checks again with backoff. Every new probe uses a new connection through CE, allowing the existing transport to reconnect. It does not replace a shared listener to force recovery. If the node loses a forward, the manager recreates it after reconciling the registry. Concurrent commands using the same state directory share a process lock.

The package never forwards or replays application commands. Applications retain responsibility for their own acknowledgements, idempotency, stream reconnection and device safety. In particular, a failed motor command must not be automatically repeated.

State is written atomically, synced to disk, and contains no capability or API token. Corrupt state is refused rather than erased. The node control API is restricted to loopback IP addresses; redirects and environment HTTP proxies are disabled.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The suite includes an authenticated fake CE API, real TCP forwarding sockets and an upstream HTTP service. It injects upstream failure, lost listeners, authorization refusal, stale observations, corrupt state and concurrent starts. This is local fault-injection evidence, not a measurement of wide-area NAT traversal or production uptime.

See [the protocol contract](docs/PROTOCOL.md) and [release validation](docs/VALIDATION.md). The [ceapp manifest](ceapp.toml) declares the watcher start and stop commands. The watcher has no HTTP listener or advertised mesh service; its process health is not substituted for connection health.

## Relationship to CE

This new repository packages recovery and readiness as a standalone tool. It reuses the CE node transport, identity and capability model. Its API integration follows the existing [device-reach](https://github.com/ce-net/device-reach) implementation. Existing `reach` deployments remain unchanged.

No deployment files, device inventory, keys or business payloads are included. The source is licensed under [AGPL-3.0](LICENSE).
