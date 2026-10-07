# CE node protocol used by ce-tailnet

The local CE HTTP API is the control plane. Its bearer token is read from the configured private file for each request. A device capability is read only when a forward must be created. Neither value appears in status output or saved state.

| Operation | Request | Required response |
| --- | --- | --- |
| Node health | `GET /status` | HTTP 200, JSON |
| Tunnel registry | `GET /tunnels` | HTTP 200, array of tunnel records |
| Create forward | `POST /tunnel` | HTTP 200, matching endpoint identity |

Registry records contain `local_port`, `remote_port` and `node_id`. Additional node fields such as `opened_at` and `conns` are accepted. The create body contains those three fields plus `caps`, the encoded capability chain. The response must name the same three identity fields.

The contract is based on CE's existing `tunnel-close` implementation, commit `4003e97b304b078cc6af0906efa9e7bbe35d337b`. Nodes without that API report `unsupported`. A different deployed node version must be checked before use.

## What the manager guarantees

1. Desired state reaches disk before a create request is sent.
2. The next attempt reconciles the registry, including after a lost create response.
3. The manager never deletes a tunnel or kills a process to resolve a conflict.
4. An upstream marker and negative-control response are required for HTTP readiness.
5. No user command or application write is retried by this package.

The CE node owns listener creation and capability enforcement. A separate process can race this client; the node must enforce port binding atomically. This client handles a refused create as a failure and reconciles on its next check.

## Remaining work

The node API needs generation-scoped tunnel ownership and confirmed listener closure before this package can safely replace a shared forward. The product also needs transparent addressing, DNS, UDP lifecycle integration, enrollment, device approval, mobile integration and cross-network relay measurements before claiming Tailscale-level coverage. These are not implied by the TCP recovery tests.
