# Release validation

Date: 2026-10-07. Version: 0.1.0. Author: foreman/ce-tailnet-lead.

## Question

Can a connection supervisor distinguish a live local tunnel listener from a responding upstream, restore a lost forward, and preserve other applications' connections?

## Method

The automated suite uses a loopback HTTP upstream, a fake authenticated CE control API and real TCP forwarding sockets. It interrupts upstream health responses, removes a forward, restarts the manager from persisted state, injects authorization failures and loses a create acknowledgement. No physical device or production node is modified by the tests.

```text
Manager --> bearer-authenticated API fixture --> TCP forward --> HTTP upstream
                         |                           |
                  tunnel registry             failure injection
```

The diagram describes the test fixture. It is not evidence of a deployed CE network.

## Results

All 21 tests passed on macOS with Python 3.9. The tests cover upstream outage/recovery, catch-all response rejection, node listener loss, concurrent starts, foreign port refusal, identity conflicts, missing API support, credential permissions, stale observations, state persistence, corrupt state, backoff, lock deadlines, lost acknowledgements and malformed configuration.

The real-socket recovery test initially failed because a closed TCP socket in TIME_WAIT was classified as a live listener. Matching the CE listener's `SO_REUSEADDR` behavior fixed that failure. The test now verifies that a lost listener is recreated exactly once and that upstream failure alone does not trigger duplicate listener creation.

A clean virtual environment built and installed the Python wheel, and its `ce-net --version` command returned `0.1.0`. The launch manifest passed the existing CE Launchpad contract validator without errors. A source-checkout command was also installed and invoked directly.

## Production limitations

The local deployed CE node tested on this date returned HTTP 404 for `GET /tunnels`. The new doctor command reported `unsupported` and exited 2. This prevents a claim of verified production connectivity until the node registry implementation is deployed and measured.

The suite does not establish cross-network relay reliability, NAT traversal, virtual-IP behavior, mobile support or long-duration availability. A device outage is not repaired by publishing this package. See [the protocol contract](PROTOCOL.md) for remaining infrastructure work.
