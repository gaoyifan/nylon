# nylon

[![Join our Discord](https://img.shields.io/discord/1499576745916104795?logo=discord&style=for-the-badge)](https://discord.gg/987gqqPGqr)
[![Docs](https://img.shields.io/badge/docs-nylon.jq.ax-blue?style=for-the-badge)](https://nylon.jq.ax)

Nylon is a self-healing WireGuard mesh that routes around failures. If a link goes down, nylon reroutes traffic through the next-best path in seconds. No manual intervention, no central coordination servers, just like how a real network should be :)

Under the hood, nylon implements the [Babel routing protocol (RFC 8966)](https://datatracker.ietf.org/doc/html/rfc8966) on top of a [modified wireguard-go](https://github.com/encodeous/nylon/tree/main/polyamide), using measured latency as the routing metric. 

Nylon targets under 10 seconds of convergence time after a link failure, as you can see in the demo below.

![Demo](docs/assets/demo.gif)

### Main Features
- **Multi-hop Routing**: traffic flows through the lowest-latency path across your mesh. Unlike Tailscale, Nebula, or ZeroTier, nodes don't need to be directly reachable from each other. Nylon forwards through intermediate hops automatically.
- **No Coordination Server**: no SaaS dependency, no single control-plane. Nodes exchange routes directly over the same WireGuard tunnel that carries your data.
- **Single Binary, Single Data-Port Number**: one statically-linked binary and one configured WireGuard port (`57175`). Optional fake-TCP emits TCP-shaped packets on the same number; optional Linux LAN discovery additionally uses subnet-local UDP `57176`.
- **Optional TCP Obfuscation**: Linux 6.6+ routers on amd64/arm64 (excluding Android) can add TCP-shaped candidates alongside UDP and let measured link performance choose between them.
- **WireGuard Client Compatibility**: connect stock WireGuard clients (iOS, Android, Windows) to the mesh with zero extra software. Mobile clients roam between gateways seamlessly.
- **Native WireGuard Speeds**: data-plane runs entirely in `wireguard-go` (polyamide), capable of 10+ Gbps throughput.

## Getting Started

Download the latest release binary from the [releases page](https://github.com/encodeous/nylon/releases), then head to the [docs](https://nylon.jq.ax) for setup instructions.

> **[Read the full documentation at nylon.jq.ax](https://nylon.jq.ax)**
> includes configuration reference, guides for connecting WireGuard clients, port forwarding, and comparisons with Tailscale/Nebula.

Sample systemd service and launchctl plist files can be found under the `examples` directory.

> [!NOTE]
> **Stability:** I daily-drive nylon on Linux and macOS. The routing protocol has an [extensive test suite](https://github.com/encodeous/nylon/blob/main/core/router_test.go) and integration tests with simulated network conditions. The config format may still change between releases.
>
> **Security:** Nylon does not modify WireGuard's cryptographic code. Route updates and endpoint probes are sent inside encrypted WireGuard tunnels. TCP obfuscation's outer control packets are not WireGuard-authenticated, but carry no mesh payload and cannot activate a candidate without an authenticated probe. For security concerns, [contact me directly](https://jiaqi.ch/).
>
> **Windows:** The Windows client has known issues. For now, I recommend connecting Windows machines as [passive WireGuard clients](/guides/wg-clients) via a Linux/macOS gateway.
>
> Bugs and feature requests welcome via [GitHub issues](https://github.com/encodeous/nylon/issues).

---

Built with sweat and tears (thankfully no blood)

`nylon` is not an official WireGuard project, and WireGuard is a registered trademark of Jason A. Donenfeld.
