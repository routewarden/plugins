# RouteWarden Generic TCP Bastion Plugin

Standalone RouteWarden modular plugin providing high-performance Layer 4 transparent TCP proxying, rate-limiting, geo-blocking, and IP filtering for arbitrary proprietary or unparsed TCP services (e.g. Remote Desktop RDP, custom game protocols, industrial IoT sockets, financial feeds).

---

## Capabilities & Defenses

- **Zero-Copy Byte Relay:** Fast bidirectional TCP stream forwarding using half-close (`CloseWrite`) TCP semantics.
- **Connection Rate Limiting:** Enforces connection rates and burst capacities per client IP to mitigate denial-of-service floods.
- **MaxMind Geo-Blocking:** Blocks connections originating from unauthorized or restricted country codes (e.g. `deny_countries: ["RU", "CN", "KP"]`).
- **CIDR IP Allow & Deny Lists:** Restricts access to trusted subnets (e.g. corporate VPN CIDR blocks) while denying malicious ranges.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/generic

# Or by short name
tcp-warden plugins install generic
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  generic:
    enabled: true
    source: "https://github.com/routewarden/plugins/generic"

services:
  custom-service-guard:
    listen: ":15432"
    upstream: "127.0.0.1:5432"
    protocol: "tcp"
    rate_limit:
      connections_per_minute: 120
      burst: 30
    ip_filter:
      allow:
        - "10.0.0.0/8"
        - "192.168.1.0/24"
        - "127.0.0.1/32"
      deny:
        - "198.51.100.0/24"
    geo_block:
      deny_countries:
        - "KP"
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection
```bash
# Redirect incoming external traffic on port 3389 (RDP) to RouteWarden on port 13389
sudo nft add table ip routewarden_nat
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 3389 redirect to :13389
```

### Strategy 2: `iptables` Redirection
```bash
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 3389 -j REDIRECT --to-port 13389
sudo netfilter-persistent save
```

### Strategy 3: Direct Port Swap / Reverse Proxy
Reconfigure the proprietary daemon to listen on an internal port (e.g. `127.0.0.1:3390`), and configure RouteWarden to bind to `:3389`.

---

## Attack Simulation & Verification

```bash
# Verify connection forwarding via nc:
nc -zv localhost 15432
# Output: Connection to localhost port 15432 [tcp/*] succeeded!
```
