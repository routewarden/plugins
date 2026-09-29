# RouteWarden Echo & Text Stream Filter Plugin

Example custom RouteWarden plugin demonstrating bidirectional Layer 4 payload inspection, signature scanning, and real-time payload filtering.

---

## Capabilities & Defenses

- **Stream Keyword Inspection:** Scans bidirectional TCP stream chunks for banned signature strings or exploit keywords.
- **Dynamic Content Blocking:** Drops connections or sanitizes payloads upon encountering prohibited keywords (`EXPLOIT`, `DROP TABLE`, `MALWARE`, `RCE_TEST`).
- **Educational Reference:** Acts as a clean reference implementation for building proprietary protocol inspectors and stream sanitizers using RouteWarden's Plugin SDK.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/echo_filter

# Or by short name
tcp-warden plugins install echo_filter
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  echo_filter:
    enabled: true
    source: "https://github.com/routewarden/plugins/echo_filter"

services:
  echo-guard:
    listen: ":7001"
    upstream: "127.0.0.1:7000"
    protocol: "echo"
    rate_limit:
      connections_per_minute: 60
      burst: 10
    plugin_config:
      banned_keywords:
        - "EXPLOIT"
        - "DROP TABLE"
        - "MALWARE"
        - "RCE_TEST"
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection
```bash
# Redirect incoming traffic on port 7000 to RouteWarden port 7001
sudo nft add table ip routewarden_nat
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 7000 redirect to :7001
```

### Strategy 2: `iptables` Redirection
```bash
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 7000 -j REDIRECT --to-port 7001
```

### Strategy 3: Direct Reverse Proxy
Set RouteWarden to listen on `:7000` and backend echo server on `127.0.0.1:7002`.

---

## Attack Simulation & Verification

```bash
# 1. Normal traffic is permitted:
echo "Hello RouteWarden" | nc localhost 7001

# 2. Banned keyword triggers immediate connection termination:
echo "Testing MALWARE injection" | nc localhost 7001
# Output: Connection closed by foreign host
```
