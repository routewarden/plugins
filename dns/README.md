# RouteWarden DNS Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Domain Name System (DNS) traffic across both UDP and TCP transports.

---

## Capabilities & Defenses

- **Dual Transport Support:** Guards DNS traffic over UDP (standard port 53 datagrams) and TCP (DNS-over-TCP with length prefixing).
- **Domain Blocklisting:** Blocks malicious queries using exact domain matching (`malware.example.com`) or wildcard suffixes (`*.ads.example.net`).
- **Amplification Attack Protection:** Enforces maximum datagram packet size thresholds (`max_packet_size`) to drop oversized DNS queries used in reflection/amplification DDoS attacks.
- **Direction Awareness:** Inspects inbound client queries while permitting return responses from authoritative upstreams.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/dns

# Or by short name
tcp-warden plugins install dns
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  dns:
    enabled: true
    source: "https://github.com/routewarden/plugins/dns"

services:
  dns-guard:
    listen: ":53"
    upstream: "1.1.1.1:53"
    transport: both    # bind UDP and TCP on :53
    protocol: dns
    udp:
      session_timeout: 30s
      max_sessions: 10000
    plugin_config:
      blocked_domains:
        - "malware.example.com"
        - "*.ads.example.net"
      max_packet_size: 4096
```
