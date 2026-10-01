# RouteWarden BitTorrent Protocol Plugin

Standalone RouteWarden modular plugin for inspecting BitTorrent traffic across both TCP (Peer Wire Protocol) and UDP (DHT + uTP) layers.

---

## Capabilities & Defenses

- **Peer Wire Protocol Inspection (TCP):** Validates BEP 3 handshakes, info hashes, and extension negotiation.
- **Info Hash Filtering:** Allowlist or blocklist specific torrent info hashes (SHA-1 hex).
- **Peer ID Controls:** Enforces Azureus-style client format (`-CCVVVV-`) to block scanners and custom crawlers; filter by client prefix (e.g. `-BS-`, `-qB-`).
- **Private Tracker Protection:** Rejects peers advertising DHT extension support in handshakes.
- **Extension Enforcement:** Require or forbid specific capability bits (DHT, Fast Extension, Extension Protocol).
- **DHT Inspection & Amplification Defense (UDP):** Inspects BEP 5 DHT datagrams, blocks specific query methods (e.g., `announce_peer`), and drops oversized packets to protect against reflection DDoS.
- **uTP Control (UDP):** Inspects or blocks BEP 29 Micro Transport Protocol traffic independently.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/bittorrent

# Or by short name
tcp-warden plugins install bittorrent
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  bittorrent:
    enabled: true
    source: "https://github.com/routewarden/plugins/bittorrent"

services:
  bittorrent:
    listen: ":6881"
    upstream: "127.0.0.1:6882"
    transport: both          # bind TCP and UDP on :6881
    protocol: bittorrent
    udp:
      session_timeout: 60s
      max_sessions: 50000
    plugin_config:
      mode: inspect           # "block" | "allow" | "inspect"
      blocked_info_hashes:
        - "aabbccddeeff00112233445566778899aabbccdd"
      require_peer_id_format: true
      blocked_peer_id_prefixes:
        - "-BS-"              # BitSpirit
      allowed_peer_id_prefixes:
        - "-qB-"              # qBittorrent
        - "-TR-"              # Transmission
      private_tracker_mode: false
      block_dht: false
      max_dht_packet_size: 1500
      block_utp: false
```
