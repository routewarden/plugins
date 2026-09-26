# RouteWarden Minecraft Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Minecraft Java Edition Server List Ping (SLP) and handshake packets to mitigate server flooding and DDoS attacks.

## Protocols
- `minecraft`
- `mc`

## Features
- **Handshake Validation**: Validates VarInt length-prefixed Minecraft handshake packets and next-state intentions (Status ping vs Login).
- **SLP Rate Limiting**: Mitigates Server List Ping flooding attacks aimed at exhausting server resources.
- **Protocol Anomaly Detection**: Rejects malformed or oversized handshake attempts before reaching the backend Minecraft server.

## Installation

### Via RouteWarden CLI
```bash
# From GitHub repository:
tcp-warden plugins install https://github.com/routewarden/plugins/minecraft

# Or from local clone:
tcp-warden plugins install ../plugins/minecraft
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  minecraft:
    enabled: true
    source: "https://github.com/routewarden/plugins/minecraft"

services:
  minecraft-guard:
    listen: ":25565"
    upstream: "127.0.0.1:25566"
    protocol: "minecraft"
    rate_limit:
      connections_per_minute: 60
      burst: 10
    plugin_config:
      max_connections_per_sec: 10
```
