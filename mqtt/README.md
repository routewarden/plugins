# RouteWarden MQTT Protocol Plugin

Standalone RouteWarden modular plugin for inspecting MQTT IoT broker traffic (OASIS MQTT 3.1.1 and 5.0) with ClientID filtering and connection anomaly detection.

## Protocols
- `mqtt`

## Features
- **CONNECT Packet Inspection**: Validates initial MQTT CONNECT packet structure and protocol version headers.
- **ClientID Filtering**: Blocks scanning tools and unauthorized clients based on banned ClientID prefixes (e.g. `shodan`, `scanner-`, `bot-`).
- **Maximum ClientID Length**: Enforces limits on ClientID lengths to prevent buffer overflow or memory exhaustion attacks on IoT brokers.

## Installation

### Via RouteWarden CLI
```bash
# From GitHub repository:
tcp-warden plugins install https://github.com/routewarden/plugins/mqtt

# Or from local clone:
tcp-warden plugins install ../plugins/mqtt
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  mqtt:
    enabled: true
    source: "https://github.com/routewarden/plugins/mqtt"

services:
  mqtt-broker-guard:
    listen: ":1884"
    upstream: "127.0.0.1:1883"
    protocol: "mqtt"
    plugin_config:
      blocked_client_id_prefixes:
        - "shodan"
        - "scanner-"
        - "bot-"
      max_client_id_len: 64
```
