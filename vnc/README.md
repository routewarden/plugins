# RouteWarden VNC / RFB Protocol Plugin

Standalone RouteWarden modular plugin for inspecting VNC / RFB (Remote Framebuffer) protocol sessions, detecting authentication failures, and preventing unauthenticated access.

## Protocols
- `vnc`
- `rfb`

## Features
- **Protocol Version Negotiation**: Validates RFB handshake (`RFB 003.003`, `RFB 003.007`, `RFB 003.008`).
- **Security Type Enforcement**: Blocks insecure or unauthenticated security types (such as security type `1` for `None`/no-auth) to ensure servers cannot be accessed without authentication.
- **VncAuth Challenge-Response Inspection**: Tracks challenge-response handshakes and detects `SecurityResult` code 1 (`Failed`).
- **Brute-Force Attack Mitigation**: Automatically triggers IP bans when repeated failed password attempts occur.
- **Direct Raw Proxying**: Seamlessly switches to low-latency raw streaming after successful authentication.

## Installation

### Via RouteWarden CLI
```bash
# From GitHub repository:
tcp-warden plugins install https://github.com/routewarden/plugins/vnc

# Or from local clone:
tcp-warden plugins install ../plugins/vnc
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  vnc:
    enabled: true
    source: "https://github.com/routewarden/plugins/vnc"

services:
  vnc-guard:
    listen: ":5901"
    upstream: "127.0.0.1:5900"
    protocol: "vnc"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    plugin_config:
      blocked_security_types:
        - 1 # Block "None" (unauthenticated) access
```
