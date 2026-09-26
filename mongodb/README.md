# RouteWarden MongoDB Protocol Plugin

Standalone RouteWarden modular plugin for inspecting MongoDB wire protocol traffic, detecting authentication failures, and blocking dangerous administrative operations.

## Protocols
- `mongodb`
- `mongo`

## Features
- **OP_MSG Inspection**: Inspects MongoDB wire protocol messages for unauthorized database commands.
- **Auth Failure Detection**: Detects MongoDB authentication failure error codes (code 18 `AuthenticationFailed`, code 334 `BadValue/SASL`) to trigger brute-force mitigation and IP bans.
- **Dangerous Operation Filtering**: Configurable blocking of destructive operations (e.g. `drop`, `dropDatabase`, `shutdown`).
- **Raw Proxy Handoff**: Switches to zero-overhead raw TCP streaming after authentication succeeds.

## Installation

### Via RouteWarden CLI
```bash
# From GitHub repository:
tcp-warden plugins install https://github.com/routewarden/plugins/mongodb

# Or from local clone:
tcp-warden plugins install ../plugins/mongodb
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  mongodb:
    enabled: true
    source: "https://github.com/routewarden/plugins/mongodb"

services:
  mongodb-guard:
    listen: ":27018"
    upstream: "127.0.0.1:27017"
    protocol: "mongodb"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    plugin_config:
      blocked_ops:
        - "drop"
        - "dropDatabase"
        - "shutdown"
```
