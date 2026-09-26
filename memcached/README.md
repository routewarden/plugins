# RouteWarden Memcached Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Memcached ASCII protocol commands with dangerous command filtering and brute-force tracking.

## Protocols
- `memcached`

## Features
- **Administrative Command Blocking**: Blocks dangerous commands such as `flush_all`, `shutdown`, `slabs reassign`, or `config` that could dump or flush cache contents.
- **Immediate Rejection Banner**: Directly sends Memcached-compatible `ERROR command '<CMD>' blocked by RouteWarden\r\n` error response without forwarding to upstream.
- **Security Event Emission**: Fires security events when clients attempt blocked administrative commands.

## Installation

### Via RouteWarden CLI
```bash
# From GitHub repository:
tcp-warden plugins install https://github.com/routewarden/plugins/memcached

# Or from local clone:
tcp-warden plugins install ../plugins/memcached
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  memcached:
    enabled: true
    source: "https://github.com/routewarden/plugins/memcached"

services:
  memcached-guard:
    listen: ":11212"
    upstream: "127.0.0.1:11211"
    protocol: "memcached"
    plugin_config:
      blocked_commands:
        - "flush_all"
        - "shutdown"
        - "verbosity"
```
