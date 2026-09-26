# RouteWarden Redis Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Redis RESP wire protocol traffic with command filtering (e.g. blocking `FLUSHALL`, `FLUSHDB`, `CONFIG`, `SHUTDOWN`) and auth brute-force tracking.

## Protocols
- `redis`

## Installation

### Via RouteWarden CLI
```bash
# From Git repository:
tcp-warden plugins install https://github.com/routewarden/plugins/redis

# Or from local clone:
tcp-warden plugins install ../plugins/redis
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  redis:
    enabled: true
    source: "https://github.com/routewarden/plugins/redis"

services:
  redis-guard:
    listen: ":6380"
    upstream: "127.0.0.1:6379"
    protocol: "redis"
    max_auth_failures: 5
    ban_after_failures: 5
    plugin_config:
      blocked_commands:
        - "FLUSHALL"
        - "FLUSHDB"
        - "CONFIG"
        - "SHUTDOWN"
```
