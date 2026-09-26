# RouteWarden PostgreSQL Protocol Plugin

Standalone RouteWarden modular plugin for inspecting PostgreSQL wire protocol traffic and guarding against authentication brute-force attacks.

## Protocols
- `postgres`
- `postgresql`

## Installation

### Via RouteWarden CLI
```bash
# From Git repository:
tcp-warden plugins install https://github.com/routewarden/plugins/postgres

# Or from local clone:
tcp-warden plugins install ../plugins/postgres
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  postgres:
    enabled: true
    source: "https://github.com/routewarden/plugins/postgres"

services:
  postgres-guard:
    listen: ":5433"
    upstream: "127.0.0.1:5432"
    protocol: "postgres"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
```
