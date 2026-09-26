# RouteWarden MySQL Protocol Plugin

Standalone RouteWarden modular plugin for inspecting MySQL and MariaDB wire protocol traffic with auth failure tracking.

## Protocols
- `mysql`
- `mariadb`

## Installation

### Via RouteWarden CLI
```bash
# From Git repository:
tcp-warden plugins install https://github.com/routewarden/plugins/mysql

# Or from local clone:
tcp-warden plugins install ../plugins/mysql
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  mysql:
    enabled: true
    source: "https://github.com/routewarden/plugins/mysql"

services:
  mysql-guard:
    listen: ":3307"
    upstream: "127.0.0.1:3306"
    protocol: "mysql"
    max_auth_failures: 3
    ban_after_failures: 3
```
