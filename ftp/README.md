# RouteWarden FTP Protocol Plugin

Standalone RouteWarden modular plugin for inspecting FTP control channel traffic (RFC 959) and monitoring authentication failures.

## Protocols
- `ftp`

## Installation

### Via RouteWarden CLI
```bash
# From Git repository:
tcp-warden plugins install https://github.com/routewarden/plugins/ftp

# Or from local clone:
tcp-warden plugins install ../plugins/ftp
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  ftp:
    enabled: true
    source: "https://github.com/routewarden/plugins/ftp"

services:
  ftp-guard:
    listen: ":2121"
    upstream: "127.0.0.1:21"
    protocol: "ftp"
    max_auth_failures: 3
    ban_after_failures: 3
```
