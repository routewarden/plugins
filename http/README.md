# RouteWarden HTTP/1.x Protocol Plugin

Standalone RouteWarden modular plugin for inspecting HTTP/1.x traffic with Host header filtering, malicious User-Agent blocking, path allowlists, and WebSocket upgrade tunneling.

## Protocols
- `http`

## Features
- **Host Header Verification**: Validates `Host` header against an allowlist, including wildcard subdomains (e.g. `*.example.com`).
- **Malicious User-Agent Blocking**: Detects and blocks scanning and exploitation tools (e.g. `sqlmap`, `nikto`, `masscan`, `nmap`).
- **Path Allowlists**: Enforces URL path policies (e.g. allow only `/api/*`, `/health`), rejecting unauthorized endpoints with `403 Forbidden`.
- **WebSocket Passthrough**: Automatically upgrades connections with `Upgrade: websocket` to raw bidirectional streaming.
- **Keep-Alive Pipeline**: Supports HTTP keep-alive persistent connections with stream reuse.

## Installation

### Via RouteWarden CLI
```bash
# From GitHub repository:
tcp-warden plugins install https://github.com/routewarden/plugins/http

# Or from local clone:
tcp-warden plugins install ../plugins/http
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  http:
    enabled: true
    source: "https://github.com/routewarden/plugins/http"

services:
  web-proxy:
    listen: ":8080"
    upstream: "127.0.0.1:80"
    protocol: "http"
    plugin_config:
      allowed_hosts:
        - "api.example.com"
        - "*.internal.corp"
      blocked_user_agents:
        - "sqlmap"
        - "nikto"
        - "acunetix"
      allowed_paths:
        - "/api/*"
        - "/health"
```
