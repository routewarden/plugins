# RouteWarden HTTP/1.x Protocol Plugin

Standalone RouteWarden modular plugin for inspecting HTTP/1.x traffic with Host header filtering, regex path blocking, regex header blocking, malicious User-Agent blocking, path allowlists, and WebSocket upgrade tunneling.

## Protocols
- `http`

## Features
- **Host Header Verification**: Validates `Host` header against an allowlist, including wildcard subdomains (e.g. `*.example.com`).
- **Path Blocking (Regex)**: Rejects requests whose path matches regular expressions (e.g. `^/admin(/.*)?$`, `\.(env|git|bak|sql)$`, directory traversal `\.\./`).
- **Header Blocking (Regex)**: Filters any HTTP header against regular expression patterns (e.g. blocking scanner User-Agents, malicious Authorization schemes, or injection in Cookies).
- **Malicious User-Agent Blocking**: Substring-based and regex-based scanner blocking (`sqlmap`, `nikto`, `masscan`, `nmap`).
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
      # 1. Allowed host names (wildcard supported)
      allowed_hosts:
        - "api.example.com"
        - "*.internal.corp"

      # 2. Path blocking with Regular Expressions
      blocked_paths:
        - "^/admin(/.*)?$"              # Block sensitive admin panels
        - "\\.(env|git|bak|sql|yaml)$"  # Block sensitive file extensions
        - "(?i)/actuator(/.*)?"         # Block Spring Boot Actuator endpoints
        - "\\.\\./"                     # Block path traversal attempts

      # 3. Path allowlist (prefix or exact match)
      allowed_paths:
        - "/api/*"
        - "/health"

      # 4. Header blocking with Regular Expressions (any header)
      blocked_headers:
        User-Agent: "(?i)(sqlmap|nikto|acunetix|nessus|masscan|zgrab)"
        X-Forwarded-Host: ".*"                  # Block untrusted reverse proxy headers
        Authorization: "(?i)^basic\\s+.*"       # Disallow Basic Auth
        Cookie: "(?i)(union.*select|<script)"   # Block SQLi/XSS in cookies

      # 5. Simple blocked User-Agent substrings
      blocked_user_agents:
        - "sqlmap"
        - "nikto"
```
