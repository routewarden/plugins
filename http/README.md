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

### Port Range Deployments

RouteWarden supports port ranges on the `http` inspector for clustered ingress or multi-port microservices:

#### 1. Many-to-One Port Range
Routes traffic from an entire range of ingress ports into a single backend HTTP service:
```yaml
services:
  http-cluster:
    listen: ":8080-8085"             # Listens on 8080, 8081, 8082, 8083, 8084, 8085
    upstream: "127.0.0.1:80"         # All requests route to port 80
    protocol: "http"
```

#### 2. 1:1 Port Range Mapping
Maintains identical port offsets across upstream backend instances:
```yaml
services:
  http-shards:
    listen: ":9000-9003"             # Listens on 9000, 9001, 9002, 9003
    upstream: "10.0.0.1:9000-9003"   # Port 9002 routes to 10.0.0.1:9002
    protocol: "http"
```

