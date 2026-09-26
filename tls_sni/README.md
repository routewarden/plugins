# RouteWarden TLS SNI Inspector Plugin

Standalone RouteWarden modular plugin for inspecting TLS ClientHello packets without decrypting payload, allowing domain whitelisting, phishing domain blocking, and SNI routing.

## Protocols
- `tls`
- `sni`

## Installation

### Via RouteWarden CLI
```bash
# From Git repository:
tcp-warden plugins install https://github.com/routewarden/plugins/tls_sni

# Or from local clone:
tcp-warden plugins install ../plugins/tls_sni
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  tls_sni:
    enabled: true
    source: "https://github.com/routewarden/plugins/tls_sni"

services:
  tls-proxy:
    listen: ":8443"
    upstream: "127.0.0.1:443"
    protocol: "tls"
    plugin_config:
      allowed_domains:
        - "*.example.com"
        - "app.internal"
      blocked_domains:
        - "*.phishing.com"
```
