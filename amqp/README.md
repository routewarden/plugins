# RouteWarden AMQP 0-9-1 Protocol Plugin

Standalone RouteWarden modular plugin for inspecting AMQP 0-9-1 (RabbitMQ) connection handshakes, monitoring authentication failures, and enforcing virtual host (vhost) access control.

## Protocols
- `amqp`
- `rabbitmq`

## Features
- **Protocol Header Verification**: Validates initial AMQP protocol header (e.g. `AMQP\x00\x00\x09\x01`).
- **Handshake Flow Tracking**: Steps through connection negotiation (`Connection.Start`, `Start-Ok`, `Tune`, `Tune-Ok`, `Open`, `Open-Ok`).
- **Auth Failure Detection**: Catches AMQP reply codes indicating authentication and access refusal (`403 ACCESS_REFUSED`, `530 NOT_ALLOWED`, `541 INTERNAL_ERROR`) to trigger fail2ban tracking.
- **Virtual Host (vhost) Allowlisting**: Restricts client access to authorized vhosts (e.g. `allowed_vhosts: ["/", "/prod"]`). Attempts to access unapproved vhosts are denied with `Connection.Close`.
- **Raw Proxy Handoff**: Transitions to raw proxy mode immediately following `Connection.Open-Ok` for minimal latency.

## Installation

### Via RouteWarden CLI
```bash
# From GitHub repository:
tcp-warden plugins install https://github.com/routewarden/plugins/amqp

# Or from local clone:
tcp-warden plugins install ../plugins/amqp
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  amqp:
    enabled: true
    source: "https://github.com/routewarden/plugins/amqp"

services:
  rabbitmq-guard:
    listen: ":5673"
    upstream: "127.0.0.1:5672"
    protocol: "amqp"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    plugin_config:
      allowed_vhosts:
        - "/"
        - "/production"
```
