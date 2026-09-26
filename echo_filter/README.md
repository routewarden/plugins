# RouteWarden Echo & Stream Filter Plugin

Standalone RouteWarden modular plugin demonstrating real-time bidirectional TCP stream inspection and payload keyword filtering.

## Protocols
- `echo_filter`
- `text_filter`

## Features
- **Deep Payload Keyword Scanning**: Inspects streaming TCP payloads in real time for banned signature strings or exploit keywords.
- **Immediate Stream Severing**: Terminates connections upon detecting banned strings (e.g. `EXPLOIT`, `DROP TABLE`, `MALWARE`, `RCE_TEST`).
- **Developer Reference**: Serves as a reference implementation for custom RouteWarden stream filtering plugins.

## Installation

### Via RouteWarden CLI
```bash
# From GitHub repository:
tcp-warden plugins install https://github.com/routewarden/plugins/echo_filter

# Or from local clone:
tcp-warden plugins install ../plugins/echo_filter
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  echo_filter:
    enabled: true
    source: "https://github.com/routewarden/plugins/echo_filter"

services:
  echo-guard:
    listen: ":9999"
    upstream: "127.0.0.1:9998"
    protocol: "echo_filter"
    plugin_config:
      banned_keywords:
        - "EXPLOIT"
        - "DROP TABLE"
        - "MALWARE"
        - "RCE_TEST"
```
