# RouteWarden Memcached Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Memcached ASCII and binary wire protocol traffic, blocking dangerous administrative operations (such as `flush_all` or `shutdown`), and protecting cache servers from unauthorized manipulation and DDoS reflection attacks.

---

## Capabilities & Defenses

- **Dual-Protocol Inspection:** Full decoding of both Memcached text (ASCII) protocol lines and binary protocol request/response headers.
- **Dangerous Command Blocking:** Intercepts and blocks cache destruction commands (`flush_all`, `shutdown`, `destroy`) without requiring authentication setup in legacy Memcached instances.
- **Amplification / Reflection Mitigation:** Limits payload size and connection burst rates to prevent open Memcached instances from participating in UDP/TCP reflection attacks.
- **Auto-Ban & Tarpit:** Automatically bans clients issuing forbidden commands or exceeding configured rate limits.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/memcached

# Or by short name
tcp-warden plugins install memcached
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  memcached:
    enabled: true
    source: "https://github.com/routewarden/plugins/memcached"

services:
  memcached-guard:
    listen: ":11212"
    upstream: "127.0.0.1:11211"
    protocol: "memcached"
    rate_limit:
      connections_per_minute: 120
      burst: 20
    ban_duration: "1h"
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero Memcached Changes)
Keep Memcached listening on default port `11211`. Divert external traffic on `eth0` to RouteWarden on port `11212`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 11211 traffic to RouteWarden port 11212
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 11211 redirect to :11212
```

---

### Strategy 2: `iptables` Redirection (Zero Memcached Changes)
```bash
# Redirect incoming external traffic on port 11211 to RouteWarden port 11212
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 11211 -j REDIRECT --to-port 11212

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:11211`:

1. **Reconfigure Memcached:**
   Edit `/etc/memcached.conf`:
   ```text
   -p 11213                     # Move Memcached to an internal port
   -l 127.0.0.1                 # Bind to loopback only to prevent direct access
   ```
2. **Restart Memcached:**
   ```bash
   sudo systemctl restart memcached
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     memcached:
       listen: ":11211"
       upstream: "127.0.0.1:11213"
       protocol: "memcached"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run Memcached in an isolated container network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "11211:11212"   # Public port 11211 -> RouteWarden 11212
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  memcached-backend:
    image: memcached:alpine
    # Notice: NO host ports exposed! Only accessible via tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```
In `tcp-warden.yaml`:
```yaml
services:
  memcached:
    listen: ":11212"
    upstream: "memcached-backend:11211"
    protocol: "memcached"
```

---

## Client Connection Examples

```bash
# Test with nc / telnet via proxy port
echo -e "stats\r\nquit\r\n" | nc localhost 11212

# Example Python pymemcache client
from pymemcache.client.base import Client
client = Client(('localhost', 11212))
client.set('key', 'value')
```

---

## Attack Simulation & Verification

```bash
# 1. Attempt dangerous 'flush_all' command
echo -e "flush_all\r\n" | nc localhost 11212
# Output: CLIENT_ERROR command 'flush_all' blocked by RouteWarden policy

# 2. Check active bans in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
