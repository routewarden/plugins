# RouteWarden Redis Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Redis RESP wire protocol traffic, enforcing command-level authorization, and defending Redis caches against brute-force attacks and destructive commands.

---

## Capabilities & Defenses

- **RESP Protocol Inspection:** Fully parses the Redis Serialization Protocol (RESP2 / RESP3), analyzing command names and arguments in real time.
- **Dangerous Command Blocking:** Blocks unauthorized or administrative commands (`FLUSHALL`, `FLUSHDB`, `CONFIG`, `SHUTDOWN`, `DEBUG`, `KEYS`, `EVAL`) without altering Redis configuration.
- **Authentication Failure Detection:** Detects Redis error responses (`-WRONGPASS invalid username-password pair`, `-ERR invalid password`, `-NOAUTH Authentication required`).
- **Auto-Ban & Tarpit:** Automatically bans malicious client IPs when authentication failures exceed `ban_after_failures` or when forbidden administrative commands are attempted.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/redis

# Or by short name
tcp-warden plugins install redis
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  redis:
    enabled: true
    source: "https://github.com/routewarden/plugins/redis"

services:
  redis-guard:
    listen: ":6380"
    upstream: "127.0.0.1:6379"
    protocol: "redis"
    max_auth_failures: 5
    ban_after_failures: 5
    ban_duration: "1h"
    rate_limit:
      connections_per_minute: 120
      burst: 20
    plugin_config:
      blocked_commands:
        - "FLUSHALL"
        - "FLUSHDB"
        - "CONFIG"
        - "SHUTDOWN"
        - "DEBUG"
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero Redis Changes)
Keep Redis running on standard port `6379`. Divert incoming external traffic on `eth0` to RouteWarden on port `6380`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 6379 traffic to RouteWarden port 6380
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 6379 redirect to :6380
```
> **Loopback Safety:** The `iifname "eth0"` match ensures that RouteWarden's upstream loopback connections to `127.0.0.1:6379` are **never** redirected back to RouteWarden.

---

### Strategy 2: `iptables` Redirection (Zero Redis Changes)
```bash
# Redirect incoming external traffic on port 6379 to RouteWarden port 6380
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 6379 -j REDIRECT --to-port 6380

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:6379`:

1. **Reconfigure Redis:**
   Edit `/etc/redis/redis.conf`:
   ```text
   port 6381                        # Move Redis to an internal port
   bind 127.0.0.1                   # Bind strictly to loopback to prevent bypass
   ```
2. **Restart Redis:**
   ```bash
   sudo systemctl restart redis-server   # or: redis
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     redis:
       listen: ":6379"
       upstream: "127.0.0.1:6381"
       protocol: "redis"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run Redis in a private container network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "6379:6380"     # Public port 6379 -> RouteWarden 6380
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  redis-backend:
    image: redis:7-alpine
    command: ["redis-server", "--requirepass", "secretpassword"]
    # Notice: NO 'ports:' section! Only reachable via tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```
In `tcp-warden.yaml`:
```yaml
services:
  redis:
    listen: ":6380"
    upstream: "redis-backend:6379"
    protocol: "redis"
```

---

## Client Connection Examples

```bash
# redis-cli via proxy port
redis-cli -p 6380 -a secretpassword

# Connection URI
redis://:secretpassword@localhost:6380/0
```

---

## Attack Simulation & Verification

### 1. Test Blocked Command Filtering
```bash
# Attempt to run a blocked command through the proxy:
redis-cli -p 6380 FLUSHALL
# Output: (error) ERR command 'FLUSHALL' blocked by RouteWarden policy
```

### 2. Test Auth Brute-Force Auto-Ban
```bash
# Attempt 5 incorrect passwords
for i in {1..5}; do
  redis-cli -p 6380 -a wrongpass ping 2>/dev/null || true
done

# The 6th attempt is blocked at Layer 4:
redis-cli -p 6380 ping
# Output: Could not connect to Redis at 127.0.0.1:6380: Connection refused

# Check ban list in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
