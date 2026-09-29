# RouteWarden MongoDB Protocol Plugin

Standalone RouteWarden modular plugin for inspecting MongoDB wire protocol traffic (OP_MSG / OP_QUERY) and defending database clusters against authentication brute-force, unauthorized commands, and connection floods.

---

## Capabilities & Defenses

- **Wire Protocol Inspection:** Decodes MongoDB wire protocol message headers and BSON documents (`OP_MSG`, `OP_QUERY`, `isMaster`/`hello` handshakes).
- **Authentication Failure Detection:** Detects BSON error responses containing code `18` (`AuthenticationFailed`), `11` (`UserNotFound`), or `334`.
- **Auto-Ban & Tarpit:** Automatically bans abusive client IPs reaching `ban_after_failures`, defending against rapid credential enumeration.
- **SSL / TLS Passthrough:** Supports TLS-wrapped MongoDB connections transparently.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/mongodb

# Or by short name
tcp-warden plugins install mongodb
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  mongodb:
    enabled: true
    source: "https://github.com/routewarden/plugins/mongodb"

services:
  mongodb-guard:
    listen: ":27018"
    upstream: "127.0.0.1:27017"
    protocol: "mongodb"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    rate_limit:
      connections_per_minute: 60
      burst: 10
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero MongoDB Changes)
Keep MongoDB running on default port `27017`. Redirect external client traffic entering `eth0` to RouteWarden on port `27018`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 27017 traffic to RouteWarden port 27018
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 27017 redirect to :27018
```
> **Loopback Safety:** The `iifname "eth0"` filter prevents RouteWarden's upstream connections to `127.0.0.1:27017` over loopback (`lo`) from being redirected back into itself.

---

### Strategy 2: `iptables` Redirection (Zero MongoDB Changes)
```bash
# Redirect incoming external traffic on port 27017 to RouteWarden port 27018
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 27017 -j REDIRECT --to-port 27018

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:27017`:

1. **Reconfigure MongoDB:**
   Edit `/etc/mongod.conf`:
   ```yaml
   net:
     port: 27019              # Move MongoDB to an internal port
     bindIp: 127.0.0.1        # Bind strictly to loopback to prevent direct access
   ```
2. **Restart MongoDB:**
   ```bash
   sudo systemctl restart mongod
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     mongodb:
       listen: ":27017"
       upstream: "127.0.0.1:27019"
       protocol: "mongodb"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run MongoDB inside a private container network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "27017:27018"   # Public port 27017 -> RouteWarden 27018
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  mongodb-backend:
    image: mongo:7.0
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: secretpassword
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
  mongodb:
    listen: ":27018"
    upstream: "mongodb-backend:27017"
    protocol: "mongodb"
```

---

## Client Connection Examples

```bash
# mongosh CLI via proxy port
mongosh --port 27018 -u admin -p secretpassword --authenticationDatabase admin

# Connection URI
mongodb://admin:secretpassword@localhost:27018/mydb?authSource=admin
```

---

## Attack Simulation & Verification

```bash
# 1. Attempt 3 logins with wrong password
for i in {1..3}; do
  mongosh --port 27018 -u admin -p wrongpass --authenticationDatabase admin --eval "db.stats()" 2>/dev/null || true
done

# 2. Connection is rejected at Layer 4
mongosh --port 27018

# 3. View active ban in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
