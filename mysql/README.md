# RouteWarden MySQL & MariaDB Protocol Plugin

Standalone RouteWarden modular plugin for inspecting MySQL and MariaDB wire protocol traffic and defending database servers against brute-force password guessing, credential stuffing, and connection floods.

---

## Capabilities & Defenses

- **Handshake & Auth Parsing:** Inspects the initial server greeting handshake (Protocol v10), client authentication response, and server response packets.
- **Authentication Failure Detection:** Detects MySQL Error packet `0xFF` containing error code `1045` (`ER_ACCESS_DENIED_ERROR`) and SQLSTATE `28000`.
- **Auto-Ban & Tarpit:** Automatically bans malicious client IPs when authentication failures reach `ban_after_failures`, cutting off brute-force botnets at Layer 4.
- **SSL / TLS Capability:** Supports SSL request negotiation transparently without requiring database TLS private keys.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/mysql

# Or by short name
tcp-warden plugins install mysql
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  mysql:
    enabled: true
    source: "https://github.com/routewarden/plugins/mysql"

services:
  mysql-guard:
    listen: ":3307"
    upstream: "127.0.0.1:3306"
    protocol: "mysql"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    rate_limit:
      connections_per_minute: 60
      burst: 10
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero Database Changes)
Keep MySQL running on standard port `3306`. Redirect external traffic entering interface `eth0` to RouteWarden on port `3307`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 3306 traffic to RouteWarden port 3307
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 3306 redirect to :3307
```
> **Loopback Safety:** The `iifname "eth0"` filter guarantees that RouteWarden's upstream connections to `127.0.0.1:3306` over loopback (`lo`) are **never** redirected back to RouteWarden.

---

### Strategy 2: `iptables` Redirection (Zero Database Changes)
```bash
# Redirect incoming external traffic on port 3306 to RouteWarden port 3307
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 3306 -j REDIRECT --to-port 3307

# Persist rules across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:3306`:

1. **Reconfigure MySQL / MariaDB:**
   Edit `/etc/mysql/my.cnf` (or `/etc/mysql/mysql.conf.d/mysqld.cnf`):
   ```ini
   [mysqld]
   port = 3308                      # Move MySQL to internal port
   bind-address = 127.0.0.1         # Bind to loopback only to prevent bypass
   ```
2. **Restart MySQL:**
   ```bash
   sudo systemctl restart mysql     # or: sudo systemctl restart mariadb
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     mysql:
       listen: ":3306"
       upstream: "127.0.0.1:3308"
       protocol: "mysql"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run MySQL inside a private container network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "3306:3307"     # Public port 3306 -> RouteWarden 3307
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  mysql-backend:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: secretpassword
      MYSQL_DATABASE: appdb
    # Notice: NO host port publication! Only accessible via tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```
In `tcp-warden.yaml`:
```yaml
services:
  mysql:
    listen: ":3307"
    upstream: "mysql-backend:3306"
    protocol: "mysql"
```

---

## Client Connection Examples

```bash
# Standard MySQL CLI via proxy port
mysql -h 127.0.0.1 -P 3307 -u root -p appdb

# Connection URI
mysql://root:secretpassword@127.0.0.1:3307/appdb
```

---

## Attack Simulation & Verification

```bash
# 1. Attempt 3 logins with an invalid password
for i in {1..3}; do
  mysql -h 127.0.0.1 -P 3307 -u root -pwrongpassword -e "quit" 2>/dev/null || true
done

# 2. Verify connection is rejected or tarpitted
mysql -h 127.0.0.1 -P 3307 -u root -p

# 3. Inspect active bans in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
