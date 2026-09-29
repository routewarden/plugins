# RouteWarden PostgreSQL Protocol Plugin

Standalone RouteWarden modular plugin for inspecting PostgreSQL wire protocol traffic and defending database clusters against authentication brute-force, credential stuffing, and unauthorized connection floods.

---

## Capabilities & Defenses

- **Wire Protocol Parsing:** Parses PostgreSQL startup packets (`SSLRequest`, `StartupMessage`, `AuthenticationOk`, `AuthenticationMD5Password`, `AuthenticationSASL`, `ErrorResponse`).
- **Authentication Failure Tracking:** Intercepts `ErrorResponse` packets with SQLSTATE `28P01` (invalid password) or `28000` (invalid authorization specification).
- **Auto-Ban & Tarpit:** Automatically bans malicious IPs after reaching `ban_after_failures` attempts, terminating connections immediately or delaying them via Layer 4 tarpit.
- **SSL / TLS Negotiation:** Transparently relays SSL negotiation handshakes without terminating TLS or requiring server private keys.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/postgres

# Or by short name
tcp-warden plugins install postgres
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  postgres:
    enabled: true
    source: "https://github.com/routewarden/plugins/postgres"

services:
  postgres-guard:
    listen: ":5433"
    upstream: "127.0.0.1:5432"
    protocol: "postgres"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    rate_limit:
      connections_per_minute: 60
      burst: 10
```

---

## Network Integration Strategies

Choose the integration method that fits your environment:

### Strategy 1: `nftables` Redirection (Recommended: Zero Database Changes)
Keep PostgreSQL listening on standard port `5432` on localhost. Route external client traffic entering `eth0` to RouteWarden on port `5433`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Create the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 5432 traffic on eth0 to RouteWarden on port 5433
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 5432 redirect to :5433
```
> **Loopback Safety:** The `iifname "eth0"` condition ensures that when RouteWarden connects to `127.0.0.1:5432`, the packet traverses the loopback interface (`lo`) and is **never** redirected back to RouteWarden.

---

### Strategy 2: `iptables` Redirection (Zero Database Changes)
```bash
# Redirect incoming external traffic on port 5432 to RouteWarden port 5433
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 5432 -j REDIRECT --to-port 5433
```

To persist across reboots:
```bash
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you want RouteWarden to bind directly to `:5432`:

1. **Reconfigure PostgreSQL:**
   Edit `/etc/postgresql/<version>/main/postgresql.conf`:
   ```text
   port = 5433                      # Move PostgreSQL to internal port
   listen_addresses = '127.0.0.1'   # Bind to loopback only to prevent bypass
   ```
2. **Restart PostgreSQL:**
   ```bash
   sudo systemctl restart postgresql
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     postgres:
       listen: ":5432"
       upstream: "127.0.0.1:5433"
       protocol: "postgres"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run PostgreSQL on an internal Docker network with **no published ports**. RouteWarden publishes port `5432` and forwards traffic over Docker DNS:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "5432:5433"     # Public port 5432 -> RouteWarden 5433
      - "9091:9091"     # Management API
    environment:
      - ROUTEWARDEN_CONFIG=/etc/routewarden/tcp-warden.yaml
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  postgres-backend:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: appuser
      POSTGRES_PASSWORD: secretpassword
      POSTGRES_DB: appdb
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
  postgres:
    listen: ":5433"
    upstream: "postgres-backend:5432"
    protocol: "postgres"
```

---

## Client Connection Examples

Connecting applications work transparently without code modifications:

```bash
# Standard CLI client via proxy port
psql -h localhost -p 5433 -U appuser -d appdb

# Connection URI
postgresql://appuser:secretpassword@localhost:5433/appdb?sslmode=prefer
```

---

## Attack Simulation & Verification

Trigger an automated ban by simulating brute-force authentication failures:

```bash
# 1. Attempt 3 logins with wrong password
for i in {1..3}; do
  PGPASSWORD=wrongpassword psql -h localhost -p 5433 -U appuser -d appdb -c '\q'
done

# 2. Next attempt will be blocked or tarpitted immediately
psql -h localhost -p 5433 -U appuser -d appdb

# 3. Check active bans in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
