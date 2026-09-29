# RouteWarden LDAP Protocol Plugin

Standalone RouteWarden modular plugin for inspecting LDAPv3 protocol traffic, protecting OpenLDAP, FreeIPA, and Active Directory servers from credential brute-force attacks, password spraying, and directory harvesting.

---

## Capabilities & Defenses

- **LDAPv3 Protocol Parsing:** Decodes ASN.1 BER-encoded LDAP message frames (`BindRequest`, `BindResponse`, `SearchRequest`).
- **Bind Authentication Failure Tracking:** Intercepts `BindResponse` messages with result code `49` (`invalidCredentials`) or `50` (`insufficientAccessRights`).
- **Auto-Ban & Tarpit:** Automatically bans IP addresses attempting automated LDAP password spraying before accounts get locked in Active Directory / LDAP.
- **Search Query Rate Limiting:** Enforces connection-level rate limits to mitigate directory harvesting and bulk extraction attempts.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/ldap

# Or by short name
tcp-warden plugins install ldap
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  ldap:
    enabled: true
    source: "https://github.com/routewarden/plugins/ldap"

services:
  ldap-guard:
    listen: ":1390"
    upstream: "127.0.0.1:389"
    protocol: "ldap"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    rate_limit:
      connections_per_minute: 60
      burst: 10
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero LDAP Server Changes)
Keep OpenLDAP running on standard port `389`. Divert external traffic on `eth0` to RouteWarden on port `1390`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 389 traffic to RouteWarden port 1390
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 389 redirect to :1390
```

---

### Strategy 2: `iptables` Redirection (Zero LDAP Server Changes)
```bash
# Redirect incoming external traffic on port 389 to RouteWarden port 1390
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 389 -j REDIRECT --to-port 1390

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:389`:

1. **Reconfigure OpenLDAP (slapd):**
   In `/etc/default/slapd`:
   ```text
   SLAPD_SERVICES="ldap://127.0.0.1:3890/"   # Move slapd to an internal port on loopback
   ```
2. **Restart slapd:**
   ```bash
   sudo systemctl restart slapd
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     ldap:
       listen: ":389"
       upstream: "127.0.0.1:3890"
       protocol: "ldap"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run OpenLDAP inside a private container network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "389:1390"      # Public port 389 -> RouteWarden 1390
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  ldap-backend:
    image: osixia/openldap:latest
    environment:
      LDAP_ORGANISATION: "RouteWarden"
      LDAP_ROOTPASS: "secretpassword"
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
  ldap:
    listen: ":1390"
    upstream: "ldap-backend:389"
    protocol: "ldap"
```

---

## Client Connection Examples

```bash
# ldapsearch via proxy port
ldapsearch -H ldap://localhost:1390 -x -D "cn=admin,dc=example,dc=org" -w secretpassword -b "dc=example,dc=org"

# Example Python ldap3 client
from ldap3 import Server, Connection, SIMPLE
server = Server('localhost', port=1390)
conn = Connection(server, 'cn=admin,dc=example,dc=org', 'secretpassword', authentication=SIMPLE)
conn.bind()
```

---

## Attack Simulation & Verification

```bash
# 1. Attempt 3 failed binds with wrong credentials
for i in {1..3}; do
  ldapsearch -H ldap://localhost:1390 -x -D "cn=admin,dc=example,dc=org" -w wrongpass -b "dc=example,dc=org" 2>/dev/null || true
done

# 2. Layer 4 ban triggers — connection refused
ldapsearch -H ldap://localhost:1390 -x -b "dc=example,dc=org"

# 3. View active ban in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
