# RouteWarden IMAP Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Internet Message Access Protocol (IMAP4rev1) sessions, detecting authentication failures (`NO [AUTHENTICATIONFAILED]`), and protecting Dovecot, Cyrus, and Courier IMAP mailboxes from brute-force password guessing.

---

## Capabilities & Defenses

- **Command Line State Inspection:** Parses IMAP client commands (`LOGIN`, `AUTHENTICATE`, `STARTTLS`, `SELECT`, `FETCH`, `LOGOUT`).
- **Authentication Failure Detection:** Intercepts tagged server `NO [AUTHENTICATIONFAILED]` or `BAD` responses.
- **Auto-Ban & Tarpit:** Automatically bans abusive client IPs reaching `ban_after_failures`, cutting off automated credential stuffing bots.
- **STARTTLS TLS Handover Support:** Transparently bridges TLS upgrade handshakes when `STARTTLS` is issued.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/imap

# Or by short name
tcp-warden plugins install imap
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  imap:
    enabled: true
    source: "https://github.com/routewarden/plugins/imap"

services:
  imap-guard:
    listen: ":1143"
    upstream: "127.0.0.1:143"
    protocol: "imap"
    rate_limit:
      connections_per_minute: 20
      burst: 5
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero Dovecot Changes)
Keep Dovecot listening on standard port `143`. Divert external traffic on `eth0` to RouteWarden on port `1143`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 143 traffic to RouteWarden port 1143
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 143 redirect to :1143
```

---

### Strategy 2: `iptables` Redirection (Zero Dovecot Changes)
```bash
# Redirect incoming external traffic on port 143 to RouteWarden port 1143
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 143 -j REDIRECT --to-port 1143

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:143`:

1. **Reconfigure Dovecot:**
   Edit `/etc/dovecot/conf.d/10-master.conf`:
   ```text
   service imap-login {
     inet_listener imap {
       port = 1144
       address = 127.0.0.1
     }
   }
   ```
2. **Restart Dovecot:**
   ```bash
   sudo systemctl restart dovecot
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     imap:
       listen: ":143"
       upstream: "127.0.0.1:1144"
       protocol: "imap"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run a mail server container on a private bridge network without publishing port 143 to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "143:1143"      # Public port 143 -> RouteWarden 1143
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  dovecot-backend:
    image: mailserver/docker-mailserver
    # Notice: NO port 143 exposed directly to host! Only accessible via tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```
In `tcp-warden.yaml`:
```yaml
services:
  imap:
    listen: ":1143"
    upstream: "dovecot-backend:143"
    protocol: "imap"
```

---

## Client Connection Examples

```bash
# Test with openssl s_client / nc via proxy port:
nc localhost 1143
# Type: a001 LOGIN testuser secretpassword
# Type: a002 LOGOUT
```

---

## Attack Simulation & Verification

```bash
# 1. Attempt 3 failed logins
for i in {1..3}; do
  echo -e "a001 LOGIN testuser wrongpass\r\na002 LOGOUT\r\n" | nc localhost 1143 2>/dev/null || true
done

# 2. Connection is rejected at Layer 4:
nc -zv localhost 1143
# Output: Connection refused

# 3. View active ban in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
