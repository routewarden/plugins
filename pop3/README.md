# RouteWarden POP3 Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Post Office Protocol (POP3) sessions, detecting authentication failures (`-ERR`), and protecting Dovecot, Courier, and Microsoft Exchange POP3 endpoints from brute-force dictionary attacks.

---

## Capabilities & Defenses

- **Command Line State Inspection:** Parses POP3 client commands (`USER`, `PASS`, `STLS`, `STAT`, `RETR`, `DELE`, `QUIT`).
- **Authentication Failure Detection:** Intercepts server `-ERR [AUTH]` responses on bad passwords or non-existent usernames.
- **Auto-Ban & Tarpit:** Automatically bans abusive client IPs reaching `ban_after_failures`, cutting off automated credential stuffing bots.
- **STLS TLS Handover Support:** Transparently bridges TLS upgrade handshakes when `STLS` is issued.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/pop3

# Or by short name
tcp-warden plugins install pop3
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  pop3:
    enabled: true
    source: "https://github.com/routewarden/plugins/pop3"

services:
  pop3-guard:
    listen: ":1110"
    upstream: "127.0.0.1:110"
    protocol: "pop3"
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
Keep Dovecot listening on standard port `110`. Divert external traffic on `eth0` to RouteWarden on port `1110`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 110 traffic to RouteWarden port 1110
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 110 redirect to :1110
```

---

### Strategy 2: `iptables` Redirection (Zero Dovecot Changes)
```bash
# Redirect incoming external traffic on port 110 to RouteWarden port 1110
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 110 -j REDIRECT --to-port 1110

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:110`:

1. **Reconfigure Dovecot:**
   Edit `/etc/dovecot/conf.d/10-master.conf`:
   ```text
   service pop3-login {
     inet_listener pop3 {
       port = 1111
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
     pop3:
       listen: ":110"
       upstream: "127.0.0.1:1111"
       protocol: "pop3"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run a mail server container on a private bridge network without publishing port 110 to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "110:1110"      # Public port 110 -> RouteWarden 1110
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  dovecot-backend:
    image: mailserver/docker-mailserver
    # Notice: NO port 110 exposed directly to host! Only accessible via tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```
In `tcp-warden.yaml`:
```yaml
services:
  pop3:
    listen: ":1110"
    upstream: "dovecot-backend:110"
    protocol: "pop3"
```

---

## Client Connection Examples

```bash
# Test with nc / telnet via proxy port:
nc localhost 1110
# Type: USER testuser
# Type: PASS secretpassword
# Type: QUIT
```

---

## Attack Simulation & Verification

```bash
# 1. Attempt 3 failed logins via python / nc
for i in {1..3}; do
  echo -e "USER testuser\r\nPASS wrongpass\r\nQUIT\r\n" | nc localhost 1110 2>/dev/null || true
done

# 2. Connection is rejected at Layer 4:
nc -zv localhost 1110
# Output: Connection refused

# 3. View active ban in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
