# RouteWarden FTP Protocol Plugin

Standalone RouteWarden modular plugin for inspecting FTP control connections (RFC 959), defending vsftpd, ProFTPD, and Pure-FTPd servers from automated credential brute-force attacks, anonymous probing, and dictionary attacks.

---

## Capabilities & Defenses

- **RFC 959 Protocol Inspection:** Intercepts client commands (`USER`, `PASS`, `AUTH TLS`, `QUIT`) and server status replies on the control channel.
- **Authentication Failure Detection:** Intercepts status code `530` (`530 Login incorrect` or `530 User cannot log in`).
- **AUTH TLS Handover Support:** Transparently permits secure TLS upgrades on the control connection.
- **Auto-Ban & Tarpit:** Automatically bans malicious client IPs after `ban_after_failures`, cutting off credential stuffing scanners.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/ftp

# Or by short name
tcp-warden plugins install ftp
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  ftp:
    enabled: true
    source: "https://github.com/routewarden/plugins/ftp"

services:
  ftp-guard:
    listen: ":2121"
    upstream: "127.0.0.1:21"
    protocol: "ftp"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    rate_limit:
      connections_per_minute: 30
      burst: 5
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero FTP Server Changes)
Keep vsftpd listening on standard port `21`. Divert external traffic on `eth0` to RouteWarden on port `2121`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 21 traffic to RouteWarden port 2121
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 21 redirect to :2121
```

---

### Strategy 2: `iptables` Redirection (Zero FTP Server Changes)
```bash
# Redirect incoming external traffic on port 21 to RouteWarden port 2121
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 21 -j REDIRECT --to-port 2121

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:21`:

1. **Reconfigure vsftpd:**
   Edit `/etc/vsftpd.conf`:
   ```text
   listen_port=2122             # Move vsftpd to an internal port
   listen_address=127.0.0.1     # Bind to loopback only to prevent direct access
   ```
2. **Restart vsftpd:**
   ```bash
   sudo systemctl restart vsftpd
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     ftp:
       listen: ":21"
       upstream: "127.0.0.1:2122"
       protocol: "ftp"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run an FTP server container inside a private network without publishing its control port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "21:2121"       # Public port 21 -> RouteWarden 2121
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  ftp-backend:
    image: fauria/vsftpd
    environment:
      FTP_USER: ftpuser
      FTP_PASS: secretpassword
    # Notice: NO port 21 exposed directly to host! Only accessible via tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```
In `tcp-warden.yaml`:
```yaml
services:
  ftp:
    listen: ":2121"
    upstream: "ftp-backend:21"
    protocol: "ftp"
```

---

## Client Connection Examples

```bash
# Standard curl / ftp via proxy port
curl -u ftpuser:secretpassword ftp://localhost:2121/

# lftp client
lftp -u ftpuser,secretpassword -p 2121 localhost
```

---

## Attack Simulation & Verification

```bash
# 1. Attempt 3 invalid logins
for i in {1..3}; do
  curl -u ftpuser:wrongpass ftp://localhost:2121/ 2>/dev/null || true
done

# 2. Connection is blocked at Layer 4:
curl ftp://localhost:2121/
# Output: curl: (7) Failed to connect to localhost port 2121: Connection refused

# 3. View active ban in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
