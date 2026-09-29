# RouteWarden SMTP Mail Transfer Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Simple Mail Transfer Protocol (SMTP) traffic, defending mail transfer agents (Postfix, Exim, Sendmail) against spam dictionary attacks, open relay probing, and authentication brute-force attacks.

---

## Capabilities & Defenses

- **SMTP Command State Tracking:** Parses SMTP commands (`HELO`, `EHLO`, `MAIL FROM`, `RCPT TO`, `AUTH`, `STARTTLS`, `DATA`, `QUIT`).
- **Sender & Recipient Enforcement:** Blocks unauthorized sender domains (e.g. disposable mail services, known spam domains) and enforces per-message recipient limits.
- **Authentication Failure Detection:** Intercepts `535 Authentication credentials invalid` replies and tracks authentication failure rates.
- **Auto-Ban & Tarpit:** Automatically bans abusive client IPs reaching `ban_after_failures`, cutting off spam botnets at Layer 4.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/smtp

# Or by short name
tcp-warden plugins install smtp
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  smtp:
    enabled: true
    source: "https://github.com/routewarden/plugins/smtp"

services:
  smtp-guard:
    listen: ":2525"
    upstream: "127.0.0.1:25"
    protocol: "smtp"
    rate_limit:
      connections_per_minute: 30
      burst: 10
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    plugin_config:
      max_recipients: 10
      blocked_sender_domains:
        - "*.tempmail.com"
        - "spam.org"
      require_starttls: false
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero Postfix Changes)
Keep Postfix listening on standard port `25`. Divert external traffic on `eth0` to RouteWarden on port `2525`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 25 traffic to RouteWarden port 2525
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 25 redirect to :2525
```

---

### Strategy 2: `iptables` Redirection (Zero Postfix Changes)
```bash
# Redirect incoming external traffic on port 25 to RouteWarden port 2525
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 25 -j REDIRECT --to-port 2525

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:25`:

1. **Reconfigure Postfix:**
   Edit `/etc/postfix/master.cf`:
   ```text
   # Change standard smtp port to internal loopback port
   127.0.0.1:2526      inet  n       -       y       -       -       smtpd
   ```
2. **Restart Postfix:**
   ```bash
   sudo systemctl restart postfix
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     smtp:
       listen: ":25"
       upstream: "127.0.0.1:2526"
       protocol: "smtp"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run a mail server container on a private bridge network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "25:2525"       # Public port 25 -> RouteWarden 2525
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  mail-backend:
    image: mailserver/docker-mailserver:latest
    # Notice: NO port 25 exposed directly to host! Only accessible via tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```
In `tcp-warden.yaml`:
```yaml
services:
  smtp:
    listen: ":2525"
    upstream: "mail-backend:25"
    protocol: "smtp"
```

---

## Client Connection Examples

```bash
# Test with swaks or telnet via proxy port
swaks --server localhost --port 2525 --to user@example.com --from test@example.com

# Test EHLO via nc
echo -e "EHLO client.test\r\nQUIT\r\n" | nc localhost 2525
```

---

## Attack Simulation & Verification

```bash
# 1. Simulate 3 failed SMTP AUTH attempts
for i in {1..3}; do
  swaks --server localhost --port 2525 --auth-user testuser --auth-password wrongpass 2>/dev/null || true
done

# 2. Connection is rejected at Layer 4:
nc -zv localhost 2525
# Output: Connection refused

# 3. View active ban in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
