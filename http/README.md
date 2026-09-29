# RouteWarden HTTP Protocol Plugin

Standalone RouteWarden modular plugin for inspecting plain HTTP/1.x traffic at Layer 4/7, blocking vulnerability scanners (e.g. sqlmap, nikto, masscan), filtering sensitive paths (`.env`, `.git`, `.bak`), and preventing host header injection before traffic reaches your web server.

---

## Capabilities & Defenses

- **HTTP/1.x Wire Parsing:** Inspects request line (`METHOD`, `URI`, `HTTP/1.1`) and initial header block.
- **Scanner User-Agent Blocking:** Immediately drops or tarpits automated scanners matching regex patterns (`sqlmap`, `nikto`, `acunetix`, `masscan`, `nmap`).
- **Sensitive Path & File Probing Protection:** Blocks path traversal and dotfile probes targeting `/.env`, `/.git`, `/wp-admin`, `.bak`, `.sql`.
- **Auto-Ban & Tarpit:** Automatically bans IPs generating repeated malicious HTTP probes.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/http

# Or by short name
tcp-warden plugins install http
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  http:
    enabled: true
    source: "https://github.com/routewarden/plugins/http"

services:
  web-guard:
    listen: ":8081"
    upstream: "127.0.0.1:80"
    protocol: "http"
    rate_limit:
      connections_per_minute: 120
      burst: 20
    ban_after_failures: 3
    ban_duration: "1h"
    plugin_config:
      blocked_paths:
        - "^/admin(/.*)?$"
        - "\\.(env|git|bak|sql)$"
      blocked_headers:
        User-Agent: "(?i)(sqlmap|nikto|acunetix|masscan)"
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero Web Server Changes)
Keep Nginx / Apache / Caddy listening on standard port `80`. Divert external traffic on `eth0` to RouteWarden on port `8081`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 80 traffic to RouteWarden port 8081
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 80 redirect to :8081
```

---

### Strategy 2: `iptables` Redirection (Zero Web Server Changes)
```bash
# Redirect incoming external traffic on port 80 to RouteWarden port 8081
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8081

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:80`:

1. **Reconfigure Nginx / Apache / Caddy:**
   In Nginx (`/etc/nginx/sites-available/default`):
   ```nginx
   server {
       listen 127.0.0.1:8082;   # Move to internal loopback port
       server_name example.com;
       ...
   }
   ```
2. **Reload Web Server:**
   ```bash
   sudo systemctl reload nginx
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     web:
       listen: ":80"
       upstream: "127.0.0.1:8082"
       protocol: "http"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run the web application on a private Docker bridge network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "80:8081"       # Public port 80 -> RouteWarden 8081
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  web-backend:
    image: nginx:alpine
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
  http:
    listen: ":8081"
    upstream: "web-backend:80"
    protocol: "http"
```

---

## Client Connection Examples

```bash
# Legitimate request passes through transparently:
curl http://localhost:8081/

# Test with curl via proxy port
curl -i http://localhost:8081/
```

---

## Attack Simulation & Verification

```bash
# 1. Probe a blocked sensitive path
curl -i http://localhost:8081/.env
# Output: 403 Forbidden / Connection dropped

# 2. Probe with a scanner User-Agent
curl -i -A "sqlmap/1.5" http://localhost:8081/
# Output: Connection reset / 403 Forbidden

# 3. Check active bans in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
