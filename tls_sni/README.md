# RouteWarden TLS SNI Domain Inspection & Routing Plugin

Standalone RouteWarden modular plugin for zero-decryption TLS ClientHello inspection, extracting Server Name Indication (SNI) hostnames, and enforcing domain allow/deny access control or SNI-based routing without needing TLS certificates or private keys.

---

## Capabilities & Defenses

- **Zero-Decryption SNI Inspection:** Parses the TLS ClientHello handshake packet (TLS 1.0, 1.1, 1.2, and 1.3), extracting the Server Name Indication extension without terminating or decrypting the TLS session.
- **Domain Allow & Deny Lists:** Enforces strict domain pattern matching (including wildcard subdomains like `*.example.com`).
- **Direct Drop on Unauthorized Domains:** Instantly resets or drops connections targeting unauthorized, unmapped, or malicious hostnames before backend certificates are exposed.
- **Privacy & Compliance:** Operates purely on Layer 4 TLS handshake metadata, satisfying strict zero-knowledge end-to-end encryption compliance.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/tls_sni

# Or by short name
tcp-warden plugins install tls_sni
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  tls_sni:
    enabled: true
    source: "https://github.com/routewarden/plugins/tls_sni"

services:
  tls-sni-guard:
    listen: ":8443"
    upstream: "127.0.0.1:443"
    protocol: "tls"
    rate_limit:
      connections_per_minute: 120
      burst: 20
    plugin_config:
      allowed_domains:
        - "*.example.com"
        - "api.company.internal"
      blocked_domains:
        - "*.malware.example"
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero Web Server Changes)
Keep your HTTPS server (Traefik, Nginx, Caddy) listening on port `443`. Divert external traffic on `eth0` to RouteWarden on port `8443`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 443 traffic to RouteWarden port 8443
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 443 redirect to :8443
```

---

### Strategy 2: `iptables` Redirection (Zero Web Server Changes)
```bash
# Redirect incoming external traffic on port 443 to RouteWarden port 8443
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8443

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:443`:

1. **Reconfigure Nginx / Traefik / Caddy:**
   Change the HTTPS listener from `:443` to an internal loopback port e.g. `127.0.0.1:8444`.
2. **Reload Web Server:**
   ```bash
   sudo systemctl reload nginx
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     tls:
       listen: ":443"
       upstream: "127.0.0.1:8444"
       protocol: "tls"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run your HTTPS reverse proxy or backend on a private network without publishing port 443:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "443:8443"       # Public port 443 -> RouteWarden 8443
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  web-gateway:
    image: traefik:v3.1
    # Notice: NO port 443 exposed directly to host! Only accessible via tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```
In `tcp-warden.yaml`:
```yaml
services:
  tls:
    listen: ":8443"
    upstream: "web-gateway:443"
    protocol: "tls"
```

---

## Client Connection Examples

```bash
# Legitimate SNI request passes through:
curl -kv --resolve app.example.com:8443:127.0.0.1 https://app.example.com:8443/

# Blocked SNI domain is dropped:
curl -kv --resolve forbidden.malware.example:8443:127.0.0.1 https://forbidden.malware.example:8443/
# Output: OpenSSL SSL_connect: Connection reset by peer
```
