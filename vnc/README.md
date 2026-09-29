# RouteWarden VNC / RFB Protocol Plugin

Standalone RouteWarden modular plugin for inspecting RFB (Remote Framebuffer) protocol traffic, protecting TigerVNC, TightVNC, and x11vnc servers from automated password brute-force and unauthorized remote desktop probes.

---

## Capabilities & Defenses

- **RFB Protocol Parsing:** Inspects the initial RFB protocol version exchange (`RFB 003.008\n`), security type negotiation, and authentication handshakes.
- **VNC Authentication Failure Tracking:** Intercepts `SecurityResult` messages returning failure status (`0x00000001` - auth failed).
- **Auto-Ban & Tarpit:** Automatically bans malicious scanners attempting automated VNC DES password dictionary attacks.
- **Connection Rate Limiting:** Enforces connection caps to prevent remote desktop denial of service.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/vnc

# Or by short name
tcp-warden plugins install vnc
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  vnc:
    enabled: true
    source: "https://github.com/routewarden/plugins/vnc"

services:
  vnc-guard:
    listen: ":5901"
    upstream: "127.0.0.1:5900"
    protocol: "vnc"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    rate_limit:
      connections_per_minute: 30
      burst: 5
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero VNC Changes)
Keep the VNC server listening on standard port `5900`. Divert external traffic on `eth0` to RouteWarden on port `5901`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 5900 traffic to RouteWarden port 5901
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 5900 redirect to :5901
```

---

### Strategy 2: `iptables` Redirection (Zero VNC Changes)
```bash
# Redirect incoming external traffic on port 5900 to RouteWarden port 5901
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 5900 -j REDIRECT --to-port 5901

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:5900`:

1. **Reconfigure VNC Server (e.g. x11vnc / tigervnc):**
   Start VNC bound to loopback on an alternate port e.g. `5902`:
   ```bash
   x11vnc -rfbport 5902 -localhost -display :0 ...
   ```
2. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     vnc:
       listen: ":5900"
       upstream: "127.0.0.1:5902"
       protocol: "vnc"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run a containerized VNC desktop environment inside a private network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "5900:5901"     # Public port 5900 -> RouteWarden 5901
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  vnc-backend:
    image: dorowu/ubuntu-desktop-lxde-vnc
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
  vnc:
    listen: ":5901"
    upstream: "vnc-backend:5900"
    protocol: "vnc"
```

---

## Client Connection Examples

```bash
# Standard vncviewer via proxy port
vncviewer localhost:5901
```

---

## Attack Simulation & Verification

```bash
# 1. Attempt 3 failed VNC connections using vncdo or vncdotool
for i in {1..3}; do
  vncdotool -s localhost::5901 -p wrongpassword type "test" 2>/dev/null || true
done

# 2. Connection is rejected at Layer 4:
vncviewer localhost:5901
# Output: Connection refused / Server dropped connection

# 3. View active ban in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
