# RouteWarden AMQP 0-9-1 (RabbitMQ) Protocol Plugin

Standalone RouteWarden modular plugin for inspecting AMQP 0-9-1 wire protocol traffic, protecting RabbitMQ brokers from authentication brute-force attacks, vhost unauthorized probing, and connection flooding.

---

## Capabilities & Defenses

- **Protocol Handshake Verification:** Inspects the AMQP protocol header (`AMQP\x00\x00\x09\x01`) and `connection.start` / `connection.start-ok` frames.
- **Authentication Failure Detection:** Intercepts `connection.close` frames carrying reply-code `403` (`ACCESS_REFUSED`), identifying failed user authentication or forbidden vhost access.
- **Auto-Ban & Tarpit:** Automatically bans offending client IPs after `ban_after_failures`, stopping distributed password guessing on message brokers.
- **Connection Rate Limiting:** Enforces connection rate limits and burst caps to prevent broker connection table exhaustion.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/amqp

# Or by short name
tcp-warden plugins install amqp
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  amqp:
    enabled: true
    source: "https://github.com/routewarden/plugins/amqp"

services:
  amqp-guard:
    listen: ":5673"
    upstream: "127.0.0.1:5672"
    protocol: "amqp"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    rate_limit:
      connections_per_minute: 60
      burst: 10
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero RabbitMQ Changes)
Keep RabbitMQ running on standard port `5672`. Divert external traffic on `eth0` to RouteWarden on port `5673`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 5672 traffic to RouteWarden port 5673
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 5672 redirect to :5673
```

---

### Strategy 2: `iptables` Redirection (Zero RabbitMQ Changes)
```bash
# Redirect incoming external traffic on port 5672 to RouteWarden port 5673
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 5672 -j REDIRECT --to-port 5673

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:5672`:

1. **Reconfigure RabbitMQ:**
   Edit `/etc/rabbitmq/rabbitmq.conf`:
   ```text
   listeners.tcp.default = 127.0.0.1:5674   # Bind to loopback on an internal port
   ```
2. **Restart RabbitMQ:**
   ```bash
   sudo systemctl restart rabbitmq-server
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     rabbitmq:
       listen: ":5672"
       upstream: "127.0.0.1:5674"
       protocol: "amqp"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run RabbitMQ on a private container network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "5672:5673"     # Public port 5672 -> RouteWarden 5673
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  rabbitmq-backend:
    image: rabbitmq:3-management-alpine
    environment:
      RABBITMQ_DEFAULT_USER: appuser
      RABBITMQ_DEFAULT_PASS: secretpassword
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
  amqp:
    listen: ":5673"
    upstream: "rabbitmq-backend:5672"
    protocol: "amqp"
```

---

## Client Connection Examples

```bash
# Standard AMQP URI via proxy port
amqp://appuser:secretpassword@localhost:5673//

# Example Python pika client
import pika
credentials = pika.PlainCredentials('appuser', 'secretpassword')
params = pika.ConnectionParameters('localhost', 5673, '/', credentials)
connection = pika.BlockingConnection(params)
```

---

## Attack Simulation & Verification

```bash
# 1. Attempt 3 logins with an invalid password using Python / amqp-publish
for i in {1..3}; do
  python3 -c "import pika; pika.BlockingConnection(pika.ConnectionParameters('localhost', 5673, '/', pika.PlainCredentials('appuser', 'wrongpass')))" 2>/dev/null || true
done

# 2. Connection is rejected at Layer 4:
python3 -c "import pika; pika.BlockingConnection(pika.ConnectionParameters('localhost', 5673, '/', pika.PlainCredentials('appuser', 'secretpassword')))"
# Output: Connection refused / Timeout

# 3. View active ban in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
