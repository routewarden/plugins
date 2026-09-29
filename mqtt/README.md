# RouteWarden MQTT IoT Broker Protocol Plugin

Standalone RouteWarden modular plugin for inspecting MQTT wire protocol traffic (MQTT 3.1.1 and 5.0), protecting Mosquitto, EMQX, and HiveMQ brokers from rogue IoT client impersonation, malicious scanners (e.g., Shodan bots), and connection flooding.

---

## Capabilities & Defenses

- **MQTT CONNECT Packet Inspection:** Decodes the MQTT fixed header and variable header in the `CONNECT` control packet.
- **ClientID Authorization & Filtering:** Blocks suspicious client ID prefixes (e.g. `bot-`, `scanner-`, `shodan`, `masscan`) and drops abnormally long client IDs exceeding `max_client_id_len`.
- **Protocol Anomaly Mitigation:** Rejects malformed variable headers or unexpected reserved flag bits.
- **Auto-Ban & Tarpit:** Automatically bans IP addresses attempting unauthorized client ID patterns or connection flooding.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/mqtt

# Or by short name
tcp-warden plugins install mqtt
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  mqtt:
    enabled: true
    source: "https://github.com/routewarden/plugins/mqtt"

services:
  mqtt-guard:
    listen: ":1884"
    upstream: "127.0.0.1:1883"
    protocol: "mqtt"
    rate_limit:
      connections_per_minute: 60
      burst: 10
    plugin_config:
      blocked_client_id_prefixes:
        - "bot-"
        - "scanner-"
        - "shodan"
      max_client_id_len: 64
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero Broker Changes)
Keep Mosquitto / EMQX running on standard port `1883`. Divert external traffic on `eth0` to RouteWarden on port `1884`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 1883 traffic to RouteWarden port 1884
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 1883 redirect to :1884
```

---

### Strategy 2: `iptables` Redirection (Zero Broker Changes)
```bash
# Redirect incoming external traffic on port 1883 to RouteWarden port 1884
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 1883 -j REDIRECT --to-port 1884

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:1883`:

1. **Reconfigure Mosquitto:**
   Edit `/etc/mosquitto/mosquitto.conf`:
   ```text
   listener 1885 127.0.0.1      # Move Mosquitto to an internal loopback port
   ```
2. **Restart Mosquitto:**
   ```bash
   sudo systemctl restart mosquitto
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     mqtt:
       listen: ":1883"
       upstream: "127.0.0.1:1885"
       protocol: "mqtt"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run Mosquitto on a private container network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "1883:1884"     # Public port 1883 -> RouteWarden 1884
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  mosquitto-backend:
    image: eclipse-mosquitto:2
    # Notice: NO port 1883 exposed directly to host! Only accessible via tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```
In `tcp-warden.yaml`:
```yaml
services:
  mqtt:
    listen: ":1884"
    upstream: "mosquitto-backend:1883"
    protocol: "mqtt"
```

---

## Client Connection Examples

```bash
# Legitimate MQTT client connection via proxy port
mosquitto_sub -h localhost -p 1884 -i "sensor-livingroom-01" -t "sensors/#"

# Publish message via proxy port
mosquitto_pub -h localhost -p 1884 -i "sensor-publisher-01" -t "sensors/temp" -m "22.5"
```

---

## Attack Simulation & Verification

```bash
# 1. Attempt connection with a blocked scanner ClientID:
mosquitto_sub -h localhost -p 1884 -i "shodan-scanner-test" -t "#"
# Output: Connection dropped / Connection refused

# 2. View active ban in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
