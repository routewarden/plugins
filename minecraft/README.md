# RouteWarden Minecraft Server Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Minecraft Java Edition Server List Ping (SLP) and handshake wire protocol packets, defending game servers (Paper, Spigot, Purpur, Fabric, Velocity) against Server List Ping DDoS attacks, bot join floods, and packet exploits.

---

## Capabilities & Defenses

- **SLP & Handshake Decoding:** Decodes Minecraft Java protocol VarInt lengths, packet IDs (`0x00` Handshake, `0x00` Status Request, `0x01` Status Ping), protocol versions, and server addresses.
- **Server List Ping DDoS Mitigation:** Throttles rapid status queries from botnets designed to exhaust server CPU and Netty event loops without logging in.
- **Bot Join Flood Protection:** Enforces strict connection-per-second limits before unauthenticated players can reach the game server's internal authentication thread.
- **Auto-Ban & Tarpit:** Automatically bans abusive scanner and bot IP addresses at Layer 4.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/minecraft

# Or by short name
tcp-warden plugins install minecraft
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  minecraft:
    enabled: true
    source: "https://github.com/routewarden/plugins/minecraft"

services:
  minecraft-guard:
    listen: ":25566"
    upstream: "127.0.0.1:25565"
    protocol: "minecraft"
    rate_limit:
      connections_per_minute: 60
      burst: 10
    ban_duration: "1h"
    plugin_config:
      max_connections_per_sec: 10
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero Game Server Changes)
Keep your Minecraft server running on standard port `25565`. Divert external traffic on `eth0` to RouteWarden on port `25566`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 25565 traffic to RouteWarden port 25566
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 25565 redirect to :25566
```

---

### Strategy 2: `iptables` Redirection (Zero Game Server Changes)
```bash
# Redirect incoming external traffic on port 25565 to RouteWarden port 25566
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 25565 -j REDIRECT --to-port 25566

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:25565`:

1. **Reconfigure Minecraft Server:**
   In `server.properties`:
   ```properties
   server-port=25567
   server-ip=127.0.0.1          # Bind strictly to loopback so players cannot bypass
   ```
2. **Restart Minecraft Server:**
   Restart your Paper/Velocity daemon.
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     minecraft:
       listen: ":25565"
       upstream: "127.0.0.1:25567"
       protocol: "minecraft"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run the game server in a private container network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "25565:25566"   # Public port 25565 -> RouteWarden 25566
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  minecraft-backend:
    image: itzg/minecraft-server
    environment:
      EULA: "TRUE"
    # Notice: NO port 25565 exposed directly to host! Only accessible via tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```
In `tcp-warden.yaml`:
```yaml
services:
  minecraft:
    listen: ":25566"
    upstream: "minecraft-backend:25565"
    protocol: "minecraft"
```

---

## Client Connection Examples

Connect the Minecraft client directly to the server:
- If using **`nftables`** or **Port Swap**: Connect to `yourserver.com` (default port 25565).
- If connecting directly to proxy port: Connect to `yourserver.com:25566`.
