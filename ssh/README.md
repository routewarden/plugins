# RouteWarden SSH Protocol Plugin

Standalone RouteWarden modular plugin for inspecting Secure Shell (SSH) protocol traffic, validating client protocol banners, rejecting obsolete SSH-1.x connections, and intercepting `SSH_MSG_USERAUTH_FAILURE` packets to automatically ban brute-force attackers.

---

## Capabilities & Defenses

- **Protocol Version Inspection:** Inspects client identification banners (`SSH-2.0-OpenSSH_...`) before granting access to the cryptographic key exchange.
- **SSH-1.x Mitigation:** Instantly terminates and rejects obsolete and vulnerable SSH-1.x client versions with an RFC-compliant disconnect packet.
- **Authentication Failure Detection:** Monitors the upstream packet stream for `SSH_MSG_USERAUTH_FAILURE` (message type 51) packets.
- **Auto-Ban & Tarpit:** Automatically bans abusive IP addresses after `ban_after_failures`, cutting off automated SSH password dictionary bots.

---

## Installation

### 1. Via RouteWarden CLI
```bash
# Install from official repository
tcp-warden plugins install https://github.com/routewarden/plugins/ssh

# Or by short name
tcp-warden plugins install ssh
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  ssh:
    enabled: true
    source: "https://github.com/routewarden/plugins/ssh"

services:
  ssh-guard:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    protocol: "ssh"
    rate_limit:
      connections_per_minute: 20
      burst: 5
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "2h"
    plugin_config:
      banner: "RouteWarden SSH Guard"
      max_auth_tries: 3
```

---

## Network Integration Strategies

### Strategy 1: `nftables` Redirection (Recommended: Zero sshd Changes)
Keep OpenSSH listening on standard port `22`. Divert external traffic on `eth0` to RouteWarden on port `2222`:

```bash
# 1. Create a NAT table
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external port 22 traffic to RouteWarden port 2222
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 22 redirect to :2222
```

---

### Strategy 2: `iptables` Redirection (Zero sshd Changes)
```bash
# Redirect incoming external traffic on port 22 to RouteWarden port 2222
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-port 2222

# Persist across reboots
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swap / Reverse Proxy (Requires Backend Changes)
If you prefer RouteWarden to bind directly to `:22`:

1. **Reconfigure OpenSSH:**
   Edit `/etc/ssh/sshd_config`:
   ```text
   Port 22222
   ListenAddress 127.0.0.1      # Bind strictly to loopback to prevent direct access
   ```
2. **Restart OpenSSH:**
   ```bash
   sudo systemctl restart sshd
   ```
3. **Configure RouteWarden:**
   In `tcp-warden.yaml`:
   ```yaml
   services:
     ssh:
       listen: ":22"
       upstream: "127.0.0.1:22222"
       protocol: "ssh"
   ```

---

### Strategy 4: Docker Compose Network Isolation (Zero Host Exposure)
Run OpenSSH inside a private container network without publishing its port to the host:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "22:2222"       # Public port 22 -> RouteWarden 2222
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  openssh-backend:
    image: linuxserver/openssh-server
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
  ssh:
    listen: ":2222"
    upstream: "openssh-backend:2222"
    protocol: "ssh"
```

---

## Client Connection Examples

```bash
# Direct SSH connection via proxy port
ssh -p 2222 user@localhost

# Or using ~/.ssh/config:
# Host myserver
#     HostName myserver.example.com
#     Port 2222
```

---

## Attack Simulation & Verification

```bash
# 1. Simulate 3 failed SSH logins
for i in {1..3}; do
  ssh -p 2222 -o PreferredAuthentications=password -o PubkeyAuthentication=no wronguser@localhost 2>/dev/null || true
done

# 2. Connection is rejected at Layer 4:
ssh -p 2222 user@localhost
# Output: ssh: connect to host localhost port 2222: Connection refused

# 3. View active ban in RouteWarden
tcp-warden banlist --api http://127.0.0.1:9091
```
