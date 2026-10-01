# RouteWarden Protocol & Filter Plugins

This repository hosts official modular protocol inspectors and stream filters for RouteWarden (including [tcp-warden](https://github.com/routewarden/tcp-warden)).

The core `tcp-warden` binary provides high-performance transparent Layer 4 TCP proxying, rate limiting, IP filtering, and geo-blocking (`generic`). All protocol-specific inspectors (`ssh`, `smtp`, `pop3`, `imap`, `postgres`, `mysql`, `redis`, `http`, `mongodb`, etc.) are distributed modularly from this repository, allowing users to install only what is required.

---

## Available Plugins

| Plugin | Protocol(s) | Default Port | Description | Integration Guide |
| :--- | :--- | :--- | :--- | :--- |
| **`ssh`** | `ssh` | `22` / `2222` | SSH protocol guard with banner validation, version checks, and `SSH_MSG_USERAUTH_FAILURE` brute-force detection | [Guide & Setup](./ssh) |
| **`smtp`** | `smtp`, `mail` | `25` / `2525` | SMTP mail transfer inspector with recipient limits, spam domain blocking, and auth tracking | [Guide & Setup](./smtp) |
| **`pop3`** | `pop3` | `110` / `1110` | POP3 mail retrieval inspector with auth brute-force tracking (`-ERR`) and STLS support | [Guide & Setup](./pop3) |
| **`imap`** | `imap` | `143` / `1143` | IMAP4rev1 mail retrieval inspector with tagged auth failure detection (`NO`/`BAD`) | [Guide & Setup](./imap) |
| **`generic`** | `tcp`, `generic`, `raw` | Any (`15432` / `5432`) | Generic Layer 4 transparent TCP proxy with rate limiting, geo-blocking, and CIDR filtering | [Guide & Setup](./generic) |
| **`ftp`** | `ftp` | `21` / `2121` | FTP control channel inspector (RFC 959) detecting brute-force credential stuffing | [Guide & Setup](./ftp) |
| **`tls_sni`** | `tls`, `sni`, `https` | `443` / `8443` | Zero-decryption TLS ClientHello SNI inspection and domain allow/deny routing | [Guide & Setup](./tls_sni) |
| **`postgres`** | `postgres`, `postgresql` | `5432` / `5433` | PostgreSQL wire protocol inspector with auth brute-force and credential stuffing mitigation | [Guide & Setup](./postgres) |
| **`mysql`** | `mysql`, `mariadb` | `3306` / `3307` | MySQL & MariaDB handshake and authentication failure inspector | [Guide & Setup](./mysql) |
| **`redis`** | `redis`, `resp` | `6379` / `6380` | Redis RESP command filtering (e.g. blocking `FLUSHALL`, `CONFIG`) and auth protection | [Guide & Setup](./redis) |
| **`mongodb`** | `mongodb`, `mongo` | `27017` / `27018` | MongoDB OP_MSG inspector detecting authentication codes 18/334 | [Guide & Setup](./mongodb) |
| **`memcached`** | `memcached` | `11211` / `11212` | Memcached ASCII/binary inspector with administrative command blocking (`flush_all`) | [Guide & Setup](./memcached) |
| **`amqp`** | `amqp`, `rabbitmq` | `5672` / `5673` | RabbitMQ AMQP 0-9-1 handshake validation and auth failure monitoring | [Guide & Setup](./amqp) |
| **`http`** | `http` | `80` / `8081` | HTTP/1.x scanner blocking (sqlmap, nikto) and sensitive path protection (`.env`, `.git`) | [Guide & Setup](./http) |
| **`ldap`** | `ldap` | `389` / `1390` | LDAPv3 BER-encoded bind failure tracking and directory harvesting defense | [Guide & Setup](./ldap) |
| **`vnc`** | `vnc`, `rfb` | `5900` / `5901` | VNC / RFB protocol inspector defending against automated remote desktop attacks | [Guide & Setup](./vnc) |
| **`mqtt`** | `mqtt` | `1883` / `1884` | MQTT IoT broker security inspector with ClientID authorization and scanner blocking | [Guide & Setup](./mqtt) |
| **`minecraft`** | `minecraft`, `mc` | `25565` / `25566` | Minecraft Java Server List Ping (SLP) DDoS and handshake flood protection | [Guide & Setup](./minecraft) |
| **`dns`** | `dns` | `53` / `53` (TCP/UDP) | DNS dual-transport guard with domain blocklists (exact/wildcard) and amplification attack defense | [Guide & Setup](./dns) |
| **`bittorrent`** | `bittorrent`, `bt` | `6881` / `6882` (TCP/UDP) | BitTorrent peer-wire, DHT, and uTP inspector with info-hash filtering, peer ID rules, and private tracker mode | [Guide & Setup](./bittorrent) |
| **`echo_filter`** | `echo`, `stream-filter` | `7000` / `7001` | Example stream filter plugin demonstrating real-time signature and keyword filtering | [Guide & Setup](./echo_filter) |

---

## Network Integration Architectures

RouteWarden sits in front of your backend services to inspect, rate-limit, and auto-ban malicious traffic. There are four primary integration patterns:

```text
Pattern A: nftables / iptables (Zero backend changes)
Client ──► [eth0 : Standard Port] ──(PREROUTING redirect)──► RouteWarden (:Proxy Port) ──► Backend (127.0.0.1:Standard Port)

Pattern B: Port Swapping / Reverse Proxy (Standard setup)
Client ──► [Standard Port] ──► RouteWarden ──► Backend (127.0.0.1:Internal Port)

Pattern C: Docker Network Isolation (Zero host exposure)
Client ──► [Host Port] ──► RouteWarden Container ──(Docker Bridge)──► Backend Container (NO host ports)
```

### Integration Trade-Off Comparison

| Method | Requires Backend Service Changes? | Requires Firewall Config? | Best For |
| :--- | :--- | :--- | :--- |
| **`nftables`** | **No** (Zero touch) | Yes (`nft add rule`) | Production bare-metal & Linux VMs (Debian 10+, Ubuntu 20.04+, RHEL 8+) |
| **`iptables`** | **No** (Zero touch) | Yes (`iptables -t nat`) | Legacy Linux hosts & cloud instances |
| **Direct Port Swap** | **Yes** (Move backend to loopback port) | No | Bare-metal where firewall redirection is disallowed |
| **Docker Isolation** | **No** (Zero touch) | No | Containerized stacks & Docker Compose environments |

---

### Strategy 1: `nftables` Redirection (Modern Linux Default)

With `nftables`, your backend service continues running on its default port on `127.0.0.1`. The kernel intercepts incoming traffic on your public network interface and redirects it to RouteWarden:

```bash
# 1. Create a NAT table (if not existing)
sudo nft add table ip routewarden_nat

# 2. Add the prerouting chain
sudo nft add chain ip routewarden_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'

# 3. Redirect external incoming traffic on standard port to RouteWarden proxy port
# Replace 'eth0' with your external interface and ports as appropriate:
sudo nft add rule ip routewarden_nat prerouting iifname "eth0" tcp dport 5432 redirect to :5433
```

> **Critical Rule (Loopback Safety):** Always specify `iifname "eth0"` (your external interface). Do **not** apply redirection to the loopback interface (`lo`). This ensures that RouteWarden's upstream connections to `127.0.0.1:5432` reach your backend service directly without creating an infinite connection loop.

---

### Strategy 2: `iptables` Redirection

```bash
# Redirect incoming external traffic on interface eth0:
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 5432 -j REDIRECT --to-port 5433

# Persist across reboots:
sudo netfilter-persistent save  # Debian / Ubuntu
```

---

### Strategy 3: Direct Port Swapping (Backend Config File Updates)

If you prefer RouteWarden to bind directly to standard ports without using firewall rules, you must update the backend service to release the port and listen on an internal loopback port:

| Service | Backend Configuration File | Configuration Setting to Change | Restart Command |
| :--- | :--- | :--- | :--- |
| **SSH** | `/etc/ssh/sshd_config` | `Port 22222`<br>`ListenAddress 127.0.0.1` | `sudo systemctl restart sshd` |
| **SMTP (Postfix)** | `/etc/postfix/master.cf` | `127.0.0.1:2525 inet n - y - - smtpd` | `sudo systemctl restart postfix` |
| **POP3 & IMAP (Dovecot)**| `/etc/dovecot/conf.d/10-master.conf` | `inet_listener imap { port = 1144 }`<br>`inet_listener pop3 { port = 1111 }` | `sudo systemctl restart dovecot` |
| **PostgreSQL** | `/etc/postgresql/<ver>/main/postgresql.conf` | `port = 5433`<br>`listen_addresses = '127.0.0.1'` | `sudo systemctl restart postgresql` |
| **MySQL / MariaDB** | `/etc/mysql/my.cnf` | `port = 3307`<br>`bind-address = 127.0.0.1` | `sudo systemctl restart mysql` |
| **Redis** | `/etc/redis/redis.conf` | `port 6380`<br>`bind 127.0.0.1` | `sudo systemctl restart redis-server` |
| **MongoDB** | `/etc/mongod.conf` | `net.port: 27018`<br>`net.bindIp: 127.0.0.1` | `sudo systemctl restart mongod` |
| **RabbitMQ** | `/etc/rabbitmq/rabbitmq.conf` | `listeners.tcp.default = 127.0.0.1:5674` | `sudo systemctl restart rabbitmq-server` |
| **OpenLDAP** | `/etc/default/slapd` | `SLAPD_SERVICES="ldap://127.0.0.1:3890/"` | `sudo systemctl restart slapd` |
| **FTP (vsftpd)** | `/etc/vsftpd.conf` | `listen_port=2122`<br>`listen_address=127.0.0.1` | `sudo systemctl restart vsftpd` |

> **Security Requirement:** Always set the backend service's bind address to `127.0.0.1` (loopback). If the backend service binds to `0.0.0.0` on its new port, attackers can scan and connect to it directly, bypassing RouteWarden.

---

### Strategy 4: Docker Compose Network Isolation

Run the backend service inside a private container bridge network with **no published ports**. RouteWarden publishes the public port on the host and proxies internally over Docker DNS:

```yaml
services:
  tcp-warden:
    image: ghcr.io/routewarden/tcp-warden:latest
    ports:
      - "5432:5433"     # Public port 5432 -> RouteWarden 5433
      - "9091:9091"     # Management API
    volumes:
      - ./tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro
    networks:
      - internal-net

  backend-service:
    image: postgres:16-alpine
    # Notice: NO 'ports:' mapping! Only reachable by tcp-warden
    networks:
      - internal-net

networks:
  internal-net:
    driver: bridge
```

---

## Privileged Ports (< 1024) & Permissions

- **In Docker (Port Mapping):** Mapping host privileged ports (e.g. `"22:2222"`, `"80:8081"`, `"443:8443"`) requires **no root permissions inside the container**. Docker's host proxy binds the low port, while RouteWarden runs safely as non-root UID 1000 (`routewarden`).
- **In Docker (Direct Low Ports):** Binding to ports `< 1024` directly (`listen: ":22"`) requires `cap_add: [NET_BIND_SERVICE]` in `docker-compose.yml`.
- **On Bare-Metal / Systemd Linux:** To bind ports `< 1024` as a non-root user, grant the ambient capability in your systemd service:
  ```ini
  [Service]
  User=routewarden
  AmbientCapabilities=CAP_NET_BIND_SERVICE
  CapabilityBoundingSet=CAP_NET_BIND_SERVICE
  ```
  Or apply file capabilities:
  ```bash
  sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/tcp-warden
  ```

---

## Installation & Usage in `tcp-warden`

### 1. Via Command Line
```bash
# Install by short name
tcp-warden plugins install postgres
tcp-warden plugins install redis

# Install from Git repository
tcp-warden plugins install https://github.com/routewarden/plugins/mongodb
```

### 2. Declarative Config (`tcp-warden.yaml`)
```yaml
plugins:
  postgres:
    enabled: true
    source: "https://github.com/routewarden/plugins/postgres"
  redis:
    enabled: true
    source: "https://github.com/routewarden/plugins/redis"

services:
  database_proxy:
    listen: ":5432"
    upstream: "127.0.0.1:5433"
    protocol: "postgres"
    max_auth_failures: 3
    ban_after_failures: 3
```

### 3. Plugin Management
```bash
# List all installed and active plugins
tcp-warden plugins list

# Enable or disable plugins
tcp-warden plugins enable postgres
tcp-warden plugins disable postgres

# Uninstall a plugin
tcp-warden plugins uninstall postgres
```

---

## Running Tests
```bash
cd plugins
go test -v ./...
```
