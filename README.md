# RouteWarden Protocol & Filter Plugins

This repository hosts official modular protocol inspectors and stream filters for RouteWarden (including [tcp-warden](https://github.com/routewarden/tcp-warden)).

Standard protocols (`ssh`, `smtp`, `pop3`, `imap`, generic `tcp`) are built directly into the core `tcp-warden` binary. All other protocols and specialized inspectors are distributed modularly from this repository.

---

## Available Plugins

| Plugin | Protocol(s) | Description | Path |
| :--- | :--- | :--- | :--- |
| **`postgres`** | `postgres`, `postgresql` | PostgreSQL wire protocol inspector with credential stuffing detection, auth failure triggers, and SSL negotiation | [`postgres/`](./postgres) |
| **`mysql`** | `mysql` | MySQL protocol handshake and authentication inspector with brute-force attack mitigation | [`mysql/`](./mysql) |
| **`redis`** | `redis`, `resp` | Redis RESP protocol inspector with command-level filtering, unauthorized command detection, and brute-force tracking | [`redis/`](./redis) |
| **`mongodb`** | `mongodb`, `mongo` | MongoDB wire protocol inspector with OP_MSG inspection, auth failure detection (codes 18/334), and blocked operation filtering | [`mongodb/`](./mongodb) |
| **`memcached`** | `memcached` | Memcached ASCII/binary protocol inspector with dangerous administrative command blocking (`flush_all`, `shutdown`) | [`memcached/`](./memcached) |
| **`amqp`** | `amqp`, `rabbitmq` | AMQP 0-9-1 protocol inspector with connection handshake validation, vhost allowlists, and authentication failure monitoring | [`amqp/`](./amqp) |
| **`http`** | `http` | HTTP/1.x inspector with Host header verification, User-Agent blocking, and URL path allowlists | [`http/`](./http) |
| **`ldap`** | `ldap` | LDAPv3 protocol inspector with BER decoding, bind credential failure tracking, and DN access control | [`ldap/`](./ldap) |
| **`vnc`** | `vnc`, `rfb` | VNC / RFB protocol inspector with authentication failure tracking and unauthenticated security type blocking | [`vnc/`](./vnc) |
| **`ftp`** | `ftp` | FTP control connection inspector with anonymous login blocking and credential monitoring | [`ftp/`](./ftp) |
| **`tls_sni`** | `tls`, `tls-sni`, `https` | TLS ClientHello SNI inspection for SNI routing, domain filtering, and TLS validation | [`tls_sni/`](./tls_sni) |
| **`mqtt`** | `mqtt` | MQTT IoT broker security inspector with client ID authorization and CONNECT packet inspection | [`mqtt/`](./mqtt) |
| **`minecraft`** | `minecraft` | Minecraft Server List Ping (SLP) inspector with DDoS mitigation and handshake validation | [`minecraft/`](./minecraft) |
| **`echo_filter`** | `echo`, `stream-filter` | Example bidirectional stream filter plugin demonstrating real-time payload transformation | [`echo_filter/`](./echo_filter) |


---

## Installation & Usage in `tcp-warden`

### 1. Via Command Line

Install any plugin directly from this repository:

```bash
# From GitHub repository URL
tcp-warden plugins install https://github.com/routewarden/plugins/postgres

# Or from local repository clone
tcp-warden plugins install ../plugins/postgres
```

The installer automatically:
1. Clones or copies the plugin source.
2. Reads and validates `plugin.yaml`.
3. Runs automated pre-flight tests (`go test -v ./...`).
4. Registers the plugin in `plugins/all/all.go`.
5. Rebuilds the `tcp-warden` binary.

### 2. Declarative Installation via `tcp-warden.yaml`

Configure plugins in `tcp-warden.yaml`. On startup, `tcp-warden` automatically pulls, caches (in `$ROUTEWARDEN_PLUGINS_CACHE` or Docker volumes), and registers missing plugins:

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
    upstream: "10.0.0.15:5432"
    protocol: "postgres"
    max_auth_failures: 5
```

### 3. Enabling & Disabling Plugins

```bash
# Enable an installed plugin
tcp-warden plugins enable postgres

# Disable a plugin (updates tcp-warden.yaml preserving comments)
tcp-warden plugins disable postgres

# List all installed and active plugins
tcp-warden plugins list

# Uninstall a plugin
tcp-warden plugins uninstall postgres
```

---

## Developing a New Plugin

Each plugin consists of:
1. `plugin.yaml`: Manifest with metadata, supported protocol names, and default configuration.
2. `plugin.go`: Implements `sdk.Plugin` and registers with `plugins.Register(&Plugin{})`.
3. `inspector.go`: Implements `sdk.Inspector` handling stream processing and security enforcement.
4. `<name>_test.go`: Automated test suite including in-memory `SelfTest()`.

### Running Tests Across All Plugins

```bash
cd plugins
go test -v ./...
```
