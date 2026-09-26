# RouteWarden LDAPv3 Protocol Plugin

Standalone RouteWarden modular plugin for inspecting LDAPv3 directory protocol traffic, monitoring bind credential failures, and enforcing Distinguished Name (DN) access control.

## Protocols
- `ldap`

## Features
- **ASN.1 BER Parser**: Robust streaming BER TLV decoder for LDAP message framing.
- **Bind Authentication Failure Detection**: Catches LDAP `BindResponse` with resultCode 49 (`invalidCredentials`) and triggers fail2ban / rate limiting.
- **Distinguished Name (DN) Filtering**:
  - Restricts binds or search requests to allowed base DN trees (e.g. `allowed_base_dns: ["dc=example,dc=com"]`).
  - Explicitly blocks access to sensitive DNs (e.g. `blocked_dns: ["cn=admin,dc=example,dc=com"]`), returning `resultInsufficientAccessRights` (code 50).
- **Zero-Copy Handoff**: Hands off established authenticated connections to raw proxying upon successful Bind.

## Installation

### Via RouteWarden CLI
```bash
# From GitHub repository:
tcp-warden plugins install https://github.com/routewarden/plugins/ldap

# Or from local clone:
tcp-warden plugins install ../plugins/ldap
```

### Via Configuration (`tcp-warden.yaml`)
```yaml
plugins:
  ldap:
    enabled: true
    source: "https://github.com/routewarden/plugins/ldap"

services:
  ldap-guard:
    listen: ":3890"
    upstream: "127.0.0.1:389"
    protocol: "ldap"
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "1h"
    plugin_config:
      blocked_dns:
        - "cn=Directory Manager"
        - "cn=root,dc=company,dc=com"
      allowed_base_dns:
        - "dc=company,dc=com"
```
