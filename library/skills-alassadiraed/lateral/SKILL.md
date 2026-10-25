---
name: lateral
description: Lateral movement and network pivoting playbook — SOCKS/SSH tunnels, port forwarding, double-hop through compromised hosts, internal service enumeration, and segmentation testing. Use after initial foothold on VPN/bastion/internal bug bounty scope or authorized red team lab.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - ask_user
---

# Lateral movement playbook

Operate only on hosts/networks in RoE. Document every hop; prefer interactive approval before pivoting to new subnets.

## 1. Situational awareness
From foothold host collect:
```sh
# Linux
ip -br a; ip route; cat /etc/resolv.conf 2>/dev/null
ss -tlnp 2>/dev/null || netstat -tlnp

# Windows (if shell available)
ipconfig /all
netstat -ano
```

Map: VLANs, RFC1918 ranges, cloud metadata routes, proxy env vars.

## 2. Trust zones
Identify segmentation:
- Can you reach other internal IPs on 443/445/5985/6379/9200?
- Cloud metadata still reachable from this host? (`ssrf` skill)
- Kubernetes API (6443) or Docker socket?

Mark each reachable subnet:port with `coverage`.

## 3. Pivot techniques (authorized)
| Method | When |
|--------|------|
| SSH `-D` / `-L` | User provides jump host creds |
| `chisel` / `ligolo` | User explicitly requests and owns infra |
| SOCKS via compromised app | SSRF to internal only if in scope |

Never install persistent backdoors outside lab. Remove tunnels after test.

## 4. Internal enumeration through pivot
Once SOCKS up, re-run from operator machine:
```sh
curl -x socks5h://127.0.0.1:1080 -ksS https://internal-app.corp/ -m 10
```

Target internal-only APIs, Jenkins, Grafana, Kibana, Redis, Elasticsearch (often unauth).

## 5. Credential relay
- Spray **single** password from breach (user supplied) against SSH/RDP — only if RoE allows and rate-limited
- Pass-the-hash / pass-the-ticket — coordinate with `active-directory`
- Extract tokens from compromised web apps (JWT, session cookies) via `browser_capture_*`

## 6. Finding classes
Reportable when in scope:
- Flat network (DMZ host reaches DB subnet directly)
- Missing segmentation between prod and staging
- Internal admin panel without auth on RFC1918
- SSRF allowing pivot to internal services

Include network diagram and exact hop path in finding.
