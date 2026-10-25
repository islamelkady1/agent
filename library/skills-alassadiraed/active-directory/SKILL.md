---
name: active-directory
description: Active Directory and Windows domain attack playbook — Kerberos abuse (AS-REP roast, Kerberoast, delegation), LDAP/LDAPS enumeration, BloodHound-style attack paths, GPO/ACL misconfig, and DCSync prerequisites. Use when scope includes on-prem AD, Azure AD hybrid, `.local` domains, or internal pentest with domain credentials.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - file_write
  - ask_user
---

# Active Directory playbook

Authorized internal assessment only. Never attack domains outside written scope.

## 1. Domain intel (from user or uploads)
Collect: domain FQDN, DC IPs, user creds (lab), BloodHound JSON/zip, `ldapsearch` output, or `nltest /dclist`.

Map trust boundaries: single forest, child domains, external trusts, Azure AD Connect sync.

## 2. Kerberos — unauthenticated
```sh
# AS-REP roast (users without preauth)
# With impacket (if installed): GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -dc-ip DC_IP

# User enumeration via Kerberos error timing (careful — rate limit)
```

Document any AS-REP hash for offline crack **only in authorized lab**.

## 3. Kerberos — authenticated
| Technique | Indicator |
|-----------|-----------|
| Kerberoast | SPNs on user accounts, `SERVICE/` SPNs |
| Constrained delegation | `msDS-AllowedToDelegateTo` |
| RBCD | `msDS-AllowedToActOnBehalfOfOtherIdentity` on computer object |
| Unconstrained | `TRUSTED_FOR_DELEGATION` on server |

Prioritize paths to **Domain Admin** or **Tier-0** assets per BloodHound tags.

## 4. LDAP / ADCS
- Anonymous LDAP bind (legacy domains)
- `PKI` templates: ESC1–ESC8 (Vulnerable Certificate Templates)
- `Certipy` / manual template ACL review when user provides export

```sh
# LDAP signing / channel binding check (conceptual — use user's ldap tools)
ldapsearch -x -H ldap://DC -s base namingContexts
```

## 5. ACL abuse
High-value ACEs: `GenericAll`, `WriteDACL`, `ForceChangePassword`, `AddMember`, `WriteOwner` on:
- Domain Admins group
- AdminSDHolder
- GPO objects (`CN=Policies,CN=System,...`)

Chain: compromise user → abuse ACE → DA or DCSync rights.

## 6. Lateral movement hooks
After foothold: `pass-the-hash`, `overpass-the-hash`, `s4u2self/s4u2proxy` for delegation chains. Coordinate with `/lateral` skill.

## 7. Evidence & reporting
For bounty/VDP: usually **out of scope** unless program explicitly includes internal AD. For pentest reports:
- Attack path diagram (user → SPN → DA)
- Exact ACE or Kerberos primitive
- Reproduction in isolated lab
- Remediation: tiering, LAPS, AES-only Kerberos, audit SPNs, harden ADCS templates

Call `confirm_finding` only when program scope covers the finding and you have reproducible proof.
