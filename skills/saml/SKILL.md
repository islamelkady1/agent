---
name: saml
description: SAML 2.0 SSO attack playbook — XML signature wrapping (XSW), comment injection, assertion replay, Audience/Recipient mismatch, and metadata poisoning. Use when the target uses enterprise SSO, Okta/ADFS/Azure AD SAML, or `/saml/` endpoints.
allowed-tools:
  - shell
  - http
  - web_search
  - web_fetch
  - confirm_finding
  - file_write
---

# SAML SSO playbook

SAML bugs are **parser differential** bugs between IdP, SP, and XML libraries. High impact = authenticate as arbitrary user.

## 1. Map SAML flow
Identify:
- SP ACS URL (`/saml/acs`, `/auth/saml/callback`)
- Metadata URL (`/saml/metadata`)
- IdP issuer and NameID format
- Whether SP validates signature, Audience, Recipient, NotOnOrAfter

Capture a **valid SAMLResponse** (base64) from user or Burp — decode:

```sh
echo 'BASE64_SAML' | base64 -d | xmllint --format - 2>/dev/null | head -80
```

## 2. Signature wrapping (XSW)
If SP validates signature on one `<Assertion>` but uses another:
- Insert wrapped assertion with attacker NameID
- Move signature block per XSW1–XSW8 patterns (PortSwigger SAML cheat sheet)

Use `web_search "SAML XSW PoC"` for library-specific variants. Test in staging first.

## 3. Comment injection
Break NameID parsing:
```xml
<saml:NameID>admin<!-- comment -->@corp.com</saml:NameID>
```

## 4. Assertion replay
- Resubmit captured SAMLResponse — is `InResponseTo` / one-time use enforced?
- Extend `NotOnOrAfter` — rejected or accepted?

## 5. Metadata trust
If SP fetches IdP cert from attacker-controlled URL (`TrustedMetadataURL` param) → key substitution.

## 6. Report
Impact: account takeover, privilege escalation to admin NameID.

VRT: `Authentication Bypass > SAML Authentication Bypass`

Include modified SAML (redacted), HTTP POST to ACS, and session cookie proving login. Never submit live production assertions to public trackers without redaction.

Call `confirm_finding` after successful forged login proof.
