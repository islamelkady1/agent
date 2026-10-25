---
name: firmware
description: IoT and embedded firmware security playbook — UART/JTAG discovery hints, firmware extraction from uploads, static analysis, hardcoded secrets, update mechanism flaws, and hardware attack surface mapping. Use when scope includes IoT devices, routers, OT lab gear, or user uploads firmware binaries (.bin, .img, squashfs).
allowed-tools:
  - shell
  - file_write
  - grep
  - glob
  - coverage
  - confirm_finding
  - ask_user
---

# Firmware / IoT playbook

Physical hardware attacks only on devices user owns and assigns. No bricking production OT.

## 1. Intake
User provides:
- Device model, firmware version, download URL (in scope)
- Dump file in `.raos/uploads/` or local path

```sh
file firmware.bin
binwalk firmware.bin 2>/dev/null | head -30
strings firmware.bin | head -200
```

## 2. Extraction
```sh
# If binwalk available
binwalk -e firmware.bin -C /tmp/fw_extract 2>/dev/null
find /tmp/fw_extract -type f | head -50
```

Identify: squashfs, cramfs, uBoot, kernel, rootfs.

## 3. Static analysis targets
| Hunt | Where |
|------|-------|
| Hardcoded creds | `/etc/passwd`, shadow copies, nvram defaults |
| Private keys | `*.pem`, `BEGIN RSA` in strings |
| Debug flags | `telnetd`, `DEBUG=1`, backdoor accounts |
| Update URLs | HTTP cleartext OTA, missing signature check |

```sh
grep -rniE 'password|secret|api_key|admin' /tmp/fw_extract 2>/dev/null | head -40
```

## 4. Network services (device on lab bench)
From user-connected lab network only:
```sh
nmap -sV -p- DEVICE_IP 2>/dev/null | head -40
curl -ksS http://DEVICE_IP/ -m 5
```

Default creds from vendor docs — test once, document.

## 5. Update mechanism
- Signed updates? Rollback protection?
- Downgrade to vulnerable version allowed?
- MD5-only checksums?

Pair with `crypto-attacks` if weak signing.

## 6. Reporting
Finding examples:
- UART shell with root, no auth (physical access assumed — clarify impact)
- Hardcoded TLS private key in firmware
- OTA without signature → remote code execution on device class

Impact: device class, not "all IoT ever". Remediation: secure boot, signed OTA, remove debug interfaces.

## 7. Safety
- Do not publish exploit for critical infrastructure without coordinated disclosure
- `ask_user` before any RF/wireless testing outside Faraday lab
