---
name: hunt-router
description: Routing brain for the installed 100-skill arsenal. When any signal or lead appears (SSRF, XSS, IDOR, JWT flaw, upload, takeover, cache, race, GraphQL, LLM abuse, web3...), this routes immediately — which skill loads as primary, which skills join as support, which specialist agent to spawn, and which named COMBO bundle to run. Use at hunt start, whenever a finding/lead is detected, when the hunter asks "هروح فين / where do I go", or when asked to combine skills.
---

# Hunt Router — خريطة التوجيه

## كيف توجّه (3 خطوات دائماً)

1. **صنّف الإشارة** — إيه نوع الثغرة/المرحلة من الجدول تحت.
2. **حمّل الحزمة** — السكيل الأساسي + سكيلز الدعم + الإيجنت المختص (عبر أداة Agent).
3. **اقفل الحلقة** — أي نتيجة تمر على `triage-validation` (7-Question Gate) قبل أي تقرير، ثم `report-writing`.

قواعد صارمة: scope أولاً دائماً · ثغرة واحدة كل مرة بعمق · "Could" = مش ثغرة · WAF حاجب؟ حزمة WAF · مفيش نتايج جلستين؟ ارجع لـ `bb-methodology`.

## جدول الإشارة → المسار

| الإشارة | سكيل أساسي | دعم | إيجنت |
|---|---|---|---|
| بداية تارجت / ضياع | `bb-methodology` | `bounty`, `webvuln` | recon-agent → recon-ranker |
| recon / سطح الهجوم | `web2-recon` | `subdomain-enum-workflow`, `recon-external`, `osint` | recon-agent, recon-ranker |
| SSRF (fetch لـ URL خارجي, webhook, importer, preview) | `ssrf` | `security-arsenal`, `waf-bypass`, `cloud` | ssrf-hunter, ssrf-specialist |
| XSS (reflection, DOM, stored) | `xss` | `proto-pollution`, `security-arsenal`, `waf-bypass` | client-side-specialist |
| SQLi / injection (search, filter, sort, id) | `sqli` | `deserialize`, `ssti`, `security-arsenal` | sqli-hunter, injection-specialist |
| IDOR / BAC (object ids, ملفات غيري) | `api-auth` | `webvuln` | access-control-specialist, bac-hunter |
| auth / OAuth / SSO / reset | `oauth` | `jwt`, `saml`, `crypto-attacks` | auth-specialist |
| JWT (token في الطلب) | `jwt` | `crypto-attacks` | auth-specialist |
| file upload (avatar, import, PDF) | `file-upload` | `deserialize` (XXE في office/SVG) | upload-specialist |
| request smuggling / desync | `smuggling` | `security-arsenal` | api-specialist |
| cache poisoning / deception | `cache-poison` | `smuggling` | api-specialist |
| race / TOCTOU (coupon, limit, otp) | `race` | `business-logic` | logic-specialist |
| business logic / checkout / payment | `business-logic` | `payment` | logic-specialist |
| GraphQL (endpoint /batch/aliases) | `graphql-audit` | `graphql` | graphql-hunter, api-specialist |
| subdomain takeover (CNAME dangling) | `takeover` | `web2-recon` | subdomain-takeover |
| secrets في JS / .env / dorking | `secrets` | `client-reverse`, `osint` | explorer |
| anti-bot / request signing / hmack | `client-reverse` | `security-arsenal` | — |
| CORS / CSRF / clickjacking | `csrf` | `security-arsenal` | client-side-specialist |
| WebSocket / SSE | `websocket` | `csrf` | api-specialist |
| Supabase / PostgREST | `supabase` | `api-auth` | — |
| ميزات AI / chatbot / RCP | `llm-redteam` | `llm-appsec`, `agentic-app-audit`, `mcp-server-audit` | bugbounty-oracle |
| smart contracts / DeFi / token | `web3-start-here` → السلسلة | `web3-audit`, `meme-coin-audit` | web3-auditor, token-auditor |
| mobile app (APK/IPA) | `mobile-pentest` | — | mobile-pentester |
| وصلنا credentials / وصول سحابي | `cloud-pentest` | `cloud`, `post-exploit` | cloud-security |
| CI/CD / GitHub Actions | `cicd-security` | `supply-chain` | cicd-redteam |
| WAF بيحجب كل حاجة | `waf-bypass` | `security-arsenal`, `smuggling` | — |
| كتابة تقرير / إثبات | `triage-validation` ثم `report-writing` | `pentest-report` | validator, report-writer |
| مراجعة كود مصدري (white-box) | `source-code-review` | `security-audit`, `web-pentest` | — |
| اختبار كامل hypothesis-driven | `web-pentest` | `web-pentesting-skills`, `api-pentest` | bugbounty-orchestrator |

## الحزم المسماة (COMBOS) — شغّلها كوحدة واحدة

- **FULL-START** (تارجت جديد): `bb-methodology` → `web2-recon` + `subdomain-enum-workflow` → sweep بـ `argus` → إيجنت recon-ranker يرتب الأولويات → `webvuln` للتنفيذ.
- **SSRF-KILLCHAIN**: `ssrf` + `security-arsenal` + `waf-bypass`؛ إيجنت ssrf-hunter. عند الإصابة: `chain-builder` (SSRF→IMDS→credentials→`cloud-pentest`) → triage → تقرير. دي أسرع طريق من P3 لـ P1.
- **XSS→ATO**: `xss` + `proto-pollution` + `waf-bypass`؛ إيجنت client-side-specialist. عند الإصابة: `chain-builder` (XSS→سرقة token→ATO) → triage → تقرير.
- **IDOR-RAID** (محتاج حسابين): `api-auth` + `webvuln`؛ إيجنت bac-hunter (يرفض يشتغل بحساب واحد) + access-control-specialist.
- **AUTH-BREAK**: `oauth` + `jwt` + `saml` + `crypto-attacks`؛ إيجنت auth-specialist. لو الـ reset link بييجي بـ token → يدخل الحزمة دي فوراً.
- **DEEP-CLIENT**: `client-reverse` + `secrets` + `proto-pollution`؛ إيجنت explorer (يحصد JS bundles ويطلع endpoints مخفية وsecrets بدون أي payloads).
- **VALIDATE-AND-SHIP**: `triage-validation` + `report-writing`؛ إيجنت validator (PASS/KILL/DOWNGRADE) ثم report-writer. **لا تقرير بدون الحزمة دي.**

## ملاحظات تشغيل

- **قاعدة الربط (مهمة):** الإيجنتس ما بتشوفش السكيلز تلقائياً — أنا الوسيط. لما تستدعي إيجنت، اكتب في التاسك نفسه: الهدف + أهم خطوات السكيل الأساسي (مختصرة) + أي lead من recon. الإيجنت يرجّع نتيجة منظمة، وأنا أقيمها بـ triage-validation.
- الأدوات الخارجية (subfinder, httpx, nuclei, ffuf...) لو مش متثبتة: كمّل بالمنهجية + curl/python، واقترح تثبيت الأداة للمرة الجاية.
- أي سكيل تطلب تشغيل سكريبت: اقرا السكريبت قبل التنفيذ، واطلع عن الـ scope = قف.
- الـ agents دي محلية (من ~/.zcode/agents) — استدعاء واحد لكل مختص، مش شرذاً كامل.
