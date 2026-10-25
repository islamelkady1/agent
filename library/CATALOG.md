# CATALOG — خريطة السكيلز والإيجنتس

> آخر تحديث: 2026-10-25 · المصدر: 17 repo من قائمة المستخدم

## التوزيع على 3 أماكن

| المكان | المحتوى | متى يُستخدم |
|---|---|---|
| `~/.zcode/skills/` | **101 سكيل نشطة** (تُحمَّل تلقائياً في كل جلسة) | الشغل اليومي |
| `~/.zcode/agents/` | **66 إيجنت** (subagents قابلة للاستدعاء) | تفويض مهام متخصصة |
| `~/.zcode/skill-library/` | **+1300 سكيل مرجعية** (22 مصدر كامل) | تُفعَّل عند الطلب: "فعّل سكيل كذا من المكتبة" |

ليش التقسيم ده؟ لو ثبتّنا الـ 1301 كلها نشطة، وصف كل سكيل هيتحمّل في بداية كل جلسة = استهلاك ضخم للسياق وبطء. النشط هو الأنسب لشغل bug bounty على الويب، والباقي مكتبة مرجعية.

---

## 1) السكيلز النشطة (52)

### حزمة Agentic-Bug-Hunter (awarexone) — 19 سكيل [العمود الفقري]
- `bug-bounty` — الماستر ووركفلو: recon → learn → hunt → validate → report، كل أنواع الثغرات، الـ 7-Question Gate
- `bb-methodology` — عقلية الصيد + الـ 5 phases + توجيه الأدوات
- `web2-recon` — subdomain enum, live hosts, crawling, nuclei
- `web2-vuln-classes` — 21 نوع ثغرة مع جداول bypass
- `security-arsenal` — paylواتد + gf patterns + قائمة الـ always-rejected
- `triage-validation` — بوابات التحقق قبل كتابة أي تقرير
- `report-writing` — قوالب H1/Bugcrowd/Intigriti/Immunefi + CVSS 3.1
- `web3-audit` — 10 أنواع ثغرات smart contracts + قالب Foundry PoC
- `meme-coin-audit` — كشف rug pull وتحليل التوكنات
- `credential-attack` — password spray منهجياً مع ضوابط قانونية
- `mobile-pentest` — Android/iOS: proxy workflow, decompile, deeplinks
- `cicd-security` — GitHub Actions injection, secrets, runner poisoning
- `graphql-audit` — introspection, batching, IDOR بالـ aliasing
- `mcp-server-audit` — تدقيق سيرفرات MCP (tool poisoning وغيره)
- `cloud-pentest` — استغلال سحابي بعد الاختراق (AWS/GCP/Azure)
- `agentic-app-audit` · `llm-redteam` · `client-reverse` · `argus`

### حزمة web3-bug-bounty-hunting (11 سكيل)
`web3-start-here` (نقطة البداية) → `web3-hunt-foundation` → `web3-bug-classes` → `web3-poc-foundry` → `web3-triage-report` + تخصصات (zksync-era, role-misconfig, grep-arsenal, solidity-audit-mcp, ai-tools, methodology-research)

### حزمة strix (usestrix) — 9 سكيل
اختبار اختراق تطبيقات ويب/API، OWASP Top 10، فحص الكود (find/fix)، CI scanning — مصممة لتعمل مع أداة Strix أو كمنهجية مستقلة

### حزمة bug-hunter (codexstar69) — 11 سكيل
`bug-hunter` (منسق) + `hunter` · `recon` · `referee` · `skeptic` · `fixer` · `security-review` · `commit-security-scan` · `vulnerability-validation` · `threat-model-generation` · `doc-lookup`

### سكيلز مفردة
- `security-audit` (Cloudflare) — تدقيق كود شامل بملفات مرجعية لكل نوع هجوم
- `subdomain-enum-workflow` (george1-adel) — workflow كامل لتعداد السب دومينات

---

## 2) الإيجنتس (65 في ~/.zcode/agents/)

### من BountySkiller (The-XSS-Rat) — 24 إيجنت
- `autopilot` — حلقة صيد مستقلة كاملة (scope → recon → rank → hunt → validate → report)
- `bugbounty-orchestrator` — منسق يوزع على المتخصصين
- متخصصون: sqli-hunter, ssrf-hunter, xxe-hunter, csrf-hunter, bac-hunter, auth-specialist, api-specialist, token-auditor, upload-specialist, chain-builder, recon-agent, recon-ranker, report-writer, validator, explorer...

### من Bug-Bounty-Agents (matty69v) — 41 إيجنت
- `attack-planner` · `engagement-planner` — تخطيط الهجوم
- `recon-advisor` · `osint-collector` — الاستطلاع
- `exploit-chainer` · `payload-crafter` · `poc-validator` — بناء وإثبات الاستغلال
- `bug-bounty` · `bizlogic-hunter` · `graphql-hunter` · `jwt-cracker` — صيد متخصص
- + أدوار red team / forensics / malware / crypto / cloud / mobile حسب الحاجة

طريقة الاستدعاء: عبر أداة الـ Agent باسم الإيجنت مباشرة.

---

## 3) مكتبة skill-library (1301 سكيل — تفعيل عند الطلب)

| المصدر | العدد | المحتوى |
|---|---|---|
| Anthropic-Cybersecurity-Skills | 818 | سكيلز Anthropic الرسمية — أغلبها blue team/DFIR/forensics؛ فيها كنوز لصيد IDOR/auth في بيئات AD والسحابة |
| recon-skills | 146 | حزمة استطلاع ضخمة (subdomains, ports, JS, URLs...) |
| hack-skills (yaklang) | 103 | نفس محتوى موقع skills.hackbenchmark.com — playbooks هجومية P0/P1/P2 |
| Claude-BugHunter | 83 | سكيلز bug bounty متفرقة بأسلوب Claude |
| Claude-Red (Skills/web) | 79 | هجوم ويب من مشروع Claude-Red |
| Agentic-Bug-Hunter (نسخة كاملة) | 20 | الريبو كامل: commands + hooks + rules الخاصة بـ Claude Code |
| claude-bug-bounty (shuvonsec) | 20 | نسخة أقدم من نفس حزمة ABH (19 مكررة + نسخة أصغر من الماستر) |
| strix · web3 · bug-hunter · security-audit | — | نسخ كاملة من اللي اتثبت نشط |
| owasp-hunting | 30 مجلد | README + ملفات payloads لكل نوع ثغرة (مرجع paylواتد مباشر) |
| subdomain-enumeration-skill | 1 | الملف الأصلي (مثبت نشط) |

**لتفعيل أي سكيل من المكتبة:** قل للإيجنت "فعّل سكيل X من `~/.zcode/skill-library/<source>/`" — هتنسخ لمجلد skills النشط وتشتغل فوراً.

---

## 4) حلقة "build skill" — تعلّم وصناعة سكيلز جديدة مع الوقت

1. **public-skills-builder** (awarexone) في المكتبة — مصنع سكيلز: يقرأ 500+ تقرير HackerOne علني + 1200 writeup من GitHub وينتج 18 ملف `hunt-*.md` جاهزين.
   - التشغيل: `python3 -m venv .venv && pip install anthropic requests` + محتاج `ANTHROPIC_API_KEY` في `.env`
   - عندما توفر المفتاح → نشغّله ونضيف النواتج للمكتبة/النشط
2. **الصناعة اليدوية فورية:** بعد كل جلسة صيد ناجحة، اطلب: "حوّل اللي اتعلمناه النهاردة لسكيل" — يُكتب SKILL.md جديد بنفس صيغة الحزمة ويُضاف للمكتبة أو النشط.
3. **bug-bounty-report-generator** (shuvonsec) — `report_generator.py` لتوليد مسودة تقرير من الـ findings.

## 5) أدوات بايثون في المكتبة (تشغيل يدوي)
- `BountySkiller/` — تطبيق ويب (`app.py`, `hunt_web.py`) + منهجية RAT-DOCTRINE.md
- `bug-bounty-report-generator/report_generator.py`
- ملاحظة: اقرا README قبل تشغيل أي أداة، وشغّلها فقط على أهداف مصرح بها.

---

## 6) إضافة 2026-10-25 (دفعة 2 — خمسة مصادر جديدة)

### سكيل التوجيه hunt-router (مصنوعة محلياً)
- **hunt-router** — "مخ" التوجيه: جدول إشارة→مسار لكل أنواع الثغرات + 7 حزم مسماة (FULL-START, SSRF-KILLCHAIN, XSS→ATO, IDOR-RAID, AUTH-BREAK, DEEP-CLIENT, VALIDATE-AND-SHIP). أي إشارة ثغرة → القي تلقائياً عليها.

### اتضافت للنشط (+49 → 101 سكيل)
- **skills-alassadiraed (42 سكيل)** — سكيلز لكل نوع ثغرة لوحده: `xss`, `sqli`, `ssrf`, `ssti`, `jwt`, `oauth`, `saml`, `takeover`, `waf-bypass`, `cache-poison`, `smuggling`, `race`, `proto-pollution`, `graphql`, `grpc`, `supabase`, `websocket`, `payment`, `secrets`, `llm` وغيرها + نسخة recon باسم `recon-external` (الاسم الأصلي كان متعارضاً مع recon بتاع bug-hunter)
- **Web-Pentesting-Skills (0xnhsec, 1)** — `web-pentesting-skills`: اختبار ويب بمنهجية evidence-led عبر blackbox/graybox/whitebox + taxonomy مرجعية
- **offensive-security-skills (vasanth15-hts, 6 من 8)** — `web-pentest` (hypothesis-driven)، `api-pentest`، `source-code-review`، `pentest-report`، `llm-appsec`، `network-pentest` — تخطينا `mobile-pentest` و`cloud-pentest` لأن حزمة ABH النشطة تغطيهم بنفس الاسم

### إيجنت جديد (66)
- **bugbounty-oracle** — شخصية ORACLE محوّلة من ماستر سيستم برومبت 0xN0RMXL: كثافة تقنية قصوى، payload حقيقية، سلاسل P3→P1، تحويلات حسب الـ WAF

### في المكتبة فقط
- **BugBountySkills-0xN0RMXL** — 624 ملف معرفة في قالب مخصص (SKILL_FILES/AUTOMATION, RECON, PAYLOADS, REPORTING...) + KNOWLEDGE_BASE + MASTER_SYSTEM_PROMPTS (نسخ ChatGPT/Copilot/local من نفس شخصية ORACLE) + سكريبتات. قالب غير قياسي — يُقرأ كمرجع
- **awesome-testing-skills** — 12 ملف لكن سكيلز فعليتين بس (api/ui-exploratory-testing × 6 إصدارات) — اختبار QA مش bug bounty؛ يُفعَّل عند الحاجة
