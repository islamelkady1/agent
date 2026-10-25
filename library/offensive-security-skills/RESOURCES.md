# Bug Bounty Resources — All Links & Repos

All sources used to build the skills playbook. Kept as a live reference.

---

## Researcher Blogs & Writeups

| Writer | Platform | Link | Focus |
|--------|----------|------|-------|
| shahjerry33 | Medium | https://shahjerry33.medium.com/ | IDOR, Auth bypass, Business logic |
| lostsec | Medium | https://lostsec.medium.com/ | IDOR, ATO, API bugs |
| NahamSec | YouTube / Blog | https://www.youtube.com/@NahamSec | Methodology, live hacking |
| Jason Haddix | Blog | https://jhaddix.medium.com/ | Recon, methodology |
| Sam Curry | Blog | https://samcurry.net/blog | OAuth, auth bypass, high-value bugs |
| Brett Buerhaus | Blog | https://buer.haus | High-value targets, chained bugs |
| Hakluke | Medium | https://hakluke.medium.com/ | Recon automation, methodology |
| tomnomnom | GitHub | https://github.com/tomnomnom | Tools: gf, waybackurls, anew, etc. |
| Assetnote | Research | https://www.assetnote.io/resources | Mass recon, cloud bugs, novel research |
| PortSwigger | Research | https://portswigger.net/research | HTTP smuggling, cache poisoning, advanced web |
| InfoSec Writeups | Medium Pub | https://infosecwriteups.com | Community writeups across all topics |
| KingOfBugbounty | GitHub | https://github.com/KingOfBugbounty/KingOfBugBountyTips | One-liners, recon automation |
| Pentester.land | Blog | https://pentester.land/list-of-bug-bounty-writeups/ | Aggregated writeup list |
| hahwul | Blog | https://www.hahwul.com/cullinan/finding/ | Categorized finding techniques |

---

## GitHub Repositories

### Tips & Methodology
| Repo | Description |
|------|-------------|
| https://github.com/KingOfBugbounty/KingOfBugBountyTips | One-liners and automation commands |
| https://github.com/jhaddix/tbhm | The Bug Hunter's Methodology (Jason Haddix) |
| https://github.com/KathanP19/HowToHunt | Category-specific hunting methodology |
| https://github.com/daffainfo/AllAboutBugBounty | Comprehensive bug bounty guide |
| https://github.com/devanshbatham/Awesome-Bugbounty-Writeups | Curated writeup list |
| https://github.com/ngalongc/bug-bounty-reference | Bug bounty reference by vulnerability type |
| https://github.com/vavkamil/awesome-bugbounty-tools | Tools + techniques reference |
| https://github.com/inonshk/31-days-of-API-Security-Tips | 31 days of API security tips |
| https://github.com/shieldfy/API-Security-Checklist | API security checklist |

### Payloads & References
| Repo | Description |
|------|-------------|
| https://github.com/swisskyrepo/PayloadsAllTheThings | Payloads for every vulnerability type |
| https://github.com/danielmiessler/SecLists | Wordlists: passwords, usernames, fuzzing |
| https://github.com/Bo0oM/fuzz.txt | Fuzzing wordlist for files and dirs |
| https://github.com/1N3/IntruderPayloads | Burp intruder payloads |
| https://github.com/EdOverflow/bugbounty-cheatsheet | Bug bounty cheatsheet |

### Disclosed H1 Reports
| Repo | Description |
|------|-------------|
| https://github.com/reddelexc/hackerone-reports | H1 reports sorted by payout |
| https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_program/TOPALL.md | Top reports by payout amount |

### Tools
| Repo | Description | Install |
|------|-------------|---------|
| https://github.com/projectdiscovery/subfinder | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| https://github.com/projectdiscovery/httpx | HTTP probing at scale | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| https://github.com/projectdiscovery/nuclei | Template-based vuln scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| https://github.com/projectdiscovery/katana | JS-aware web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| https://github.com/projectdiscovery/naabu | Port scanner | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| https://github.com/projectdiscovery/dnsx | DNS resolver | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| https://github.com/projectdiscovery/notify | Notify to Slack/Discord/Telegram | `go install github.com/projectdiscovery/notify/cmd/notify@latest` |
| https://github.com/ffuf/ffuf | Fast web fuzzer | `go install github.com/ffuf/ffuf/v2@latest` |
| https://github.com/tomnomnom/waybackurls | Wayback Machine URL fetcher | `go install github.com/tomnomnom/waybackurls@latest` |
| https://github.com/lc/gau | Get All URLs (multiple sources) | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| https://github.com/tomnomnom/gf | Pattern-based grep for bug bounty | `go install github.com/tomnomnom/gf@latest` |
| https://github.com/tomnomnom/anew | Append new lines only | `go install github.com/tomnomnom/anew@latest` |
| https://github.com/tomnomnom/qsreplace | Replace querystring values | `go install github.com/tomnomnom/qsreplace@latest` |
| https://github.com/hahwul/dalfox | XSS scanner | `go install github.com/hahwul/dalfox/v2@latest` |
| https://github.com/Emoe/kxss | Find reflected parameters | `go install github.com/Emoe/kxss@latest` |
| https://github.com/sqlmapproject/sqlmap | SQL injection tool | `pip install sqlmap` |
| https://github.com/trufflesecurity/trufflehog | Secret scanner | `brew install trufflesecurity/trufflehog/trufflehog` |
| https://github.com/maurosoria/dirsearch | Web path discovery | `pip install dirsearch` |
| https://github.com/ticarpi/jwt_tool | JWT attack toolkit | `pip install jwt_tool` |
| https://github.com/GerbenJavado/LinkFinder | JS file link/endpoint finder | `pip install linkfinder` |
| https://github.com/m4ll0k/SecretFinder | Find secrets in JS files | Clone + `pip install -r requirements.txt` |
| https://github.com/s0md3v/Arjun | HTTP parameter discovery | `pip install arjun` |
| https://github.com/s0md3v/uro | URL list deduplication | `pip install uro` |
| https://github.com/haccer/subjack | Subdomain takeover checker | `go install github.com/haccer/subjack@latest` |
| https://github.com/Ice3man543/SubOver | Subdomain takeover | `go install github.com/Ice3man543/SubOver@latest` |
| https://github.com/nahamsec/JSParser | Parse JS for endpoints | Clone + Python |
| https://github.com/hakluke/hakrawler | Fast web crawler | `go install github.com/hakluke/hakrawler@latest` |
| https://github.com/dwisiswant0/cf-check | Cloudflare bypass checker | Go install |
| https://github.com/assetnote/kiterunner | API route discovery | Go build |
| https://github.com/assetnote/surf | SSRF finder | Go build |

---

## Learning Platforms & References

| Resource | Link | Type |
|----------|------|------|
| HackerOne Hacktivity | https://hackerone.com/hacktivity | Live public disclosures |
| Bugcrowd Disclosures | https://bugcrowd.com/disclosures | Public disclosed reports |
| OWASP API Security Top 10 | https://github.com/OWASP/API-Security | API vulnerability reference |
| OWASP Web Top 10 | https://owasp.org/www-project-top-ten/ | Web vulnerability reference |
| HackTricks | https://book.hacktricks.xyz | Comprehensive hacking reference |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Payloads reference |
| PortSwigger Web Academy | https://portswigger.net/web-security | Free labs for all web vulns |
| PentesterLab | https://pentesterlab.com | Paid, very practical labs |
| AppSecWiki | https://appsecwiki.com | AppSec reference |
| API Security Encyclopedia | https://apisecurity.io/encyclopedia/ | API-specific vuln encyclopedia |

---

## Dork References

### Google Dorks (use on Google)
```
# Find exposed .env files
site:target.com ext:env
site:target.com inurl:".env"

# Find exposed config files
site:target.com ext:json inurl:config
site:target.com inurl:"/api/v1" intext:"api_key"

# Find login pages
site:target.com inurl:login
site:target.com inurl:admin

# Find Swagger/API docs
site:target.com inurl:swagger
site:target.com inurl:api-docs
site:target.com inurl:openapi.json

# Find backup files
site:target.com ext:bak OR ext:old OR ext:backup
```

### GitHub Dorks (use on github.com/search)
```
# API keys and secrets
"target.com" "api_key" language:javascript
"target.com" "secret" language:python
"target.com" password filename:.env
"target.com" AWS_SECRET_ACCESS_KEY

# Specific patterns
"AKIA" "target.com"
"-----BEGIN RSA PRIVATE KEY-----" "target.com"
"sg_" site:github.com "target.com"  # SendGrid key
```

### Shodan Dorks (shodan.io)
```
# Find target's exposed services
org:"Target Company" port:8080
org:"Target Company" http.title:"admin"
org:"Target Company" product:"Apache Tomcat"

# Find exposed actuator endpoints
http.html:"/actuator/env"
http.html:"Spring Boot" http.html:"actuator"

# Find exposed databases
org:"Target Company" port:5432
org:"Target Company" port:27017
org:"Target Company" port:6379

# Find exposed S3-style endpoints
http.html:"ListBucketResult" org:"Target Company"
```

---

## Our Own Findings (Reference)

Bugs found and documented in this repo:

| Target | Bug | Severity | File |
|--------|-----|----------|------|
| Klarna | AWS VPC Lattice ARN leak via /oauth2/* | Medium | `reports/klarna/` |
| Razorpay | Unauthenticated OAuth client registration | High | `reports/razorpay/` |
| Razorpay | /revoke returns HTTP 500 on all requests | Medium | `reports/razorpay/` |
| Razorpay | Splitz API unauthenticated | Low | `reports/razorpay/` |
| Elastic | CORS wildcard on upload.elastic.co | Medium | `reports/elastic/` |
| Elastic | JFrog Artifactory 42 repos unauthenticated | Medium | `reports/elastic/` |
| LaunchDarkly | Segment write key + 700 flags via /internal/config/anonymous | Medium | `reports/launchdarkly/` |
| Frontegg | Universal CORS any-origin + null with ACAC:true | High | `reports/frontegg/` |

---

## Sources for `skills/osint-pentest.md` (added June 2026)

Research backing the OSINT / exploitation playbooks. ~130 writeups read across recon, ATO, IDOR, race/logic, injection/SSRF, client-side, GraphQL, cloud, and proxy-tooling.

### Recon & methodology
| Source | Focus | Link |
|--------|-------|------|
| ProjectDiscovery | One-shot recon chain | https://projectdiscovery.io/blog/building-one-shot-recon |
| wolfsec1337 | Passive-first JS recon | https://wolfsec1337.medium.com/practical-javascript-recon-for-bug-bounty-a-real-world-passive-first-workflow-6559a5f4a93d |
| 0x_Ju1ian | JS source-map reconstruction | https://medium.com/@0x_Ju1ian/making-use-of-javascript-source-maps-js-map-files-in-bug-bounty-information-gathering-tips-87deddf1aa8d |
| dwisiswant0 | awesome-oneliner-bugbounty | https://github.com/dwisiswant0/awesome-oneliner-bugbounty |
| msnrasel1 | Vhost discovery | https://msnrasel1.medium.com/vhost-discovery-for-bug-bounty-hunters-8ad2f1caa83d |
| aufzayed | 403 bypass | https://github.com/aufzayed/bugbounty |
| razzlemouse | Tesla recon→RCE ($10k) | https://razzlemouse.medium.com/how-i-discovered-an-rce-vulnerability-in-tesla-securing-a-10-000-bounty-62e725c2a6bd |

### Account takeover & auth
| Source | Focus | Link |
|--------|-------|------|
| anugrahsr | 10 password-reset flaws | https://anugrahsr.github.io/posts/10-Password-reset-flaws/ |
| tuhin1729 | Reset/2FA methodology | https://github.com/tuhin1729/Bug-Bounty-Methodology |
| System Weakness | OTP brute via rate-limit bypass | https://systemweakness.com/brute-forcing-otp-via-bypassing-rate-limit-c5ee6b25c2a8 |
| Doyensec | OAuth common vulns | https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html |
| Descope | nOAuth (email-claim ATO) | https://www.descope.com/blog/post/noauth |
| PortSwigger | JWT attack labs | https://portswigger.net/web-security/jwt |
| USENIX | Pre-hijacking paper | https://arxiv.org/pdf/2205.10174 |

### IDOR / access control
| Source | Focus | Link |
|--------|-------|------|
| arXiv | BOLA empirical taxonomy | https://arxiv.org/html/2605.25865v1 |
| Intigriti | Advanced IDOR guide | https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities |
| Ozgur Alp | Second-order IDOR | https://ozguralp.medium.com/a-less-known-attack-vector-second-order-idor-attacks-14468009781a |
| josephthacker | Unpredictable IDORs (ID leak sources) | https://josephthacker.com/hacking/cybersecurity/2022/08/18/unpredictable-idors.html |
| Cobalt | Mass assignment in the wild | https://www.cobalt.io/blog/mass-assignment-apis-exploitation-in-the-wild |

### Race / logic / payment
| Source | Focus | Link |
|--------|-------|------|
| PortSwigger | Single-packet attack | https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local |
| PortSwigger | Smashing the state machine | https://portswigger.net/research/smashing-the-state-machine |
| Cristian Cornea | Top-25 race reports | https://corneacristian.medium.com/top-25-race-condition-bug-bounty-reports-84f9073bf9e5 |
| Intigriti | Top-6 price manipulation | https://www.intigriti.com/blog/news/top-6-price-manipulation-vulnerabilities-ecommerce |

### Injection / SSRF / RCE
| Source | Focus | Link |
|--------|-------|------|
| Assetnote | Blind SSRF chains | https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/ |
| sirleeroyjenkins | Yahoo gopher SSRF→RCE ($15k) | https://sirleeroyjenkins.medium.com/just-gopher-it-escalating-a-blind-ssrf-to-rce-for-15k-f5329a974530 |
| PortSwigger | SSTI research | https://portswigger.net/research/server-side-template-injection |
| Picus/Team82 | JSON-based SQLi WAF bypass | https://www.picussecurity.com/resource/blog/waf-bypass-using-json-based-sql-injection-attacks |
| PortSwigger (Heyes) | Server-side prototype pollution | https://portswigger.net/research/server-side-prototype-pollution |

### Client-side / mobile
| Source | Focus | Link |
|--------|-------|------|
| PortSwigger | mXSS / DOMPurify bypass | https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss |
| 0xsobky | Ultimate XSS polyglot | https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot |
| Outpost24 | CORS exploitation | https://outpost24.com/blog/exploiting-permissive-cors-configurations/ |
| jlajara | postMessage XSS | https://jlajara.gitlab.io/Dom_XSS_PostMessage |
| streaak | keyhacks (API key validation) | https://github.com/streaak/keyhacks |

### Cloud (AWS / Azure / GCP / K8s)
| Source | Focus | Link |
|--------|-------|------|
| Rhino Security | AWS priv-esc methods | https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/ |
| hackingthe.cloud | AWS exploitation recipes | https://hackingthe.cloud |
| Cobalt | Cognito takeover | https://www.cobalt.io/blog/full-account-takeover-via-aws-cognito-misconfiguration |
| GitLab | Plundering GCP | https://about.gitlab.com/blog/plundering-gcp-escalating-privileges-in-google-cloud-platform/ |
| Datadog | Unauth K8s API server | https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/unauthenticated-api-server/ |
| Aqua | Kubelet API exploitation | https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/ |

### GraphQL
| Source | Focus | Link |
|--------|-------|------|
| PortSwigger | GraphQL academy | https://portswigger.net/web-security/graphql |
| dolevf | graphw00f / Threat Matrix | https://github.com/dolevf/graphw00f |
| Doyensec | GraphQL CSRF | https://blog.doyensec.com/2021/05/20/graphql-csrf.html |
| Wallarm | Batching attack | https://lab.wallarm.com/graphql-batching-attack/ |
| nicholasaleks | CrackQL | https://github.com/nicholasaleks/CrackQL |
| OWASP | GraphQL cheat sheet | https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html |

### Proxy tooling (Burp / Caido)
| Source | Focus | Link |
|--------|-------|------|
| omaroymdm | 10 Burp extensions | https://medium.com/@omaroymdm/these-10-burp-extensions-changed-the-way-i-do-bug-bounties-54daf5b08b15 |
| appsec.guide | Burp tips | https://appsec.guide/docs/web/burp/tips/ |
| Jon Bottarini | Match&Replace privesc | https://www.jonbottarini.com/2019/06/17/using-burp-suite-match-and-replace-settings-to-escalate-your-user-privileges-and-find-hidden-features/ |
| aituglo | Caido 101 | https://aituglo.com/caido/ |
| Caido | HTTPQL reference | https://www.caido.io/httpql/ |

---

*Add new resources here as they're discovered. PRs welcome.*
