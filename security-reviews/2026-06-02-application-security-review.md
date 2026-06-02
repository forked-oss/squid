# Application Security Review — squid

**Scanned commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`  
**Review date:** 2026-06-02 (scheduled cron)  
**Branch:** `cursor/application-security-review-1987`

## Summary

This review documents **3** validated finding(s) at medium severity or above.

## 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

**Location:** `src/dns_internal.cc`

**Attacker:** Remote HTTP client whose request triggers DNS resolution

**Controlled input:** Hostname up to NS_MAXDNAME with fewer than ndots separators

**Attack path:** idnsALookup copies max-length name then strcat appends search domain without bounds check

**Impact:** Heap corruption; potential RCE or DoS

## 2. [HIGH] Store-ID helper can poison cache for normalized URLs while fetching attacker URL

**Location:** `src/client_side_request.cc`

**Attacker:** External HTTP proxy client when store_id_program is configured

**Controlled input:** Request URL and store-id note from helper

**Attack path:** Cache keys use storeId() while fetch uses original URL

**Impact:** Cross-user web cache poisoning

## 3. [MEDIUM] URL rewrite helper can reach destinations blocked by http_access when adapted_http_access is unset

**Location:** `src/client_side_request.cc`

**Attacker:** External proxy client when url_rewrite_program is enabled

**Controlled input:** rewrite-url from helper

**Attack path:** http_access runs once; clientAccessCheck2 defaults ALLOW without adapted_http_access

**Impact:** ACL bypass and SSRF to internal URLs
