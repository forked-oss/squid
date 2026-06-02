# Application Security Review — squid

**Scanned commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`  
**Review date:** 2026-06-02 (scheduled cron)  
**Branch:** `cursor/application-security-review-0a64`

## Summary

This review documents **3** validated finding(s) at medium severity or above.

## 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

**Location:** `src/dns_internal.cc`

**Attacker:** Remote HTTP client triggering DNS resolution

**Controlled input:** Hostname at NS_MAXDNAME with fewer than ndots separators

**Attack path:** idnsALookup strcat appends search domain without bounds check after max-length copy

**Impact:** Heap corruption; potential RCE or DoS

**Remediation:** Bound strcat using remaining buffer space

## 2. [MEDIUM] URL rewriter rewrite-url bypasses destination http_access when adapted_http_access is unset

**Location:** `src/client_side_request.cc`

**Attacker:** HTTP client allowed by initial http_access with redirect_program

**Controlled input:** rewrite-url from redirect helper

**Attack path:** URL rewrite applied after http_access without mandatory adapted_http_access re-check

**Impact:** SSRF and ACL bypass to internal destinations

**Remediation:** Re-run http_access on rewritten URL or require adapted_http_access mirroring policy

## 3. [MEDIUM] Store-ID helper can alias cache keys and poison shared cache entries

**Location:** `src/client_side_request.cc`

**Attacker:** Client influencing store_id helper

**Controlled input:** store-id helper response

**Attack path:** clientStoreIdDone sets store_id used as cache key without safety validation

**Impact:** Cross-user cache poisoning

**Remediation:** Validate store-id targets and restrict helper output
