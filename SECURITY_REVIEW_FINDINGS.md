# Application Security Review — squid

**Scanned commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`
**Review date:** 2026-06-02 (scheduled cron)
**Branch:** `cursor/application-security-review-bcf6`

## Summary

This review documents **3** validated finding(s) at medium severity or above.

## 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

**Location:** `src/dns_internal.cc`

**Attacker:** Remote HTTP client whose request triggers DNS resolution

**Controlled input:** Hostname up to NS_MAXDNAME bytes with search path append

**Attack path:** idnsALookup strcat appends search domain without bounds check

**Impact:** Heap corruption; potential RCE or DoS

## 2. [MEDIUM] Host header forgery enables cache poisoning and Host ACL bypass when host_verify_strict is off **[NEW this scan]**

**Location:** `src/client_side_request.cc`

**Attacker:** Remote HTTP client permitted to use forward proxy

**Controlled input:** Mismatched URL authority and Host header

**Attack path:** hostHeaderVerify skipped when hostStrictVerify off; cache keys use URL only

**Impact:** Cross-user cache poisoning and Host ACL bypass

## 3. [MEDIUM] SSL-bumped inner requests skip per-request proxy_auth validation **[NEW this scan]**

**Location:** `src/auth/AclProxyAuth.cc`

**Attacker:** Client with CONNECT-time authentication on SSL-bump proxy

**Controlled input:** Inner HTTP without per-request Proxy-Authorization

**Attack path:** sslBumped requests skip authenticateUserAuthenticated

**Impact:** Per-request proxy_auth policy bypass on bumped HTTPS
