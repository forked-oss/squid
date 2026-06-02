# Application Security Review — squid

**Scanned commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`  
**Review date:** 2026-06-02 (scheduled cron)  
**Branch:** `cursor/application-security-review-5025`

## Summary

This review documents **3** validated finding(s) at medium severity or above.

## 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

**Location:** `src/dns_internal.cc`

**Attacker:** Remote HTTP client whose request triggers DNS resolution

**Controlled input:** Hostname up to `NS_MAXDNAME` bytes with fewer than `ndots` label separators

**Attack path:** `idnsALookup` copies a max-length name into `q->name` then `strcat` appends the search domain without verifying remaining buffer space

**Impact:** Heap corruption in the Squid worker; potential remote code execution or denial of service

**Remediation:** Use bounded string concatenation with explicit length checks before appending search domains.

## 2. [MEDIUM] Web cache poisoning via duplicate Host headers on forward proxy

**Location:** `src/client_side_request.cc`

**Attacker:** Any client allowed to use the forward proxy with `host_strict_verify` enabled

**Controlled input:** Two `Host` headers where the first matches the request-URI authority and the second is attacker-controlled

**Attack path:** `hostHeaderVerify` uses `HttpHeader::getStr`, which returns only the first `Host`; `packInto` forwards all `Host` entries to the origin, which may honor the last value; the cache key omits the rogue `Host`

**Impact:** Cross-user cache poisoning delivering attacker-controlled content for victim URLs

**Remediation:** Reject requests with multiple `Host` headers or verify every `Host` value against the request URI before caching.

## 3. [MEDIUM] ssl_bump stare mode forces MITM when final ssl_bump ACL denies

**Location:** `src/ssl/PeekingPeerConnector.cc`

**Attacker:** HTTPS client through an `ssl-bump` port classified into stare mode

**Controlled input:** TLS connection at peek step 3 where the `ssl_bump` ACL returns deny

**Attack path:** `checkForPeekAndSpliceDone` calls `checkForPeekAndSpliceGuess` on deny; when `sslBumpMode` is `bumpStare`, guess returns `bumpBump` instead of `bumpSplice`

**Impact:** SSL bump policy bypass forcing interception despite an explicit `ssl_bump` deny at the final peek decision

**Remediation:** On ACL deny at step 3, default to splice (or terminate) rather than inferring bump from stare mode.
