# Application Security Review — squid

**Scanned commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`
**Review date:** 2026-06-02

## Summary

**1** validated finding(s) at medium severity or above.

### 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

**Location:** `src/dns_internal.cc`

**Attacker:** Remote HTTP client whose request triggers DNS resolution

**Controlled input:** Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators

**Attack path:** idnsALookup copies a max-length name into q->name then strcat appends search domain without bounds check

**Impact:** Heap corruption in Squid worker; potential RCE or DoS

**Remediation:** Apply input validation and authorization at the trust boundary; use parameterized APIs and post-resolution permission checks where applicable.
