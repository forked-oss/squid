# Application Security Review Findings

Scanned commit: `f6cc033f30b0214d4a501d7967672446cbf0a654`

Validated medium, high, and critical issues with end-to-end attack paths.

## 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

**Location:** `src/dns_internal.cc`

**Attacker:** Remote HTTP client whose request triggers DNS resolution

**Controlled input:** Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators

**Attack path:** idnsALookup copies max-length name into q->name then strcat appends search domain without bounds check

**Impact:** Heap corruption in Squid worker; potential RCE or DoS

## 2. [MEDIUM] Post-ICAP reqmod ACL bypass when adapted_http_access is unset

**Location:** `src/client_side_request.cc`

**Attacker:** HTTP client when reqmod ICAP or eCAP can mutate requests

**Controlled input:** ICAP-adapted request URL or headers that would fail virgin http_access

**Attack path:** http_access runs once on virgin request then clientAccessCheck2 allows all when adapted_http_access has no rules

**Impact:** ACL bypass to restricted destinations after ICAP adaptation
