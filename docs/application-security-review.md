# Application Security Review — squid

**Scan date:** 2026-06-02 (Pacific)
**Commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`
**Branch:** `cursor/application-security-review-126f`

Validated medium, high, and critical findings with end-to-end attack paths.
This document is for maintainer tracking; follow each project's security disclosure process before public discussion.

## 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

- **Location:** `src/dns_internal.cc`
- **Impact:** Heap corruption in Squid worker; potential RCE or DoS when dns_defnames enabled

## Remediation priorities

Address high-severity items first. Each finding should be verified on the scanned commit before patch design.
