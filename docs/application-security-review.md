# Application Security Review — squid

**Scanned commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`
**Review date:** 2026-06-11 (PST)

Validated medium, high, and critical findings with end-to-end attack paths.

## [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

- **Location:** `src/dns_internal.cc`
- **Attacker:** Remote proxy client
- **Controlled input:** Hostname up to NS_MAXDNAME single-label
- **Attack path:** strcat appends search domain without bounds when res_defnames on
- **Impact:** Heap corruption; crash or potential RCE
