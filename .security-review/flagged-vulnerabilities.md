# Application Security Review — squid

Scanned commit: `f6cc033f30b0214d4a501d7967672446cbf0a654`
Detected: 2026-06-02T03:19:18-07:00

Validated medium, high, and critical findings with end-to-end attack paths.

## 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

**Location:** `src/dns_internal.cc`

**Attacker:** Remote HTTP client whose request triggers DNS resolution

**Controlled input:** Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators

**Attack path:** idnsALookup copies a max-length name into q->name then strcat appends search domain without bounds check

**Impact:** Heap corruption in Squid worker; potential RCE or DoS

## 2. [HIGH] store_id_program enables cross-URL cache poisoning when helper output is attacker-influenced

**Location:** `src/client_side_request.cc`

**Attacker:** HTTP client allowed by http_access and store_id ACLs when store_id_program is configured

**Controlled input:** Request URL and headers influencing store_id helper store-id response note

**Attack path:** Helper returns store-id for victim host while origin fetch uses attacker URL; cache keyed by storeId serves attacker content on victim requests

**Impact:** Persistent cache poisoning delivering attacker-controlled responses for unrelated URLs

## 3. [MEDIUM] url_rewrite_program bypasses http_access for rewritten destinations when adapted_http_access unset

**Location:** `src/client_side_request.cc`

**Attacker:** Client passing initial http_access when url_rewrite_program is configured

**Controlled input:** Redirect helper rewrite-url response pointing to blocked internal destination

**Attack path:** clientAccessCheck runs once; after URL rewrite http_access_done prevents re-check; adapted_http_access defaults ALLOW

**Impact:** SSRF and ACL bypass to internal or forbidden destinations via rewritten URL
