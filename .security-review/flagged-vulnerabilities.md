# Application Security Review — squid

Scanned commit: `f6cc033f30b0214d4a501d7967672446cbf0a654`
Detected: 2026-06-02T05:08:41-07:00

Validated medium, high, and critical findings with end-to-end attack paths.

## 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

**Location:** `src/dns_internal.cc`

**Attacker:** Remote HTTP client whose request triggers DNS resolution

**Controlled input:** Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators

**Attack path:** idnsALookup copies a max-length name into q->name (NS_MAXDNAME+1) then strcat appends "." and searchpath domain without remaining space check

**Impact:** Heap corruption in Squid worker; potential RCE or DoS

## 2. [HIGH] store_id_program enables cross-URL cache poisoning when helper output is attacker-influenced

**Location:** `src/client_side_request.cc`

**Attacker:** HTTP client allowed by http_access and store_id ACLs when store_id_program is configured

**Controlled input:** Request URL and headers influencing store_id helper store-id response note

**Attack path:** Helper returns store-id for victim host while origin fetch uses attacker URL; cache keyed by storeId serves attacker content on victim requests

**Impact:** Persistent cache poisoning delivering attacker-controlled responses for unrelated URLs

## 3. [HIGH] Stack buffer overflow in peer login=PASS credential encoding from external_acl

**Location:** `src/http.cc`

**Attacker:** Client influencing external_acl helper output when cache_peer uses login=PASS

**Controlled input:** Unbounded user= and password= fields in external ACL helper response (up to HELPER_INPUT_BUFFER)

**Attack path:** httpBuildRequestHeader base64-encodes extacl_user and extacl_passwd into loginbuf sized for MAX_LOGIN_SZ (128) via base64_encode_update with no output bounds check

**Impact:** Stack buffer overflow in Squid worker; memory corruption and potential RCE

## 4. [MEDIUM] url_rewrite_program bypasses http_access for rewritten destinations when adapted_http_access unset

**Location:** `src/client_side_request.cc`

**Attacker:** Client passing initial http_access when url_rewrite_program is configured

**Controlled input:** Redirect helper rewrite-url response pointing to blocked internal destination

**Attack path:** clientAccessCheck runs once; after URL rewrite http_access_done prevents re-check; adapted_http_access defaults ALLOW

**Impact:** SSRF and ACL bypass to internal or forbidden destinations via rewritten URL

## 5. [MEDIUM] Unauthenticated cache manager disclosure from localhost by default

**Location:** `src/cache_manager.cc`

**Attacker:** Any process on the Squid host (local attacker, container escape, co-hosted SSRF)

**Controlled input:** HTTP request to /squid-internal-mgr/ actions such as info, objects, or username_cache

**Attack path:** Default http_access allow localhost manager; CheckPassword returns allow when action has no cachemgr_passwd entry; many RegisterAction handlers require no password

**Impact:** Disclosure of cache contents, authenticated usernames, client IPs, and operational topology
