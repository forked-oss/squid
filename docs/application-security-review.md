# Application Security Review — squid

**Scanned commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`
**Review date:** 2026-06-12 (PST)

Validated medium, high, and critical findings with end-to-end attack paths.
This document is for maintainer triage; follow each project's security disclosure process before public discussion.

## 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

- **Location:** `src/dns_internal.cc`
- **Attacker:** Remote HTTP client whose request triggers DNS resolution
- **Controlled input:** Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators
- **Attack path:** idnsALookup copies max-length name into q->name then strcat appends search domain without bounds check
- **Impact:** Heap corruption in Squid worker; potential RCE or DoS

## 2. [HIGH] url_regex ACL bypass via percent-encoded null and c_str truncation

- **Location:** `src/acl/Url.cc`
- **Attacker:** Any HTTP client allowed to send requests through the proxy
- **Controlled input:** Percent-encoded null in request-target path such as /public%00/admin
- **Attack path:** DecodeOrDupe decodes %00 to NUL; c_str() truncates before ACL regex match while full path is forwarded
- **Impact:** Bypass of url_regex http_access deny rules; access to paths ACL never evaluated

## 3. [MEDIUM] urllogin ACL bypass via percent-encoded null in URL userinfo

- **Location:** `src/acl/UrlLogin.cc`
- **Attacker:** Any HTTP client using the proxy
- **Controlled input:** Userinfo with embedded %00 such as alloweduser%00blocked:pass@host
- **Attack path:** DecodeOrDupe on userInfo then c_str() truncates at NUL before urllogin regex match
- **Impact:** Bypass of urllogin-based ACL rules guarding privileged URL credentials

## 4. [MEDIUM] Stack buffer overflow in SSPI basic auth helper via unbounded sscanf

- **Location:** `src/auth/basic/SSPI/basic_sspi_auth.cc`
- **Attacker:** Client triggering Proxy-Authorization on Windows deployments using basic_sspi_auth
- **Controlled input:** Basic auth username token over 255 bytes without space
- **Attack path:** fgets reads up to 8196 bytes; sscanf %s %s into 256-byte stack buffers overflows when first token exceeds 255 bytes
- **Impact:** Memory corruption and potential code execution in auth helper running as Squid service account

## 5. [HIGH] Cache Manager reflects attacker-controlled Origin with credentialed CORS letting malicious sites read localhost-reachable manager reports

- **Location:** `src/cache_manager.cc`
- **Attacker:** Remote website operator whose page is visited by user whose browser can reach Squid cache manager on localhost
- **Controlled input:** HTTP Origin header on cache-manager requests
- **Attack path:** PutCommonResponseHeaders echoes Origin into Access-Control-Allow-Origin with Access-Control-Allow-Credentials true; default ACL allows localhost manager access
- **Impact:** Exfiltration of sensitive operational data including live URLs, authenticated usernames, and connection metadata without cachemgr password on many actions

## 6. [MEDIUM] Cache Manager config dump emits WCCP passwords and cache-peer login credentials in cleartext

- **Location:** `src/wccp2.cc`
- **Attacker:** Party who can obtain config cache-manager report via password or credentialed CORS theft
- **Controlled input:** Access to /squid-internal-mgr/config manager action
- **Attack path:** dump_wccp2_service prints WCCP shared secret verbatim; dump_peer_options prints login= values while other secrets are masked
- **Impact:** Disclosure of WCCP MD5 key and upstream peer credentials enabling cluster impersonation or authenticated relay
