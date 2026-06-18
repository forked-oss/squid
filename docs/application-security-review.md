# Application Security Review — squid

**Scanned commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`
**Review date:** 2026-06-17 (PST)

Validated medium, high, and critical findings with end-to-end attack paths.
This document is for maintainer triage; follow each project's security disclosure process before public discussion.

## 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

- **Location:** `src/dns_internal.cc`
- **Attacker:** Remote HTTP client whose request triggers DNS resolution
- **Controlled input:** Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators
- **Attack path:** idnsALookup copies a max-length name into q->name then strcat appends search domain without bounds check
- **Impact:** Heap corruption in Squid worker; potential RCE or DoS

## 2. [HIGH] Cache Manager reflects attacker-controlled Origin with credentialed CORS letting malicious sites read localhost-reachable manager reports

- **Location:** `src/cache_manager.cc`
- **Attacker:** Remote website operator whose page is visited by a user whose browser can reach Squid cache manager on localhost
- **Controlled input:** HTTP Origin header on cache-manager requests
- **Attack path:** PutCommonResponseHeaders echoes Origin into Access-Control-Allow-Origin with Access-Control-Allow-Credentials true; default ACL allows localhost manager access
- **Impact:** Exfiltration of sensitive operational data including live URLs, authenticated usernames, and connection metadata without cachemgr password on many actions

## 3. [MEDIUM] Cache Manager config dump emits WCCP passwords and cache-peer login credentials in cleartext

- **Location:** `src/wccp2.cc`
- **Attacker:** Party who can obtain config cache-manager report via password or credentialed CORS theft
- **Controlled input:** Access to /squid-internal-mgr/config manager action
- **Attack path:** dump_wccp2_service prints WCCP shared secret verbatim; dump_peer_options prints login= values while other secrets are masked
- **Impact:** Disclosure of WCCP MD5 key and upstream peer credentials enabling cluster impersonation or authenticated relay

## 4. [MEDIUM] Reflected XSS in URN resolution page with unescaped URN URL and resolver-supplied URLs in generated HTML

- **Location:** `src/urn.cc`
- **Attacker:** Proxy client crafting URN request URL or attacker controlling URN resolver response
- **Controlled input:** URN URL in client request and URLs returned by external URN resolver
- **Attack path:** urnHandleReply interpolates e->url and resolver u->url into HTML without html_quote
- **Impact:** JavaScript execution in browsers of users whose traffic passes through affected Squid instance

## 5. [MEDIUM] FTP directory listing XSS via unescaped fallback LIST lines

- **Location:** `src/clients/FtpGateway.cc`
- **Attacker:** Malicious FTP server operator or MITM of FTP data channel
- **Controlled input:** FTP LIST line that fails ftpListParseParts parsing containing HTML or JavaScript
- **Attack path:** htmlifyListEntry emits raw line without escaping in the !parts fallback branch; listing HTML inserted into ERR_DIR_LISTING template without quoting
- **Impact:** XSS against users browsing FTP via Squid; session hijack of proxy admin UI
