# Application Security Review

Automated security findings for **squid**.

- **Generated:** 2026-06-27 02:03 UTC
- **Scanned commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`
- **Active findings:** 6

## Summary

| Severity | Count |
|----------|------:|
| high | 2 |
| medium | 4 |

## Findings

### 1. Cache Manager reflects attacker-controlled Origin with credentialed CORS letting malicious sites read localhost-reachable manager reports

- **Severity:** high
- **Status:** active
- **Location:** src/cache_manager.cc
- **Commit:** f6cc033f30b0214d4a501d7967672446cbf0a654
- **Detected (PST):** 2026-06-12T19:00:22-07:00
- **Reported:** https://github.com/forked-oss/squid/pull/21
- **Attacker:** Remote website operator whose page is visited by a user whose browser can reach Squid cache manager on localhost
- **Controlled input:** HTTP Origin header on cache-manager requests
- **Attack path:** PutCommonResponseHeaders echoes Origin into Access-Control-Allow-Origin with Access-Control-Allow-Credentials true; default ACL allows localhost manager access
- **Impact:** Exfiltration of sensitive operational data including live URLs, authenticated usernames, and connection metadata without cachemgr password on many actions

### 2. Heap buffer overflow when appending DNS search path in idnsALookup

- **Severity:** high
- **Status:** active
- **Location:** src/dns_internal.cc
- **Commit:** f6cc033f30b0214d4a501d7967672446cbf0a654
- **Detected (PST):** 2026-06-01T00:12:00-07:00
- **Attacker:** Remote HTTP client whose request triggers DNS resolution
- **Controlled input:** Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators
- **Attack path:** idnsALookup copies a max-length name into q->name then strcat appends search domain without bounds check
- **Impact:** Heap corruption in Squid worker; potential RCE or DoS

### 3. Cache Manager config dump emits WCCP passwords and cache-peer login credentials in cleartext

- **Severity:** medium
- **Status:** active
- **Location:** src/wccp2.cc
- **Commit:** f6cc033f30b0214d4a501d7967672446cbf0a654
- **Detected (PST):** 2026-06-12T19:00:22-07:00
- **Reported:** https://github.com/forked-oss/squid/pull/21
- **Attacker:** Party who can obtain config cache-manager report via password or credentialed CORS theft
- **Controlled input:** Access to /squid-internal-mgr/config manager action
- **Attack path:** dump_wccp2_service prints WCCP shared secret verbatim; dump_peer_options prints login= values while other secrets are masked
- **Impact:** Disclosure of WCCP MD5 key and upstream peer credentials enabling cluster impersonation or authenticated relay

### 4. FTP directory listing XSS via unescaped fallback LIST lines

- **Severity:** medium
- **Status:** active
- **Location:** src/clients/FtpGateway.cc
- **Commit:** f6cc033f30b0214d4a501d7967672446cbf0a654
- **Detected (PST):** 2026-06-15T19:34:51-07:00
- **Reported:** https://github.com/forked-oss/squid/pull/24
- **Attacker:** Malicious FTP server operator or MITM of FTP data channel
- **Controlled input:** FTP LIST line that fails ftpListParseParts parsing containing HTML or JavaScript
- **Attack path:** htmlifyListEntry emits raw line without escaping in the !parts fallback branch; listing HTML inserted into ERR_DIR_LISTING template without quoting
- **Impact:** XSS against users browsing FTP via Squid; session hijack of proxy admin UI

### 5. Reflected XSS in URN resolution page with unescaped URN URL and resolver-supplied URLs in generated HTML

- **Severity:** medium
- **Status:** active
- **Location:** src/urn.cc
- **Commit:** f6cc033f30b0214d4a501d7967672446cbf0a654
- **Detected (PST):** 2026-06-13T19:25:43-07:00
- **Reported:** https://github.com/forked-oss/squid/pull/22
- **Attacker:** Proxy client crafting URN request URL or attacker controlling URN resolver response
- **Controlled input:** URN URL in client request and URLs returned by external URN resolver
- **Attack path:** urnHandleReply interpolates e->url and resolver u->url into HTML without html_quote
- **Impact:** JavaScript execution in browsers of users whose traffic passes through affected Squid instance

### 6. TLS AIA certificate-fetch SSRF via attacker-controlled caIssuers URI

- **Severity:** medium
- **Status:** active
- **Location:** src/ssl/support.cc
- **Commit:** f6cc033f30b0214d4a501d7967672446cbf0a654
- **Detected (PST):** 2026-06-25T19:00:36-07:00
- **Attacker:** Remote client triggering HTTPS origin connections where Squid validates TLS chains
- **Controlled input:** caIssuers URI in upstream server X.509 Authority Info Access extension
- **Attack path:** PeerConnector handleMissingCertificates collects AIA URIs via findIssuerUri and Downloader fetches them with no private-IP or metadata URL blocking
- **Impact:** Blind SSRF from Squid process to internal services and cloud metadata during TLS chain validation
