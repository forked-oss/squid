# Security Review — 2026-07-01

Commit scanned: `f6cc033f30b0214d4a501d7967672446cbf0a654`

**Findings:** 9 (2 new in this scan)

## New findings (this scan)

### Medium: Unauthenticated cachemgr cache enumeration leaks all cached objects

- **Location:** `src/stat.cc`
- **Attacker:** Remote client reaching cache manager URLs when http_access permits manager access
- **Attack path:** objects vm_objects and openfd_objects actions register with Protected::no so CheckPassword returns success when no cachemgr_passwd entry exists dumping full store contents
- **Impact:** Enumeration of cached URLs metadata and sensitive cached response content

### Medium: FTP error-page percent-g embeds server-controlled listing without HTML escaping

- **Location:** `src/errorpage.cc`
- **Attacker:** Malicious FTP server operator serving proxied FTP traffic
- **Attack path:** errorpage case g appends ftp.listing raw with do_quote=0 into text/html error pages without html_quote
- **Impact:** Reflected XSS in Squid error-page origin enabling session theft against proxy users

## All tracked findings

- **High:** Heap buffer overflow when appending DNS search path in idnsALookup
- **High:** Cache Manager reflects attacker-controlled Origin with credentialed CORS letting malicious sites read localhost-reachable manager reports
- **High:** Cache Manager config dump emits WCCP passwords and cache-peer login credentials in cleartext
- **High:** Reflected XSS in URN resolution page with unescaped URN URL and resolver-supplied URLs in generated HTML
- **High:** FTP directory listing XSS via unescaped fallback LIST lines
- **High:** TLS AIA certificate-fetch SSRF via attacker-controlled caIssuers URI
- **High:** LDAP DN injection in basic_ldap_auth direct-bind mode
- **High:** Unauthenticated cachemgr cache enumeration leaks all cached objects
- **High:** FTP error-page percent-g embeds server-controlled listing without HTML escaping
