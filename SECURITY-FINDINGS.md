# Application Security Review — squid

**Scan commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`  
**Review date:** 2026-07-03 (PST)

No new findings this scan.

## Active findings inventory

| Severity | Location | Title |
|----------|----------|-------|
| high | src/dns_internal.cc | Heap buffer overflow when appending DNS search path in idnsALookup |
| high | src/cache_manager.cc | Cache Manager reflects attacker-controlled Origin with credentialed CORS letting malicious sites read localhost-reachable manager reports |
| medium | src/wccp2.cc | Cache Manager config dump emits WCCP passwords and cache-peer login credentials in cleartext |
| medium | src/urn.cc | Reflected XSS in URN resolution page with unescaped URN URL and resolver-supplied URLs in generated HTML |
| medium | src/clients/FtpGateway.cc | FTP directory listing XSS via unescaped fallback LIST lines |
| medium | src/ssl/support.cc | TLS AIA certificate-fetch SSRF via attacker-controlled caIssuers URI |
| high | src/auth/basic/LDAP/basic_ldap_auth.cc | LDAP DN injection in basic_ldap_auth direct-bind mode |
| medium | src/stat.cc | Unauthenticated cachemgr cache enumeration leaks all cached objects |
| medium | src/errorpage.cc | FTP error-page percent-g embeds server-controlled listing without HTML escaping |
| medium | src/urn.cc | URN resolution open redirect via attacker-controlled Location header |
| medium | src/urn.cc | URN resolution triggers ICMP probes to resolver-supplied internal hosts |

Findings tracked in automation memory (`squid---flagged-vulnerabilities.json`).
