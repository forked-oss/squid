# Security Review — 2026-06-30

Commit scanned: `f6cc033f30b0214d4a501d7967672446cbf0a654`

**Findings:** 7 (no new findings in this scan)

## Known findings

- **High:** Cache Manager reflects attacker-controlled Origin with credentialed CORS letting malicious sites read localhost-reachable manager reports
- **High:** Heap buffer overflow when appending DNS search path in idnsALookup
- **High:** LDAP DN injection in basic_ldap_auth direct-bind mode
- **Medium:** Cache Manager config dump emits WCCP passwords and cache-peer login credentials in cleartext
- **Medium:** FTP directory listing XSS via unescaped fallback LIST lines
- **Medium:** Reflected XSS in URN resolution page with unescaped URN URL and resolver-supplied URLs in generated HTML
- **Medium:** TLS AIA certificate-fetch SSRF via attacker-controlled caIssuers URI
