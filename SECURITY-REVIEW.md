# Squid Security Review

Commit: `f6cc033f30b0214d4a501d7967672446cbf0a654`

## New findings (2026-07-01)

### Medium: URN resolution open redirect via attacker-controlled Location header

- **Location:** `src/urn.cc`
- **Attacker:** Any client allowed to send `urn:` requests through the proxy
- **Controlled input:** URLs in the URN resolver response body; lowest-RTT URL becomes `Location`
- **Attack path:** Attacker operates or poisons a URN resolver. Squid selects the attacker URL in `urnFindMinRtt` and returns `302 Found` with `Location` set to that URL without allowlist validation.
- **Impact:** Open redirect and phishing against users whose traffic passes through the proxy.
- **Remediation:** Validate redirect targets against an allowlist or same-origin policy before emitting `Location`.

### Medium: URN resolution triggers ICMP probes to resolver-supplied internal hosts

- **Location:** `src/urn.cc`
- **Attacker:** Any client allowed to send `urn:` requests through the proxy
- **Controlled input:** Hostnames in URN resolver response lines
- **Attack path:** `urnParseReply` calls `netdbPingSite(uri.host())` for hosts with zero RTT. Attacker resolver returns internal hostnames; Squid sends ICMP echo requests from its network position.
- **Impact:** Blind internal-network reconnaissance and host-reachability mapping without the attacker sending ICMP directly.
- **Remediation:** Disable ICMP probing for URN resolution or restrict probe targets to public address space.

## Previously reported findings

| Severity | Title |
|----------|-------|
| High | Heap buffer overflow when appending DNS search path in idnsALookup |
| High | Cache Manager reflects attacker-controlled Origin with credentialed CORS |
| Medium | Cache Manager config dump emits WCCP passwords and cache-peer login credentials |
| Medium | Reflected XSS in URN resolution page |
| Medium | FTP directory listing XSS via unescaped fallback LIST lines |
| Medium | TLS AIA certificate-fetch SSRF via attacker-controlled caIssuers URI |
| High | LDAP DN injection in basic_ldap_auth direct-bind mode |
| Medium | Unauthenticated cachemgr cache enumeration leaks all cached objects |
| Medium | FTP error-page percent-g embeds server-controlled listing without HTML escaping |
