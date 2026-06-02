# Application Security Review Findings

Commit scanned: `f6cc033f30b0214d4a501d7967672446cbf0a654`

## 1. High: Heap buffer overflow when appending DNS search path in idnsALookup

- Severity: High
- Primary location: `src/dns_internal.cc`
- Attacker: Remote HTTP client whose request triggers DNS resolution
- Controlled input: Hostname up to `NS_MAXDNAME` (1025) bytes with fewer than `ndots` label separators so search-path expansion runs
- Attack path: `idnsALookup` rejects `nameLength > NS_MAXDNAME` but allows a 1025-byte name into `q->name[NS_MAXDNAME + 1]`; when `res_defnames` applies, `strcat(q->name, ".")` and `strcat(q->name, searchpath[...].domain)` append past the fixed buffer
- Impact: Heap corruption in the Squid worker process; potential RCE or denial of service
- Remediation: Check combined length of name, dot, and search domain before strcat; use bounded string APIs

## 2. Medium: Forward-proxy web cache poisoning via Host and request-URI desync

- Severity: Medium
- Primary location: `src/client_side_request.cc`
- Attacker: Client of an open forward HTTP proxy with caching enabled
- Controlled input: `GET http://victim.example/asset HTTP/1.1` with a forged `Host: attacker.example` header
- Attack path: With default `host_verify_strict off`, forward-proxy Host validation is skipped (`validate skipped` → `doCallouts()`). Squid connects using the request-line URL but forwards the attacker `Host` header. Cache keys use `storeId()` / `effectiveRequestUri()` (request-line URL), not `Host`. `maybeCacheable()` does not block forward-proxy Host mismatches.
- Impact: Attacker poisons a shared cache entry; other proxy users requesting the same URL receive attacker-controlled content
- Remediation: Enable `host_verify_strict on` for untrusted forward-proxy clients; ensure origins emit `Vary: Host` where vhost-sensitive; deny caching for assets that vary by Host

## 3. Medium: URL rewrite bypasses http_access destination controls without adapted_http_access

- Severity: Medium
- Primary location: `src/client_side_request.cc`
- Attacker: Client allowed by initial `http_access`, or operator of a compromised `url_rewrite_program` helper
- Controlled input: `rewrite-url` from `url_rewrite_program` pointing at internal destinations (for example `http://127.0.0.1/admin`)
- Attack path: `doCallouts()` runs `http_access` on the original URL, then `clientRedirectStart()` may replace the URL. `clientAccessCheck2()` runs `adapted_http_access` only when configured; otherwise it logs `default: ALLOW` and permits the rewritten destination without re-evaluating dst-based ACLs.
- Impact: SSRF and ACL bypass to internal hosts that were blocked only at the first `http_access` check
- Remediation: Mirror dst/src ACLs in `adapted_http_access`; treat rewrite helpers as trusted code; restrict rewrite output
