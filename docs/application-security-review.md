# Application Security Review

Commit: `f6cc033f30b0214d4a501d7967672446cbf0a654`  
Branch: `cursor/application-security-review-7b43`

## Findings

### 1. [High] Heap buffer overflow when appending DNS search path in idnsALookup

- **Location:** `src/dns_internal.cc`
- **Attacker:** Remote HTTP client whose request triggers DNS resolution
- **Controlled input:** Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators
- **Attack path:** `idnsALookup` copies a max-length name into `q->name` then `strcat` appends search domain without bounds check.
- **Impact:** Heap corruption in Squid worker; potential RCE or DoS.
- **Remediation:** Bound the combined hostname length before appending search domains.

### 2. [Medium] HTTP response header injection via URL rewriter Location value

- **Location:** `src/HttpReply.cc`
- **Attacker:** Remote HTTP client when `url_rewrite_program` is enabled and helper output reflects attacker input
- **Controlled input:** `url=` value from `url_rewrite_program` helper containing CRLF sequences
- **Attack path:** `clientRedirectDone` stores `urlNote` in `redirect.location` without validation; `HttpReply::redirect` calls `putStr(LOCATION)` which `packInto` writes with raw CRLF.
- **Impact:** Response splitting against the client receiving the redirect (e.g. injected `Set-Cookie`).
- **Remediation:** Reject CR/LF in redirect URLs and validate absolute URI form before emitting `Location`.
