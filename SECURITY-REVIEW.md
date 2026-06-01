# Application Security Review

**Branch:** `cursor/application-security-review-8f44`  
**Commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`  
**Reviewed:** 2026-06-01

## Findings

### [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

| Field | Detail |
|-------|--------|
| **Location** | `src/dns_internal.cc` |
| **Attacker** | Remote HTTP client whose request triggers DNS resolution |
| **Controlled input** | Hostname up to `NS_MAXDNAME` bytes with fewer than `ndots` label separators |
| **Attack path** | `idnsALookup` allows names up to `NS_MAXDNAME` bytes into `q->name[NS_MAXDNAME+1]`, then `strcat` appends `"."` and the search domain without a bounds check. |
| **Impact** | Heap corruption in the Squid worker; potential RCE or DoS. |
| **Remediation** | Check remaining buffer space before appending search path; reject names that leave insufficient room. |

### [HIGH] http_access not re-evaluated after URL rewrite; adapted_http_access defaults to ALLOW

| Field | Detail |
|-------|--------|
| **Location** | `src/client_side_request.cc` |
| **Attacker** | Any client allowed by `http_access` on the original URL |
| **Controlled input** | Request URL matching a redirector/StoreID rule that rewrites to a restricted destination |
| **Attack path** | `http_access` runs once and sets `http_access_done`. After `clientRedirectDone` rewrites the URL via `resetRequestXXX()`, `doCallouts()` runs again but skips `http_access`. If `adapted_http_access` is unset, `clientAccessCheck2()` defaults to `ACCESS_ALLOWED`. Squid forwards to destinations blocked on the original URL. |
| **Impact** | ACL bypass / SSRF to internal hosts and admin paths when redirectors are used without explicit `adapted_http_access` rules. |
| **Remediation** | Configure `adapted_http_access` with default deny; re-run `http_access` or reset `http_access_done` after URL rewrite. |
