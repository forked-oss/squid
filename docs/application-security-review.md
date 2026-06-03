# Application Security Review

**Scan date (PST):** 2026-06-03  
**Commit:** `f6cc033f30b0214d4a501d7967672446cbf0a654`  
**Branch:** cursor/application-security-review-c0fa

This document records validated medium-and-above vulnerabilities with end-to-end attack paths identified during automated security review. These are findings for maintainer triage, not patches.

## Findings

### 1. [HIGH] Heap buffer overflow when appending DNS search path in idnsALookup

- **Location:** `src/dns_internal.cc`
- **Attacker:** Remote HTTP client whose request triggers DNS resolution
- **Controlled input:** Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators
- **Attack path:** `idnsALookup` copies a max-length name into `q->name` then `strcat` appends search domain without bounds check
- **Impact:** Heap corruption in Squid worker; potential RCE or DoS

### 2. [HIGH] url_regex ACL bypass via percent-encoded null and c_str truncation

- **Location:** `src/acl/Url.cc`
- **Attacker:** Any HTTP client allowed to send requests through the proxy
- **Controlled input:** Percent-encoded null in request-target path such as `/public%00/admin`
- **Attack path:** `DecodeOrDupe` decodes `%00` to NUL; `c_str()` truncates before ACL regex match while full path is forwarded to origin
- **Impact:** Bypass of `url_regex` `http_access` deny rules; possible access to paths ACL never evaluated

### 3. [MEDIUM] urllogin ACL bypass via percent-encoded null in URL userinfo

- **Location:** `src/acl/UrlLogin.cc`
- **Attacker:** Any HTTP client using the proxy
- **Controlled input:** Userinfo with embedded `%00` such as `alloweduser%00blocked:pass@host`
- **Attack path:** `DecodeOrDupe` on `userInfo` then `c_str()` truncates at NUL before `urllogin` regex match
- **Impact:** Bypass of `urllogin`-based ACL rules guarding privileged URL credentials

### 4. [MEDIUM] Stack buffer overflow in SSPI basic auth helper via unbounded sscanf

- **Location:** `src/auth/basic/SSPI/basic_sspi_auth.cc`
- **Attacker:** Client triggering `Proxy-Authorization` on Windows deployments using `basic_sspi_auth`
- **Controlled input:** Basic auth username token over 255 bytes without space on helper stdin line
- **Attack path:** `fgets` reads up to 8196 bytes; `sscanf` `%s %s` into 256-byte stack buffers overflows when first token exceeds 255 bytes
- **Impact:** Memory corruption and potential code execution in auth helper running as Squid service account

## Remediation guidance

- **DNS:** Bound-check before `strcat` when appending search domains in `idnsALookup`.
- **ACL URL matching:** Match on `SBuf` without `c_str()` after `%00` decoding, or reject embedded NULs before regex evaluation.
- **SSPI helper:** Use width-limited `sscanf` or parse with explicit length limits.
