# Application Security Review Findings

Scanned commit: `f6cc033f30b0214d4a501d7967672446cbf0a654`

## High: Heap buffer overflow when appending DNS search path in idnsALookup

**Location:** `src/dns_internal.cc`

**Attacker:** Remote HTTP client whose request triggers DNS resolution.

**Controlled input:** Hostname up to `NS_MAXDNAME` bytes with fewer than `ndots` label separators.

**Attack path:** `idnsALookup` copies a max-length name into `q->name` then `strcat` appends search domain without bounds check.

**Impact:** Heap corruption in Squid worker; potential RCE or DoS.

**Remediation:** Use bounded string concatenation with explicit buffer size checks before appending search domains.

## Medium: Intercepted Host-header forgery bypasses URL-based http_access rules under default configuration

**Location:** `src/client_side_request.cc`

**Attacker:** Any client on a NAT/TPROXY-intercepted path.

**Controlled input:** Forged `Host:` header (and derived request URL built from it).

**Attack path:** Client opens a TCP connection intercepted by Squid to a blocked destination IP. Squid builds the request URL from `Host:` via `buildUrlFromHost()`. `hostHeaderVerify()` DNS-checks `Host:` against the intercepted local destination; verification fails. With default `host_verify_strict off`, `hostHeaderVerifyFailed()` logs and continues instead of returning HTTP 409. `clientAccessCheck()` evaluates URL-based ACLs (`dstdomain`, `url`, `url_regex`, etc.) against the forged hostname in the URL—not the real destination. Deny rules for the real destination do not match; an allow rule matches. Forwarding uses `ORIGINAL_DST` to the real blocked IP because `!hostVerified` forces original-destination routing.

**Impact:** ACL bypass on transparent/intercept deployments using domain/URL-based rules; blocked sites reachable by forging `Host:`.

**Remediation:** Enable `host_verify_strict on` by default for intercept deployments, or evaluate ACLs against both the forged URL and the original destination IP.

## Medium: TLS 1.3 peek-mode SSL bump step-3 ACL is skipped, forcing splice without policy evaluation

**Location:** `src/ssl/PeekingPeerConnector.cc`

**Attacker:** Any HTTPS client or server negotiating TLS 1.3 through a peek/stare bump path.

**Controlled input:** TLS 1.3 handshake (encrypted certificates; optional session resumption).

**Attack path:** Squid is configured for SSL bump with peek/stare at step 2 and step-3 `ssl_bump` rules intended to bump, splice, or terminate based on server certificate properties. During peek, server certificate validation fails (expected for TLS 1.3 where certificates are encrypted). `noteNegotiationError()` detects `encryptedCertificates()` (true for TLS 1.3+) or `resumingSession()`. Code calls `checkForPeekAndSpliceMatched(Ssl::bumpSplice)` directly, bypassing `checkForPeekAndSplice()` which normally runs the step-3 `ssl_bump` ACL via `NonBlockingCheck`. Connection is spliced (tunneled uninspected) regardless of step-3 policy.

**Impact:** SSL/TLS interception policy bypass for TLS 1.3 (and resumed sessions) in peek mode; traffic exits uninspected even when step-3 rules would require bump or terminate.

**Remediation:** Run step-3 `ssl_bump` ACL evaluation even when certificates are encrypted, using available ClientHello/server metadata, or default to terminate rather than splice when policy cannot be evaluated.
