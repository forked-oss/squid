# Application Security Review Findings

Commit scanned: `f6cc033f30b0214d4a501d7967672446cbf0a654`

## 1. High: Heap buffer overflow when appending DNS search path in idnsALookup

- Severity: High
- Primary location: `src/dns_internal.cc`
- Attacker: Remote HTTP client whose request triggers DNS resolution.
- Controlled input: Hostname up to NS_MAXDNAME bytes with fewer than ndots label separators.
- Attack path: `idnsALookup` copies a max-length name into `q->name` then `strcat` appends search domain without bounds check.
- Impact: Heap corruption in Squid worker; potential RCE or DoS.
- Remediation: Use bounded string concatenation with explicit buffer size checks.

## 2. High: FTP control-channel command injection via URL-decoded CRLF in credentials and path

- Severity: High
- Primary location: `src/clients/FtpGateway.cc`
- Attacker: Any HTTP client allowed by `http_access` to request `ftp://` URLs through Squid's HTTP→FTP gateway.
- Controlled input: `ftp://` URL user-info and path segments after `rfc1738_unescape()`, including percent-encoded `%0d`/`%0a`; or `Authorization: Basic` credentials containing raw CR/LF.
- Attack path: Decoded credentials and path components are passed to `snprintf`-formatted FTP control commands (`USER`, `PASS`, `CWD`, `RETR`, etc.) without CRLF sanitization. Embedded newlines split one command into multiple FTP protocol lines on the upstream control connection.
- Impact: Arbitrary additional FTP commands injected against upstream FTP servers reachable from Squid, enabling unauthorized file read/write/delete depending on upstream permissions.
- Remediation: Reject or strip `\r`, `\n`, and other control characters from decoded user-info and path components before formatting FTP control commands.
