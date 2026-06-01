# Application Security Review (2026-06-01)

Commit: `f6cc033f30b0214d4a501d7967672446cbf0a654`

## Findings

### HIGH: Heap buffer overflow when appending DNS search path

| Field | Detail |
|-------|--------|
| **Location** | `src/dns_internal.cc` |
| **Attacker** | Remote HTTP client whose request triggers DNS resolution for a hostname |
| **Controlled input** | Hostname up to `NS_MAXDNAME` (255) bytes with fewer than `ndots` label separators |
| **Attack path** | `idnsALookup()` accepts names with `nameLength <= NS_MAXDNAME`, copies into `q->name[NS_MAXDNAME + 1]`, then `strcat()` appends `"."` and a resolver search domain without checking remaining space. Typical `resolv.conf` search lists make this reachable. |
| **Impact** | Heap corruption in the Squid worker during DNS resolution; potential RCE or reliable DoS |
| **Remediation** | Reject names that would exceed `NS_MAXDNAME` after search-path append (included in this branch) |
