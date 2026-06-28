# Application Security Review

Commit: `f6cc033f30b0214d4a501d7967672446cbf0a654`

## New Finding (2026-06-27)

### LDAP DN injection in basic_ldap_auth direct-bind mode (High)

- **Location:** `src/auth/basic/LDAP/basic_ldap_auth.cc`
- **Attacker:** Unauthenticated HTTP client using Basic authentication against Squid when `basic_ldap_auth` runs without `-f searchfilter` (direct-bind mode)
- **Controlled input:** Username with URL-encoded LDAP metacharacters such as `victim%2Cou%3Dadmins`
- **Attack path:** Squid URL-decodes the username before forwarding it to the helper. `validUsername()` does not reject `,` or `=`. In direct-bind mode the helper builds `uid=<userid>,<basedn>` without escaping, so injected commas change the bind DN. `ldap_simple_bind_s()` then authenticates against the attacker-selected entry.
- **Impact:** Authentication bypass allowing login as arbitrary LDAP accounts when the attacker knows valid credentials for a different DN subtree
- **Remediation:** Reject usernames containing LDAP DN metacharacters or always use a parameterized search filter with `ldap_escape_value()`
