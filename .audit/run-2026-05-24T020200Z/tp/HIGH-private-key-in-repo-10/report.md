# private-key-in-repo

| Field | Value |
|-------|-------|
| Severity | HIGH |
| Repository | squid |
| Commit | f6cc033f30b0214d4a501d7967672446cbf0a654 |
| File | /agent/repos/squid/src/security/cert_generators/file/security_file_certgen.cc |
| Line | 65 |

## Summary

Pattern `BEGIN (RSA |OPENSSH )?PRIVATE KEY` matched in source.

## Status

True positive (heuristic pattern match — requires manual validation).
