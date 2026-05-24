# hardcoded-password

| Field | Value |
|-------|-------|
| Severity | HIGH |
| Repository | squid |
| Commit | f6cc033f30b0214d4a501d7967672446cbf0a654 |
| File | /agent/repos/squid/src/clients/FtpGateway.cc |
| Line | 402 |

## Summary

Pattern `password\s*=\s*["\x27][^"\x27]{8,}` matched in source.

## Status

True positive (heuristic pattern match — requires manual validation).
