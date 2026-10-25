# Security policy

Do not deploy the historical 1.x installer. The 2.0 work is a security-focused replacement requiring isolated VM acceptance before production. Support is scoped to the documented Rocky Linux 9 target; no multi-node availability or zero-downtime restore guarantee is made.

Report suspected vulnerabilities privately to the repository owner's established security contact or GitHub private vulnerability reporting when enabled. Do not publish credentials, mailbox contents or exploitable production details in public issues. Repository administrators must configure the reporting channel, branch protections, required CI, restricted release rights, signed release provenance, secret scanning and dependency advisory handling; source files cannot enable account-level protections by themselves.

Operators must track upstream advisories for OS packages, PHP, Roundcube, PostfixAdmin and their dependencies. Version floors and checksums are not a continuous vulnerability scanner. Target critical-patch response within 24 hours after exposure assessment and staging validation. Maintain independent recoverable backups and an accountable on-call operator.

Review `docs/IMPLEMENTATION.md` for what is implemented and what still requires environmental evidence. TLS and encrypted backups do not provide end-to-end email encryption. A clean local test run is not certification of a production server.
