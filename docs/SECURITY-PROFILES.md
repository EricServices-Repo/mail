# Additional security profiles

These tools target a dedicated Rocky Linux 9 host. Run from the reviewed repository
as root, after normal provisioning and before public activation. Python modules are
also copied to `/opt/eric-mail/current/lib/` by runtime installation. Optional
profiles require explicit setup because the operator must provide trusted IPs,
certificates, DNS records and external services. No live host, DNS zone, or remote
log receiver was changed by this PR.

## Malware scanning and quarantine (improvement 5)

```
bash install.sh content-security enable
bash install.sh content-security health
bash install.sh content-security list
bash install.sh content-security release --id ABC123 --approve
bash install.sh content-security expire --days 30 --approve
```

Enable installs signed ClamAV packages, a local socket-only scanner, hourly signature
updates, and Rspamd policy. Malware, encrypted attachments and Office macros go to
Postfix's native **hold queue**. Scanner failures defer with a temporary SMTP error;
archive expansion/size limits generate scanner alerts instead of clean results.
Signatures older than 48 hours fail host health. There is no automatic expiry or
release. Review hold metadata privately: it includes sender and recipient addresses.
Approved release rescans with both ClamAV and Rspamd, requires an allowed result,
rechecks that the message is held, and records an authpriv audit event before
`postsuper -H`. This does not bypass the content filters. Investigate and remove the
underlying policy reason before release. Expiry deletes matching old hold messages;
queue IDs can be reused, so perform operations during controlled queue maintenance.

Before production, on a disposable VM verify EICAR is held, benign mail delivers,
scanner stop defers (no silent delivery), encrypted/oversized archives are held,
release of infected mail fails, signatures refresh under SELinux enforcing, and a
reboot preserves service operation. This PR is draft pending those host checks.
If configuration validation fails during enable, repair the policy and rerun before
restarting mail services; partial scanner setup must never be treated as accepted.

## Web worker isolation (improvement 7)

Copy `config/web-egress.example.json` to a root-owned mode-0600 policy, replacing
the example addresses with the exact mail endpoints and local recursive resolvers:

```
bash install.sh web-egress apply --policy /root/web-egress.json
bash install.sh web-egress health
```

The separate nftables output table allows Roundcube TCP 587/993 only to listed
addresses and TCP/UDP 53 only to listed resolvers. Both Roundcube and PostfixAdmin
UIDs are rejected for all other network destinations, including loopback port 25.
Local database sockets continue to work. Other UIDs and firewalld tables are
unaffected. PHP-FPM requires the boot-time firewall unit. Rules are syntax-checked
before one atomic nft transaction. Live rule drift fails health. Reapply the profile
if account UIDs or mail addresses change. PostfixAdmin mail notifications and
Roundcube remote HTTP plugins will be blocked; deploy only reviewed plugins.
Root, nginx, Postfix and separate services need their own confinement; this profile
is specifically for PHP worker egress. A separate web host remains an architectural
option. Verify IPv4/IPv6, loopback relay denial and reboot behavior on the target.

## Domain readiness, transport and DKIM (improvement 8)

Install the signed `bind-utils` package for `dig`. Check the actual public records:

```
bash install.sh domain-security check --domain example.com --address 192.0.2.25
bash install.sh domain-security sts-policy --mode testing > /root/mta-sts.txt
bash install.sh domain-security dkim-stage --domain example.com --selector mail2027
bash install.sh domain-security dkim-promote --domain example.com --selector mail2027 --address 192.0.2.25
bash install.sh domain-security dane-enable
```

Readiness checks exact MX and forward/reverse IP sets, a conservative explicit-IP
SPF policy ending in `-all`, enforced DMARC/reporting, published DKIM key equality,
MTA-STS TXT ID, TLS-RPT reporting and the authenticated HTTPS MTA-STS policy. The
readiness gate requires **enforce** mode and the configured MX; start deployment in
testing mode and observe reports before promoting. Indirect SPF includes and
multiple MX providers require a separate reviewed policy; this gate rejects them.
Publish the exported policy at `https://mta-sts.DOMAIN/.well-known/mta-sts.txt` using
independent HTTPS hosting with a publicly trusted certificate for that hostname.
The tool neither provisions DNS nor pretends a policy file is publicly published.
For `_mta-sts`, use `v=STSv1; id=UNIQUE_ALPHANUMERIC_ID`; change the ID whenever the
policy changes. `_smtp._tls` needs `v=TLSRPTv1; rua=mailto:YOUR_REPORT_MAILBOX`.
The receiver must actually process reports and external report destinations may
need DNS authorization. See [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461.html).

DKIM stage generates a new 2048-bit RSA key and prints only the public TXT record.
Publish it, wait for DNS propagation, then promote. Promotion checks readiness
before changing Rspamd's per-domain override, validates config and rolls back a
failed reload. Old keys/records remain: retain public records beyond queue/retry
and DNS TTL lifetimes, then retire under change control. Normal provisioning
continues to use the configured default selector for new domains.

DANE enable requires an already configured **local validating DNSSEC resolver**;
it verifies authenticated positive resolution and rejection of a deliberately
bogus signed domain before setting Postfix `dnssec`/`dane`. The settings are reapplied
on deployment and checked by health. DNS outages fail this setup check. Outbound
DANE applies only to DNSSEC-authenticated TLSA destinations; other destinations
retain opportunistic TLS. It does not implement an outbound MTA-STS policy cache.
Inbound DANE requires DNSSEC signing of your zone and coordinated TLSA publication/
certificate rotation. Publish TLSA records only after independent validation; no
operator DNS credentials are present in the repository.

## Independent delivery and audit (improvement 9)

`lib/mail_canary.py` runs outside the server using a dedicated controlled mailbox
and a revocable device credential. A mode-0600 JSON file must contain exactly
`hostname`, `username`, `password`, `sender`, `recipient`; sender and recipient must
be the controlled mailbox, with username including its device ID under mailbox MFA.

```
bash install.sh canary --credentials /secure/canary.json --output /secure/result.json
bash install.sh remote-audit --policy /root/remote-audit.json
```

The canary verifies TLS identity, submits a unique message and polls IMAP for its
Message-ID. Output contains only time, latency and delivery status. It marks only
its own message deleted and never performs a broad EXPUNGE. Give the canary mailbox
a retention policy. Timeouts and TLS/authentication failures return nonzero.
The GitHub workflow runs independently of the mail host: configure the protected
`mail-delivery-canary` environment's `MAIL_CANARY_JSON` secret, test manually, then
set repository variable `MAIL_CANARY_ENABLED=true` to enable the 15-minute schedule.
Use GitHub failure notifications or your independent monitoring service. Scheduled
Actions are best effort, so use an external SLA monitor when strict timing matters.

Remote audit uses signed `rsyslog-gnutls`, verifies the receiver hostname, presents
an independently issued client certificate, and queues logs to bounded disk during
outages. Configure a remote policy from `config/remote-audit.example.json` and verify
a marker arrives on the receiver. The receiver must authorize this client, retain
logs off-host, and alert on missing heartbeats/logging gaps or full sender queues.
A compromised root can stop local forwarding, so remote liveness detection remains
necessary. Native service logs and the tools' authpriv events do not constitute a
complete immutable audit trail of every web-admin database change.

## Advisory, inventory, integrity and rotation (improvement 10)

```
bash install.sh security-ops sbom > /root/mail-sbom.json
bash install.sh security-ops advisories
bash install.sh security-ops enable-checks
bash install.sh security-ops drift
bash install.sh security-ops verify --archive /root/release.tar.gz --signature /root/release.sig --key /root/release-key.pem --key-sha256 INDEPENDENT_PIN --toolkit
bash install.sh security-ops verify --archive /root/application.tar.gz --signature /root/application.sig --key /root/application-key.pem --key-sha256 INDEPENDENT_PIN
bash install.sh security-ops enforce-signatures
bash install.sh security-ops rotate-db
bash install.sh security-ops recover-rotation
```

Inventory is CycloneDX JSON with installed RPM versions, pinned application artifact
hashes and production Composer dependencies. Advisory checks refresh vendor security
metadata (respecting Rocky backports) and query OSV for installed Composer packages
and top-level application package names. Daily checks alert on errors or findings;
reports older than 48 hours fail health after enabling checks. Coverage is explicit:
absence of a feed match does not prove a component safe. Review Roundcube,
PostfixAdmin, ClamAV and Rspamd upstream notices as well. The updater does not
silently install unaudited application releases.

Drift checks content, owner, group, file type and mode of managed files plus explicitly
applied profile files. Upgrade refreshes the main manifest; profile operations only
refresh their own paths. Signatures are detached RSA/ECDSA SHA-256 signatures accepted
by OpenSSL `dgst`, with an independently trusted SHA-256 pin of the public-key PEM
file (not a certificate/SPKI fingerprint). Supply upstream compatible signatures or
sign reviewed artifacts through your organization's separate release process. Never
trust a key fetched alongside the artifact without independent verification. Toolkit
verification compares every executed installer/library/template file against the
signed archive before recording a private attestation. Verify both application
archives and the exact toolkit, then `enforce-signatures` enables the deployment
and upgrade gate. Any subsequent source change requires a new signed release.
Initial script trust still depends on obtaining/reviewing the verifier through a
trusted channel; a script cannot authenticate itself against malicious root.

SQL rotation takes the host operation lock, requires healthy unchanged state,
stops mail/auth/web consumers, generates four distinct random credentials, alters
only account passwords (preserving grants), rewrites credential consumers, checks
configuration and service health, and rolls back a failure. A private durable journal
retains both generations until success, including after a power loss. Normal deploy
and public activation reject an unfinished rotation. `recover-rotation` selects the
old generation by default; `--use-new` selects the new generation, rebuilds in
restricted mode, and requires fresh acceptance before reopening ingress. Store the
journal securely and retain a tested recovery backup before rotation. Rotation
preserves the Roundcube session encryption key, mailbox MFA seed key and DKIM keys.
Those keys require separate staged migration/session revocation; blind replacement
would destroy data or silently invalidate enrolled users. Mailbox/device revocation
is provided by the built-in MFA PR; DKIM rotation is described above.

## Acceptance and remaining deployment work

Run `tests/check.sh` for syntax, PHP lint and regressions. Tests mock operating-system
boundaries and do not certify ClamAV/Rspamd interoperability, SELinux policy labels,
nftables persistence, MariaDB credential rotation or public DNS. Complete these on
disposable Rocky hosts and retain measured acceptance evidence before activation.
The MFA PR and recovery PR have their own browser/client and full-host acceptance
requirements. These controls provide implementation and explicit setup commands;
no production credentials, PKI issuance, DNS changes or host infrastructure were
invented or performed as part of repository development.


Activation requires the new evidence checks in
`config/release-evidence.example.json` as well as the original checks. An old proof
cannot open ingress without those additional measured acceptance results. The
profile installers require that their source matches the installed reviewed runtime;
upgrade/deploy the release first rather than switching the managed runtime while
applying a profile from a different checkout.
