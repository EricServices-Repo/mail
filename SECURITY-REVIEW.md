# Mail server technical and security review

Implementation update: the historical findings below refer to the original revision. See [implementation status](docs/IMPLEMENTATION.md) for the replacement toolkit, remediation coverage, and required deployment acceptance.

Review date: October 25, 2026. Repository: EricServices-Repo/mail.
Reviewed commit: `502dfc052028c4b9a039c99ef90f4ee42a61bbf8`.

## Decision

**Do not deploy this revision as an Internet-facing production mail server.** It is an incomplete provisioning prototype with security and availability blockers. Postfix, Dovecot, MariaDB, Nginx and webmail can form a sound stack, but these scripts do not yet configure and maintain that stack safely.

This review covers every tracked shell script, README, and version history. It is a source review, with local syntax checks and isolated evaluation of the setup-password expression. No installer or operational helper was run against the host. No production server, DNS zone, certificates, logs, installed package inventory, GitHub branch protections, or backup storage was inspected. Missing controls below mean absent from the repository; separate infrastructure may provide them. There is no claim that a running system has been compromised or is an unauthenticated public open relay.

Priorities: **P0** blocks deployment or requires immediate attention if the affected feature is live; **P1** required before general production use; **P2** operational improvement after the baseline is secured. Severity and exploitation depend on actual deployment and which optional scripts have been used.

## Confirmed findings and required changes

### F01 — P0: Installation is syntactically broken and does not fail safely

Evidence: `install.sh:85–96` indents the `EOF` closing delimiter of a `<< EOF` heredoc. `bash -n install.sh` reports an unexpected end of file at line 719. Normalizing only that delimiter in memory makes syntax validation pass. Earlier complete commands may still execute before Bash reaches a parse error; do not interpret a syntax error as a guarantee of no side effects.

The scripts lack strict error handling, preflight validation, rollback, and a final health gate. Configuration is repeatedly appended, so reruns duplicate PHP opening tags, service directives, cron entries and shell aliases. Services and firewall access are enabled before complete configuration and certificates exist (`install.sh:148–155,295–299,379–382,529–532`).

Fix: repair the heredoc, use a Bash shebang on the first line of each executable, run helpers with Bash rather than `sh`, add `set -Eeuo pipefail` with explicit handling of expected failures, root/OS/version checks, a restrictive umask and an execution lock. Render owned configuration files into temporary files, validate them, install atomically and retain protected backups. Keep public access closed until all health checks pass. Replace blind append/sed editing with versioned templates or configuration management.

Acceptance: syntax and ShellCheck pass; a clean supported-OS VM installs successfully; a second run produces no unintended changes; package/download/certificate failures stop deployment without reporting success or exposing unfinished services.

### F02 — P0: Untrusted package and script supply chain

Evidence: optional repositories use HTTP with `gpgcheck=0` (`install.sh:85–95`), and official repositories are moved aside. The Remi release RPM is fetched over HTTP (`:141`). Application archives have no explicit signature/checksum verification (`:209,582`). Helpers are downloaded from mutable `main` (`:540–546`); the README recommends immediate execution of a mutable remote installer.

Impact: a compromised unsigned mirror or altered privileged script can become root execution. HTTPS alone authenticates the transport endpoint, not an independently reviewed software release.

Fix: retain trusted distribution repositories; require repository signing and independently validated key fingerprints; use HTTPS; pin application releases and script bundles to reviewed versions/commits; validate signed release metadata or trusted recorded digests before extraction. Treat dependency updates as reviewed releases. Remove direct remote execution from installation guidance. Create a manifest recording installed versions, sources and digests.

The updater also requests `scripts/mail-update.sh.new`, which is absent from this reviewed repository, and uses `wget -P` without controlled replacement of existing names (`scripts/mail-update.sh:4–12,33–35`). Repeated downloads can leave suffixed copies instead of updating active files, and a failed self-download can be followed by removal of the working updater. Replace this with a verified staged bundle and atomic promotion only after all files validate.

Acceptance: modified payloads and invalid signatures are rejected before installation; download failures cannot replace installed helpers; updating requires a reviewed release artifact.

### F03 — P0: Stale web applications and no application patch lifecycle

Evidence: Roundcube is pinned to **1.6.5** (`install.sh:582–585`) and PostfixAdmin to **3.3.13** (`:209–211`). `scripts/mail-update.sh` updates helpers, not web applications or database schemas.

Roundcube published security releases **1.6.20 / 1.7.5 on October 19, 2026**, covering multiple injection, content-handling and other security defects. Use a currently patched supported branch, with a verified migration plan; do not merely change a download URL. [Roundcube advisory](https://roundcube.net/news/2026/10/19/security-updates-1.6.20-and-1.7.5).

PostfixAdmin's release page currently lists **4.0.5** and discusses dependency fixes and PHP-dependent release builds. Select a maintained release and verify the bundled dependency tree rather than assuming all builds have the same security properties. This review does not establish a specific exploitable PostfixAdmin CVE in this deployment. [PostfixAdmin releases](https://github.com/postfixadmin/postfixadmin/releases).

The installer chooses PHP 8.2 without a minimum patched package check. PHP 8.2 upstream security support ends December 31, 2026. PHP announced critical fixes on October 21, 2026 in 8.2.35, 8.3.36, 8.4.27 and 8.5.12; vendor backports also require verification. Check actual deployed packages immediately if this stack is live. Prefer a compatible branch with a longer maintenance runway. [PHP security announcements](https://www.php.net/archive/2026.php), [support lifecycle](https://www.php.net/supported-versions.php).

Fix: establish OS and application security-update ownership, advisory monitoring, upgrade rehearsals, schema migrations, rollback backups, and a critical-patch response target of 24 hours. Inventory distribution backports before judging vulnerabilities by version strings.

Acceptance: deployed component inventory maps to supported, patched packages; webmail/admin upgrades and database restores are exercised in staging.

### F04 — P0: Setup-password hash is generated from an empty PHP variable

Evidence: `install.sh:226` invokes `php -r 'echo password_hash("$PFASETUPPASSWORD", PASSWORD_DEFAULT);'`. Shell single quotes prevent passing the shell value, and PHP interpolates its own undefined `$PFASETUPPASSWORD`. Isolated execution confirmed the hash verifies against an empty string. It does not hash the operator's supplied password. Whether setup.php accepts an empty submitted password depends on application validation and must not be assumed.

Fix: pass the secret through a controlled input stream or protected temporary input, hash its actual bytes, require nonempty strong input, and test verification with the supplied value and rejection of empty/wrong values. Restrict setup to a private administrative session, then remove or explicitly deny the setup route.

Acceptance: correct input verifies, blank and wrong inputs fail; public setup access returns a denial after provisioning.

### F05 — P0: Weak defaults, secret exposure and excessive database privilege

Evidence: known default passwords and echoed secrets (`install.sh:56–66`; replication helper `:43–49`); SQL passwords on command lines; one password reused by PostfixAdmin, Dovecot, Postfix maps and Roundcube (`install.sh:219,315,465–515,588`). Postfix and Dovecot use the administrative database identity. No explicit restrictive secret-file ownership/modes are established. Raw secret input is interpolated into SQL, PHP and connection strings.

Impact: local users or a compromised component may read credentials or obtain unnecessary database write privileges. Apostrophes, spaces and DSN metacharacters can break configuration or alter the generated SQL/PHP; this is an administrator-input handling flaw, not a demonstrated remote SQL injection endpoint.

Fix: remove default secrets and terminal echoes; use silent prompts or protected secret provisioning. Create separate administrative, Postfix read-only lookup, Dovecot read-only authentication and Roundcube accounts, scoped to necessary tables/databases. Use local database sockets and supported administrative authentication. Avoid credentials in argv; use protected client option files. Serialize values safely for each target language; parameterize SQL provisioning. Use `umask 077`, explicit ownership, root-only secrets where possible, and narrowly scoped service groups where required. Protect config backups equally.

Acceptance: lookup accounts cannot write; unrelated service identities cannot read secrets; special-character secrets round-trip correctly; logs contain no supplied secrets. Rotate defaults/reused credentials on existing deployments after checking service dependencies.

### F06 — P0: Broad private networks can relay without authentication

Evidence: `install.sh:399` trusts `172.16.0.0/16`, `192.168.0.0/16`, `10.0.0.0/8` and IPv4 loopback. `smtpd_relay_restrictions` permits `mynetworks` first (`:447`). Any reachable host with a trusted source address may relay externally without SMTP AUTH.

Fix: trust only loopback (`127.0.0.0/8` and `::1/128`) by default. Explicitly allow individual infrastructure relay clients only when needed, with source restrictions, dedicated policies and limits; prefer authenticated submission. Test from both public and internal networks. The existing `reject_unauth_destination` is meaningful protection; this is not evidence that every Internet host can relay.

Acceptance: unauthenticated external-to-external recipients are rejected from public and unapproved internal clients; legitimate inbound local recipients and authenticated submission work; IPv6 is covered.

### F07 — P1: SMTP MX, submission and IMAP security policies are incomplete

Evidence: global `smtpd_tls_security_level=encrypt`, `smtpd_tls_auth_only=no`, global AUTH enabled (`install.sh:404–405,440`); protocol exclusions only explicitly name SSLv2/v3 (`:409–412`). Port 465/587 setup only uncomments service names (`:520–521`), without writing explicit per-service policies. Effective behavior depends on vendor defaults. No explicit Dovecot TLS-required/authentication policy is established.

Fix: define each listener explicitly. Public MX on port 25 should offer opportunistic TLS and normally not advertise AUTH. Require authenticated, encrypted submission on 587; configure implicit TLS wrapper mode explicitly on 465 if offered. Enforce a TLS 1.2 minimum for client access and support TLS 1.3 where compatible. Set Dovecot's version-appropriate TLS-required and no-cleartext-auth settings. Disable unused POP3; close 143 if STARTTLS IMAP is not needed. Do not rely on commenting patterns in vendor files.

Public MX must retain Internet SMTP interoperability; Postfix specifically warns against requiring STARTTLS on a publicly referenced SMTP server. Strengthen interdomain transport with tested MTA-STS/TLS reporting or DNSSEC/DANE policies rather than a blanket inbound `encrypt` policy. Encryption alone does not authenticate a remote mail server. [Postfix TLS guidance](https://www.postfix.org/TLS_README.html).

Acceptance: port 25 receives ordinary inbound mail but cannot relay anonymously; 587 requires TLS then authentication; 465 performs an immediate TLS handshake; cleartext IMAP login fails; obsolete client TLS fails; authenticated submission cannot bypass scanning or sender authorization.

### F08 — P1: SELinux protection is permanently disabled

Evidence: `setenforce 0` and persistent `SELINUX=permissive` (`install.sh:164–168`).

Fix: keep enforcing mode; apply persistent file contexts and the minimum required service booleans/policy. Investigate actual AVC denials; avoid indiscriminate generated allow rules. Apply appropriate systemd sandboxing after compatibility tests. Separate web and mailbox service identities and writable paths.

Acceptance: complete delivery, login, webmail, certificate renewal and reboot tests pass under SELinux enforcing, without unexplained denials.

### F09 — P0 when used: Debug helper enables password logging

Evidence: `scripts/mail-server-enable-debug.sh:4,6` attempts to enable `auth_verbose_passwords=yes` and `auth_debug_passwords=yes`. Actual edits depend on matching configuration text, but supported Dovecot debug settings can disclose passwords. [Dovecot logging documentation](https://doc.dovecot.org/2.3/admin_manual/logging/).

Fix: remove password logging options entirely. Provide time-limited diagnostic logging with automatic expiration, a named incident owner, restricted log access and redaction. Explicitly disable secret logging rather than merely commenting matching lines. Review existing logs if this helper has been used; restrict and dispose of sensitive copies according to retention requirements, and rotate affected credentials where disclosure is established or cannot be bounded.

Acceptance: a failed login using a unique test secret leaves no secret in any service or forwarded log; debugging expires and survives configuration variations safely.

### F10 — P1: Webmail/admin lack privilege and installation-route isolation

Evidence: world-writable PostfixAdmin cache (`install.sh:213`) and Roundcube temp/log directories (`:591–592`); both sites use the same FPM socket. Roundcube serves its full application root without explicit protected-path rules (`:594–617`). README instructs web installation, with no cleanup or denial implemented. Certificates are optional and default off (`:48–50`); sites initially serve HTTP.

Fix: keep PostfixAdmin on a VPN or administrative allowlist and require MFA using a compatible app/identity configuration. Use separate PHP-FPM pools/users, service-owned cache/temp directories outside public roots, and read-only application code. Remove world-write permissions. Deny installer/setup, config, SQL, logs, temp, dotfiles and backup paths as appropriate for the selected release. Enforce HTTPS before login, secure/HttpOnly/SameSite session cookies, login throttling, upload/body limits, and tested security headers. Introduce HSTS after validating HTTPS coverage. Do not put public IMAP/SMTP behind an interactive browser-only identity gateway.

Acceptance: protected paths and installers are inaccessible; credentials cannot be submitted over HTTP; compromising the webmail pool does not grant admin-database or mailbox-file access; backups are not web accessible.

### F11 — P1: Roundcube configuration is not generated correctly

Evidence: `install.sh:580` contains `$ROUNDCUBEHASH=openssl rand -base64 12`, which attempts to execute a command instead of assigning command output. The configuration helper is never fetched or invoked by the installer. Its unquoted heredoc expands `$config` as a shell variable (`scripts/roundcube.sh:1–75`), producing invalid PHP under normal conditions. Its loopback IMAP choice also depends on effective Dovecot cleartext-login policy.

Fix: generate a cryptographically random key of the exact length required by the selected Roundcube cipher, safely render valid PHP, initialize the schema noninteractively and remove the installer. Use a fixed trusted IMAP endpoint; use certificate-verified TLS or a deliberately scoped local connection with appropriate service isolation. URL-encode DSN credentials and maintain stable IMAP host identity across upgrades.

Acceptance: generated configuration passes `php -l`; login, IMAP retrieval, SMTP submission, attachment and session tests pass; encryption key is nonempty and different across clean installations.

### F12 — P1: Add-domain helper can generate broken configurations and certificates

Evidence: unescaped Nginx `$uri`, `$document_root`, `$fastcgi_script_name`, `$host`, `$request_uri` are expanded by Bash (`scripts/mail-add-domain.sh:62–145`). Certificates are hardcoded to `mail.ericembling.com` (`:86–87,130–131`). The ACME command requests `postfixadmin.$DOMAIN` while the vhost uses `admin.$DOMAIN` (`:166`). The collected certificate-domain array and CERTBOT choice are unused. Domain input is interpolated into filenames and config without validation.

Fix: validate domain names and reject path/control/config delimiters; render literal Nginx variables safely; use explicit certificate lineage and SAN management; separate hosted email domains from actual client-service hostnames to avoid unnecessary SAN expansion. Add domains through the administrative database workflow, not a client-IP whitelist. Validate and reload only after success.

Acceptance: add two domains, rerun both, and verify unique valid vhosts, hostname-correct certificates, intact PHP variables and no duplicate config. Failed ACME issuance leaves the working configuration intact.

### F13 — P1: Abuse prevention and domain authentication are missing or ineffective

Evidence: no DKIM signer, SPF/DKIM/DMARC evaluator, content scanner, sender-ownership mapping, quota enforcement, authentication throttling or explicit per-account outbound rate policy is installed. `zen.samhaus.org` is misspelled (`install.sh:445`). The domain whitelist is used with `check_client_access` (`:446–447`), which checks client identity rather than creating hosted domains or validating sender identity.

Fix: integrate Rspamd (or an equivalent maintained filter) with Postfix for ingress validation, scoring and outbound DKIM signing; use Redis locally if required. Decide filter-outage behavior explicitly: temporary SMTP deferral preserves the security boundary without silent bypass. Add malware/attachment scanning where required, with resource limits; scanners cannot guarantee that attachments are safe. Deploy a suitable resolver and comply with DNSBL service terms. Use a phased quarantine/rejection policy and safe training inputs. [Rspamd integration overview](https://docs.rspamd.com/tutorials/quickstart/).

Configure per-domain DKIM selectors and rotation, SPF with all legitimate senders, DMARC reporting followed by alignment-validated enforcement, accurate MX/A/AAAA/PTR/HELO, and working postmaster/abuse mailboxes. Enforce authorized envelope senders on authenticated submission using sender-login maps and alias/delegation rules; assess header From authorization separately. Add per-account outbound recipient/rate controls, authentication abuse controls, mailbox and storage quotas, queue limits and alerts. Do not blindly reject forwarded mail solely for SPF failure; test DKIM/DMARC/ARC and forwarding behavior. [Postfix SASL and sender authorization](https://www.postfix.org/SASL_README.html).

Acceptance: authorized outbound mail validates DKIM and DMARC at an independent receiver; spoofed account senders are rejected; spam tests are filtered; scanner failure follows the documented policy; abusive account traffic is bounded and alerted.

### F14 — P1: Replication is unfinished and unsafe to treat as availability

Evidence: replication user is created for `%` without a TLS requirement (`scripts/mail-replication-primary.sh:53–54`); firewall rule references undefined `$SECONDARYIPADDR` instead of `$SECONDARYIPADDRESS` (`:61`); MariaDB is configured toward all-interface binding (`:66`). Separate lock/unlock client sessions do not hold a consistent snapshot (`:56–57`). The secondary script contains only comments. No mailbox synchronization, fencing, promotion, certificates, queue or restore orchestration exists.

Fix: disable the advertised replication feature until designed and tested. Start with one primary and verified offsite backups. If availability requirements justify another node, define recovery objectives, database and mailbox replication, private peer transport, certificate-verified database TLS, exact peer account/source restrictions, consistency checks, promotion/fencing, queue handling and failure drills. Replication is not a backup. Avoid promising automatic active-active service.

Acceptance: isolated peer connectivity, rejected untrusted peers, measured lag and alerting, consistent restore, node-failure and split-brain drills, and documented recovery-point/recovery-time outcomes.

### F15 — P1: No proven backup, monitoring or recovery capability

Evidence: no implementation backs up mailboxes, databases, signing keys, configuration or necessary encryption material; no restore drills, alert definitions, storage capacity controls or end-to-end probes exist. Dovecot rotation covers only one of three named log files (`install.sh:327–332,626–639`). Effective Postfix log rotation depends on available tooling/permissions and is not verified by the appended cron line (`:641–643`).

Fix: encrypted offsite backups with separate credentials, immutable retention where available, coordinated mailbox/database consistency and isolated recovery keys. Include configuration, DKIM private keys, relevant webmail encryption keys and documented certificate recovery; avoid unnecessary secret duplication. Define business-approved RPO/RTO and test restore to an isolated host. Monitor queue age/depth, disk bytes/inodes, delivery latency, login failures, outbound spikes, database/replication health, filtering health, certificate expiry and backup freshness. Rotate all application logs, restrict their access and forward security events to protected storage. Add external synthetic delivery and login probes using dedicated accounts.

Acceptance: restore a randomly selected mailbox and its account data, then perform a full isolated restore; prove delivery and retrieval within agreed recovery targets; trigger every critical alert and verify it reaches an accountable operator.

### F16 — P1: Platform claims exceed the implementation

Evidence: README advertises Rocky, Red Hat, Fedora and CentOS, while the installer hardcodes an Enterprise Linux 8 Remi RPM and exact vendor configuration-file substitutions. Database bootstrap edits `mysql.user` directly (`install.sh:185`) and assumes version-specific root authentication behavior. Dovecot's auth listener is appended at top level rather than explicitly inside `service auth` (`:335–341`), risking invalid effective configuration. There is no runtime parser validation.

Fix: choose one supported OS major version as the initial target, document exact package sources and component compatibility, and test it on a full systemd VM with enforcing SELinux. Use supported SQL account-management commands. Pin Dovecot configuration syntax to the deployed major version; do not paste 2.3 settings into a newer major version without migration. Only advertise additional distributions once CI provisions and tests them.

Acceptance: `nginx -t`, `php -l`, `doveconf -n`, `postfix check`, database queries and service-health checks pass on the selected platform after initial provisioning, rerun and reboot.

## Recommended target architecture

Retain the existing core stack if the team can maintain its lifecycle. Use a dedicated mail host with a supported OS, enforcing SELinux, signed packages, restricted management access and protected mailbox storage. Separate the webmail/admin tier onto another host when practical; otherwise use distinct service users and PHP pools. Keep MariaDB and filter services local or reachable only through a private peer network. Do not place unrelated applications on this host.

Public services should be limited to SMTP 25, authenticated submission 587, IMAPS 993, and HTTPS 443. Offer 465 only if needed and correctly configured. Allow port 80 only for ACME validation and HTTPS redirection; DNS-based validation can reduce that need. Close POP3 and unused IMAP listeners. Restrict SSH and administration to management sources with keys/MFA. Apply the same policy to IPv6 and upstream cloud/network firewalls.

Use Postfix → filter → Dovecot LMTP for local delivery, with protected Unix sockets and independent SQL lookup identities. Filter both incoming mail and authenticated outgoing mail. Use per-account policy controls so a stolen password cannot immediately exhaust queue/storage resources or destroy sending reputation. Encrypted transport and storage do not provide end-to-end message encryption; use a separate S/MIME/PGP workflow if that is a requirement.

Do not add high availability before reliable installation, patching, observability and recovery exist. A maintained external mail service remains an architectural option if the organization cannot staff continuous security and deliverability operations; that is a business decision rather than a prerequisite to fixing this repository.

## Implementation sequence

1. **Contain existing exposure, if deployed.** Inventory effective configuration and package versions; restrict admin/setup routes; patch exposed web applications/PHP; disable password logging; reduce relay trust; establish a verified backup. Rotate known/default/exposed secrets with a coordinated service change. Preserve relevant evidence if compromise indicators exist.
2. **Make provisioning deterministic.** Fix parser errors; define one supported platform; build templates, safe secret provisioning, verified downloads, atomic updates, explicit listeners and configuration validators. Remove incomplete replication from supported features.
3. **Implement production controls.** Enforce TLS on client access, least-privilege SQL and service permissions, SELinux, web isolation, filtering, domain authentication, sender authorization, quotas and abuse limits.
4. **Prove recovery and maintainability.** Add application upgrades, rollback/migrations, monitoring, alerts, offsite backups and restore drills. Introduce MTA-STS/TLS-RPT or DANE after domain/certificate operations are stable.
5. **Release only against the gates below.** Keep a staging host and a canary mailbox. Migrate accounts/mail and lower DNS TTLs deliberately; retain a tested rollback path that avoids divergent mailbox state.

Suggested repository structure: `templates/` for versioned service config, `lib/` for validated provisioning functions, `tests/` for generated-config and integration checks, `docs/` for DNS/operations/recovery runbooks, and a signed/versioned release manifest. Ansible is a reasonable replacement for the monolithic script if it fits the team's operations; safe desired-state behavior matters more than the tool choice.

## Production acceptance gates

- Every shell file passes syntax and ShellCheck; generated PHP passes lint; generated server configuration passes actual installed daemon validators. Test secrets containing quotes, spaces and reserved DSN characters without logging them.
- Full systemd VM installation, second run, interrupted run, upgrade, rollback and reboot pass on every advertised OS. Container-only tests do not establish firewall/systemd/SELinux correctness.
- Test relay rejection from public IPv4, IPv6, an untrusted LAN address and an approved relay client. Verify valid local delivery and early unknown-recipient rejection without backscatter.
- Test each listener independently: TLS versions, hostname/chain verification, AUTH exposure, cleartext rejection, unauthorized sender rejection, and bounded authentication abuse. Verify a third-party inbound sender without STARTTLS follows the intended public MX policy.
- Confirm SPF/DKIM/DMARC results on actual outbound mail; test aliases, forwarding, bounces, quarantine and filter outages. Use authorized test mailboxes; avoid live-user data in tests.
- Prove admin/installer restrictions, web file permissions, secure sessions, upload limits and separation between webmail, admin and mail storage. Scan only explicitly authorized infrastructure.
- Simulate certificate renewal and validate updated certificates on SMTP, submission, IMAP and HTTPS; alert before expiry and on renewal failure. Prefer managed timers/hooks and reloads where supported rather than unnecessary restarts.
- Restore mailbox plus account/database data and required keys to an isolated host; measure RPO/RTO. Verify queues, disk/inode exhaustion controls, backup failures and end-to-end delivery alerts.
- Record an operator, escalation path, patch window, incident process, recovery procedure and release approval for the resulting system. A green install command alone is not a production security gate.

## Validation performed and limitations

`bash -n install.sh` failed. After changing only the indented heredoc terminator in an in-memory copy, it passed. All ten helper scripts passed Bash syntax checks; that does not validate their generated PHP/Nginx, service semantics or runtime safety. The PHP setup hash expression was independently shown to hash the empty string. ShellCheck was not installed and was not run. No root installation, service execution, network penetration testing or production remediation was performed.

This report adds recommendations only. Production scripts remain unchanged. Revalidate external advisories and deployed package status when implementation begins.
