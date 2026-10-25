# EricServices-Mail-Server

**A Bash installer for a native, self-hosted, multi-domain mail server.** Run it
on a prepared Rocky Linux host with `sudo bash install.sh`. It installs packages
and systemd services directly; Docker is not required for deployment or runtime.
Bash provides the installer entry point and command dispatch; Python 3.9+ is a
dependency for the configuration and security helpers.

The installer configures:

- **Dovecot** — IMAP access and local mail delivery.
- **Postfix** — SMTP transport and authenticated submission.
- **PostfixAdmin** — domain, mailbox and alias management.
- **Roundcube** — email web client.
- **MariaDB** — multi-domain account and application databases.
- **Rspamd and Redis** — filtering, DKIM signing and outbound abuse controls.
- **Nginx and PHP-FPM** — HTTPS portals with separate application identities.
- **Let's Encrypt / Certbot** — supported certificate issuance and renewal integration; another trusted CA can also be used.

This README retains the original project's organization and expands it for the
current security-focused installer. The [original README](docs/README.original.md)
is preserved unchanged for historical reference; its installation commands, variables
and web setup routes describe the legacy installer and must not be used for this release.

## Features

The original TLS, connection restriction and SQL multi-domain features now include:

- **Encrypted client access:** TLS-required submission on port 587 and IMAPS on
  993, with certificate and hostname validation. Public MX on port 25 supports
  opportunistic TLS and Postscreen connection screening.
- **Relay and sender protection:** authenticated submission, sender ownership,
  matching header/envelope identities, per-account outbound limits and restricted
  loopback relay trust. Management-network access never grants SMTP relay rights.
- **Multi-domain management:** SQL-backed domains, mailboxes and aliases, with
  explicit domain enable/disable commands. Provisioning preserves suspended domains.
- **Mailbox MFA:** built-in webmail TOTP, encrypted enrollment seeds, recovery
  codes, replay protection and session invalidation after enrollment reset.
  Mail clients use separate expiring, revocable device credentials; those bearer
  credentials are not themselves multi-factor IMAP authentication.
- **Restricted administration:** PostfixAdmin TOTP, management CIDRs and client
  certificate authentication/revocation, with web setup routes disabled.
- **Malware quarantine:** an explicitly enabled ClamAV/Rspamd profile holds
  suspicious messages in Postfix's queue, defers mail on scanner failure and
  requires approved rescanning before release.
- **Web isolation:** separate PHP pools and SQL identities, enforcing SELinux,
  plus an explicitly configured nftables profile restricting web-worker egress,
  including access to the trusted loopback SMTP relay.
- **Domain and transport readiness:** DNS checks, MTA-STS policy export,
  TLS-RPT checks, staged DKIM rotation and opt-in outbound DANE with a validating
  local DNSSEC resolver. Public DNS and policy hosting require operator setup.
- **Recovery:** encrypted offsite Restic backups, consistent SQL/mailbox snapshots,
  durable queue copies, isolated restore destinations, optional thick-LVM snapshots
  and guarded recovery drills. An optional private, mutually authenticated SQL
  replica provides database disaster recovery; it does not replicate mailboxes
  or provide automatic mail failover.
- **Operations and integrity:** health checks, alerts, certificate renewal checks,
  an independent delivery canary, remote TLS audit forwarding, CycloneDX inventory,
  advisory checks, file drift detection, signed-artifact verification and recoverable
  SQL credential rotation.

Profile setup and acceptance requirements are documented in
[security profiles](docs/SECURITY-PROFILES.md), [mailbox MFA](docs/MAILBOX-MFA.md),
[recovery acceptance](docs/RECOVERY-ACCEPTANCE.md) and
[SQL replication](docs/REPLICATION.md).

## Dependencies

The supported deployment target is a **fresh, dedicated Rocky Linux 9 host** with
systemd and enforcing SELinux. The original broader Red Hat/Fedora/CentOS claim
is historical; those distributions are not current tested installation targets.

Prepare these before installation:

- Static addresses, console access, adequate storage and narrow management CIDRs.
- Reviewed, signed distribution and required third-party package repositories.
- Compatible, complete Roundcube and PostfixAdmin release archives, supplied offline
  with independently verified digests and provenance.
- A trusted server certificate covering the mail and admin hostnames, its private
  key, and an administrative client CA and current CRL.
- An initialized offsite Restic repository, separately protected recovery keys and
  an independent executable alert integration.
- DNS records for the mail and admin hostnames, MX, matching forward/reverse DNS,
  SPF, DKIM and DMARC. The current configuration uses one stable mail hostname for
  webmail, IMAP and submission; separate `imap`/`smtp` aliases are optional and need
  appropriate certificate coverage and client configuration.

Read [deployment requirements](docs/DEPLOYMENT.md) and [DNS guidance](docs/DNS.md)
for exact prerequisites, component compatibility and certificate policy.

## Installation

### Review and prepare the release

Obtain a reviewed checkout or signed release and inspect it before running it.
The current installer replaces mail/web configuration on a dedicated host; existing
legacy installations need a planned migration rather than an in-place rerun.

```bash
git clone https://github.com/EricServices-Repo/mail.git
cd mail
# Select and verify the reviewed revision/release before running its scripts.
# For file-based configuration, copy config/site.example.json to a private site.json.
```

If using file-based configuration, copy `config/site.example.json` to `site.json`,
set mode `0600`, and edit its site-specific fields. Interactive installation below
collects those settings for you. A prepared file can also be previewed offline:

```bash
bash install.sh init-secrets --output secrets.json
bash install.sh render --config site.json --secrets secrets.json --output build
```

Rendering is offline. The preview secrets and generated output are private and
must not be committed or copied over an established host's credentials.

### Deploy on the prepared host

You can supply JSON or answer questions in the Bash installer.

**Interactive installation — no JSON file required:**

```bash
sudo bash install.sh
```

The installer prompts for hostnames, domains, management networks, certificates,
verified application archives/hashes, backups, alerts and limits. It validates each
answer, lets you choose a configuration filename (default `/root/site.json`), saves
it with mode `0600`, then starts deployment. Blank answers use displayed defaults;
required values must be entered. Existing files are never overwritten. Ctrl-C or
end-of-input cancels setup before deployment.

Certificates, client CA/CRL, reviewed package repositories, application archives,
backup access and the notification executable still need to be prepared; answering
the questions does not create those external prerequisites. Passwords are generated
by provisioning rather than requested in this questionnaire.

**Installation with an existing JSON file — no prompts:**

```bash
sudo bash install.sh --config /root/site.json
```

For repeat deployments, explicitly pass the saved configuration, for example
`sudo bash install.sh deploy --config /etc/eric-mail/site.json`. A missing or invalid
explicit file is an error, not a request to silently switch to interactive setup.
Unattended execution must supply `--config`; without a terminal it fails clearly.

To collect and validate answers without installing anything:

```bash
bash install.sh configure --output "$PWD/site.json"
```

Choose a private, non-shared directory owned by the invoking user. Use
`bash install.sh --help` to list commands, or
`bash install.sh mailbox-mfa --help` for feature help. The complete checkout/release
is required alongside `install.sh`.

The installer generates persistent credentials under `/etc/eric-mail/`, installs
its managed runtime under `/opt/eric-mail/current`, validates services and takes an
initial backup. Public ingress remains restricted pending acceptance evidence.
The historical direct-download execution commands are superseded by this reviewed
release workflow.

## Variables and configuration

Settings live in a private `site.json`, generated from the Bash questionnaire or
copied and edited from [config/site.example.json](config/site.example.json), rather
than shell variables in the installer.

- `hostname` and `admin_hostname` select the mail/webmail and administration names.
- `domains` lists hosted mail domains; `dkim_selector` selects the default signer.
- `management_networks` and `interface` control administrative ingress.
- Certificate, private-key, client-CA and CRL paths define the TLS trust inputs.
- Application archive paths, SHA-256 digests and declared versions pin the artifacts.
- `backup_environment`, `alert_command`, quota and queue/rate limits define operations.

The old `SQLPASSWORD`, `PFAPASSWORD` and `PFASETUPPASSWORD` settings are replaced by
independently generated credentials and root-only account provisioning. `ESREPO`
and `CERTBOT` toggles no longer bootstrap repository trust or certificate issuance;
prepare trusted repositories and certificates explicitly. Optional security profiles
have their own example policies and setup commands.

## Post Installation

Create administrative and required service mailboxes using the managed CLI:

```bash
sudo bash /opt/eric-mail/current/install.sh admin --address operator@example.com
sudo bash /opt/eric-mail/current/install.sh mailbox --address postmaster@example.com
sudo bash /opt/eric-mail/current/install.sh mailbox --address abuse@example.com
```

Use your own hosted domain. Enroll administrator TOTP and mailbox TOTP, issue device
credentials for mail clients, configure the security profiles, publish DNS and test
external delivery. For example, mailbox enrollment is a root-only operation:

```bash
sudo bash /opt/eric-mail/current/install.sh mailbox-mfa enroll --address postmaster@example.com
sudo bash /opt/eric-mail/current/install.sh mailbox-mfa device --address postmaster@example.com --label 'Mail client'
```

Enrollment seeds, recovery codes and device passwords are displayed once. Deliver
and store them through a protected process. See [mailbox MFA](docs/MAILBOX-MFA.md).
The legacy `/setup.php` and `/installer` web routes are intentionally disabled.

Run the acceptance checks and retain their actual results. Copy
[the release evidence template](config/release-evidence.example.json), populate the
configuration fingerprint, installed release hash and operator, and mark checks true
only after execution. Then activate:

```bash
sudo bash /opt/eric-mail/current/install.sh activate --evidence /root/release-evidence.json
```

Acceptance includes relay rejection, MFA/revocation, scanner outage/quarantine,
web-worker egress, recovery, independent delivery/audit, integrity/rotation and domain
readiness. Source checks and CI do not replace real Rocky/SELinux, browser, DNS,
external-network and recovery testing. Deployment and upgrade return the host to
restricted ingress until acceptance is repeated.

## Access

With your configured hostnames:

- `https://mail.example.com` — Roundcube webmail.
- `https://admin.example.com` — PostfixAdmin, requiring management-network access,
  an authorized client certificate and administrator authentication/MFA.
- `mail.example.com:993` — IMAPS for mail clients.
- `mail.example.com:587` — authenticated SMTP submission using STARTTLS.
- Port 25 — public server-to-server SMTP; it does not offer mailbox authentication.

POP3, cleartext IMAP and optional port 465 are disabled by the managed configuration.

## Debug Commands

The original `debugmail` / `undebugmail` helpers are replaced by managed commands:

```bash
sudo bash /opt/eric-mail/current/install.sh health
sudo bash /opt/eric-mail/current/install.sh debug-on
sudo bash /opt/eric-mail/current/install.sh debug-off
```

Diagnostic logging expires automatically and password logging remains disabled.
See [operations and recovery](docs/OPERATIONS.md) for service logs, backup/restore,
certificate renewal, upgrades and incident procedures.

## Customization

Configure quotas, outbound limits, domains and management networks through reviewed
site configuration. Use the documented upgrade workflow for configuration changes;
a normal deploy only reruns the same desired state. Configure optional malware,
egress, audit, advisory, signature, snapshot and replication profiles explicitly.

Repository signing-key trust, certificate issuance/renewal and staging CA usage
belong in the deployment workflow. A staging certificate must not be used for a
production deployment. Enable MTA-STS/DANE only after the required DNS, resolver,
certificate and report-processing infrastructure has been validated.

## Development checks

Python 3.9+, PHP CLI and ShellCheck are required for local release checks:

```bash
./tests/check.sh
```

GitHub CI uses Docker only for an isolated MariaDB replication integration test.
This test does not build or deploy a mail-server container image. Disposable
host scenarios are manually dispatched against an explicitly configured lab runner;
they must never target production. See [implementation status](docs/IMPLEMENTATION.md)
and the feature-specific acceptance guides for validation boundaries.

## Support

[Discord](https://discord.gg/8nKBgURRbW)

For security reporting and patch policy, see [SECURITY.md](SECURITY.md). The
[original security review](SECURITY-REVIEW.md) records the historical findings;
current setup and acceptance procedures are linked above.
