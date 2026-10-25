# Eric Mail

A security-focused provisioning toolkit for a **dedicated Rocky Linux 9 host**, using Postfix, Dovecot 2.3, MariaDB, Rspamd, Redis, Nginx, PHP-FPM, PostfixAdmin and Roundcube.

**This is a replacement for the legacy installer, not an in-place migration.** Local checks exercise rendering, credentials and failure handling. Full VM, SELinux, external mail, upgrade and restore acceptance must pass before production release. The toolkit keeps public ingress restricted until an operator supplies release evidence.

## Security model

- Signed distribution packages; application archives supplied offline with independently verified SHA-256 digests. No `curl | bash`, unsigned mirror, mutable helper download, or self-updater.
- TLS-required authenticated submission on 587 and IMAPS on 993. Public MX on 25 offers TLS with Internet SMTP interoperability and Postscreen pre-greeting screening. POP3, cleartext IMAP and optional 465 are disabled.
- Loopback-only trusted relaying; submission requires authentication and envelope sender ownership. Rspamd enforces matching header/envelope identities, filters ingress and egress, signs DKIM and limits outbound recipients per account. Filter failures defer SMTP.
- Independent read-only lookup/authentication SQL users and restricted web application identities. Separate PHP pools; HTTPS, administrative CIDRs, client certificates and PostfixAdmin TOTP; installation routes denied.
- Enforcing SELinux, persistent service configuration, bounded diagnostic logging, explicit firewall zones, encrypted offsite backups, health checks and alert integration.

## Prepare a deployment

Read [deployment requirements](docs/DEPLOYMENT.md), [operations and recovery](docs/OPERATIONS.md), [DNS configuration](docs/DNS.md), and the [implementation/acceptance status](docs/IMPLEMENTATION.md).

Obtain a reviewed checkout/release, inspect its changes, and transfer it to the dedicated host. Provision trusted signed package repositories, certificates and offsite backup access first. There is no automatic repository/key trust bootstrap.

```bash
cp config/site.example.json site.json
chmod 600 site.json
# Edit all site-specific fields, archive digests, network restrictions and operator.
./install.sh init-secrets --output secrets.json
./install.sh render --config site.json --secrets secrets.json --output build
```

Rendering is offline and does not modify host services. PHP CLI is required only for initial setup-hash generation and PHP checks. Render output and secrets must stay private; the default ignore rules exclude them.

On the prepared Rocky host, deploy as root:

```bash
sudo ./install.sh deploy --config /root/site.json
```

The installer creates its own persistent credentials under `/etc/eric-mail/`; do not copy preview secrets onto an established host. Services are available only from configured management CIDRs until activation. The managed runtime is installed under `/opt/eric-mail/current`.

Provision accounts without passwords in argv:

```bash
sudo /opt/eric-mail/current/install.sh admin --address operator@your-domain.tld
sudo /opt/eric-mail/current/install.sh mailbox --address postmaster@your-domain.tld
sudo /opt/eric-mail/current/install.sh mailbox --address abuse@your-domain.tld
```

Enroll administrator TOTP, publish DNS, run acceptance tests, record evidence using `config/release-evidence.example.json`, then activate. Never mark checks true without executing them.

```bash
sudo /opt/eric-mail/current/install.sh activate --evidence /root/release-evidence.json
```

## Development checks

Python 3.9+ and PHP CLI are sufficient for the unit suite. ShellCheck is required for release checks.

```bash
python3 -m unittest discover -s tests -v
./tests/check.sh
```

The GitHub CI workflow runs local checks. The VM acceptance workflow is manually dispatched on a disposable, explicitly configured self-hosted lab runner. It must never target a production host.

See [SECURITY.md](SECURITY.md) for reporting, patch policy and deployment limitations. The original [review](SECURITY-REVIEW.md) remains the historical baseline; the implementation status document tracks changes and remaining environment-dependent verification.


## Optional minimal SQL replica

For a peer-restricted, mutually authenticated, read-only MariaDB replica without a web/mail stack, see [SQL disaster-recovery replication](docs/REPLICATION.md). This does not provide mailbox replication, a backup MX or automatic failover; independent offsite backups remain mandatory.
