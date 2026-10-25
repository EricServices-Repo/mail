# Dedicated-host deployment

Use the native Bash installer from the complete reviewed checkout/release:
`sudo bash install.sh --config /root/site.json`. A bare `sudo bash install.sh`
deploys the prepared `/etc/eric-mail/site.json`. Bash dispatches the installer
commands to Python 3.9+ security/configuration helpers, so both runtimes are
required on the target. Services run directly under systemd; Docker is not an
installation or runtime dependency. `bash install.sh --help` lists commands.

## Supported target and prerequisites

The only configured target is Rocky Linux 9 with systemd, enforcing SELinux, Postfix >=3.5, Dovecot 2.3 and PHP 8.3 from AppStream. The runtime rejects incompatible Dovecot/PHP versions. As of the review, conservative upstream PHP floors are 8.3.36/8.4.27/8.5.12. A distribution build with an older version and a security backport needs an explicit reviewed policy change; it is not silently accepted. Version floors are a dated baseline, not an advisory feed.

Use a fresh VM with console access, one dedicated ingress interface, static addresses, forward/reverse DNS and sufficient storage. Do not place unrelated services on it. The deployment replaces mail/web configuration and controls the specified interface's firewalld zone. Additional interfaces, cloud security groups, NAT and upstream firewalls must be managed separately. Keep SSH key/MFA access restricted. A provisioning failure leaves mail/web stopped and public ingress closed; use the console if management-network input was incorrect.

Configure official distribution repositories and any required EPEL/Rspamd repositories using their publishers' signing instructions and independently checked key fingerprints. Review every enabled repository. The installer does not fetch signing keys or repository RPMs. DNF enforces package signatures, including local RPMs; initial key trust is an operator responsibility. Ensure `dnf install rspamd restic fail2ban-firewalld` can resolve signed packages before deployment. Do not turn signature checks off to work around missing packages.

Obtain complete release archives (with `vendor/autoload.php`) for Roundcube and PostfixAdmin. Verify their signatures/provenance, including bundled dependency security status, outside the installer. Record their SHA-256 values in the reviewed site configuration. Defaults require Roundcube >=1.6.20 on 1.6 or >=1.7.5 on 1.7, and PostfixAdmin >=4.0.5; recheck advisories before use. The PHP 8.4 PostfixAdmin release bundle may run under compatible PHP 8.3, but validate its Composer platform requirements. If a complete compatible artifact is unavailable, build and audit it in a separate trusted build environment. Never run dependency installation as the web service user in production.

The installer accepts only tar.gz archives with one root directory, regular files/directories, no traversal, symlinks, devices or setuid bits, and <1 GiB unpacked content. It verifies the configured digest before extraction and checks the declared application version. Store archives at the configured absolute paths; their credentials/configuration are not included in application artifacts.

## Certificates and restricted administration

Provision a production certificate covering both service hostnames and its full chain. The key must be root-owned and mode 0600. Certificates, key and admin client CA must not be writable by others. The deployment checks the chain, names, matching private key and at least fourteen days of validity. It does not deploy staging/self-signed server certificates or start HTTP login pages.

Use ACME DNS-01 with a narrowly scoped DNS credential outside web roots, or a separate protected issuance workflow. Configure renewal through the packaged Certbot timer and validate its availability (`systemctl list-timers '*certbot*'`); the toolkit installs a deploy hook to validate the renewed chain and both hostnames, reload Nginx, restart Postfix/Dovecot and check the served certificate fingerprints under the operation lock. A non-Certbot CA must invoke the same locked renewal operation (`install.sh renew-certificate`). If the hook fails because a backup or deployment holds the lock, re-run that command after the operation completes; Certbot may not automatically repeat a deploy hook for an already-renewed certificate. Run `certbot renew --dry-run` and inspect every live listener before attesting renewal.

Create an organizational client CA for administration and issue revocable client certificates. Set `admin_client_ca` to its PEM trust bundle and `admin_client_crl` to a current signed PEM CRL. The installer/monitor verifies the CRL signature and at least one day of validity; Nginx enforces revocation. Keep CRL publication and reloads in your PKI rotation workflow. Configure narrow management networks (IPv4 /24 or narrower and IPv6 /64 or narrower); these are administrative reachability grants, never SMTP relay trust. Both the network restriction and a valid client certificate are required for the admin vhost. Enable TOTP for each administrator; do not grant exceptions. Establish client-certificate revocation/rotation operations and access removal. The current Nginx template uses CA verification; add your CA's CRL policy before release.

The mail hostname is stable across hosted domains. Adding a mail domain does not create new web hostnames or expand the certificate SAN list. Public ingress opens only 25/80/443/587/993. Port 80 redirects the two configured names; unknown hosts are dropped. IMAPS and submission use the stable mail hostname and a certificate-valid DNS route back to the same host for local webmail/health probes.

## Backups and notifications are mandatory

Create a remote Restic repository with separate credentials and initialize it manually. The installer will not initialize or delete remote repositories. Restrict backup credentials, use provider-supported object retention/versioning/immutability, and keep recovery credentials and the encryption password offline under separate control. Verify the chosen backend's immutable-retention behavior with Restic before enabling it.

Example `/etc/eric-mail/restic.env`, root-owned mode 0600 (literal values, no shell quotes or `export`):

```text
RESTIC_REPOSITORY=s3:https://backup-provider.example/bucket/mail
RESTIC_PASSWORD_FILE=/root/recovery/restic-password
AWS_ACCESS_KEY_ID=your-backup-key
AWS_SECRET_ACCESS_KEY=your-backup-secret
```

The password file must be root-owned mode 0600. Supported offsite prefixes are `s3:https://`, `rest:https://`, `b2:`, `azure:` and `gs:`. The environment parser does not source/evaluate input. Keep recovery keys outside backed-up trees. Configure repository retention with a separately authorized retention identity; the routine backup command intentionally does not run `forget`/`prune`.

Install a root-owned, executable mode 0700 notification command and set its absolute argv array in `alert_command`. It receives an event name and private health-result path. It must reach an independent alerting system, return nonzero on failed delivery and avoid sending secrets. Test it with `install.sh alert --event staging-notification-test`; configure monitoring for failure of the notification channel itself. The toolkit invokes this hook on target-system service failures; it does not configure a specific email/chat provider or send messages during development.

## Apply and publish

Review all `site.json` fields. `deploy` refuses preexisting `/var/vmail`, managed app directories or active mail/web services on first install. Use the migration plan for legacy systems. It creates independent cryptographically random persistent SQL credentials, validates configurations, applies narrow grants, initializes databases, generates DKIM keys, installs systemd operations, starts services behind management-only ingress and takes an initial verified remote backup. First deployment failures need inspection/recovery; partial installations are intentionally not treated as fresh hosts on retry.

Run the external probe from each authorized management test source (IPv4, IPv6 and LAN) and the manual acceptance checklist in `config/release-evidence.example.json`. Management sources may reach mail ports for testing even before public activation. Do not infer public network success from a localhost check. Use a disposable staging instance with matching topology for destructive failure/upgrade/restore tests. Release evidence must identify the exact configuration fingerprint and runtime release hash (from `/var/lib/eric-mail/installed.json`), responsible operator, UTC epoch completion time and all checks as true; keep detailed test logs separately. Evidence is an accountable attestation, not cryptographic proof of a penetration test.

`activate` checks matching installed state, complete/fresh evidence (<7 days), runtime health and backup freshness before opening public ports. It does not alter DNS or upstream firewalls. Repeated deploy/upgrade returns to management-only mode and requires reactivation. `close` restricts public ingress without destroying mail or keys.

## Signed toolkit releases

Repository maintainers can use `scripts/package-release.sh SIGNED_REF NEW_OUTPUT_DIR SIGNING_KEY` to package a committed, signature-verified Git revision and sign its archive manifest. The script rejects unsigned revisions and an existing output directory. Keep release signing keys separate from the mail host and application/backup credentials. Configure the Git signing verification environment and verify the signing identity, not merely that some unknown key signed a commit.

On the target, verify `manifest.sig` using an independently distributed/pinned public release key (`openssl dgst -sha256 -verify trusted-release-public.pem -signature manifest.sig manifest.json`), then compare the archive's SHA-256 to the signed manifest **before extraction or execution**. A content-addressed installed runtime records what was installed; it does not independently prove who authorized it. GitHub branch protection and signing-key custody remain repository-owner controls.
