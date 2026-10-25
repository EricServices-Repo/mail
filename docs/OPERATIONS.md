# Operations, upgrades and recovery

## Daily operation

Use `/opt/eric-mail/current/install.sh --help`. Site configuration is `/etc/eric-mail/site.json`; root-only generated credentials are `/etc/eric-mail/secrets.json`. Do not edit generated files or replace secret files to rotate passwords without a coordinated application/database change. File copies, backups and manifests containing secrets must retain their protected modes.

- `health` checks services, certificate expiration, verified IMAPS/STARTTLS, AUTH gating, queue depth/age, free bytes/inodes, backup age, configuration validators and SELinux-compatible service behavior. A systemd timer runs it every five minutes. View `/var/lib/eric-mail/health.json` and the system journal.
- `backup` stops mail/web/filter/cache writers, dumps application databases, creates an encrypted offsite snapshot and checks the repository. It restarts previously active services even if a dump/backup fails. This deliberately introduces a maintenance pause for consistent snapshots; remote SMTP senders retry. Measure backup duration and schedule appropriately. Large installations should replace this with tested volume snapshots plus database-consistency coordination before claiming low downtime.
- Nightly backups run around 02:00 in the server's configured timezone. Set the server timezone deliberately and monitor `eric-mail-backup.timer`. Define business-approved RPO/RTO; the default schedule alone is not a recovery guarantee. Backup success older than 26 hours is unhealthy. Restic `check` validates repository structure; schedule `check --read-data` separately and perform actual restores.
- `debug-on` enables password-redacted Dovecot auth diagnostics for fifteen minutes. `debug-off` explicitly disables it. The expiration timer remains enabled across reboot. Never enable password debug settings manually. Journald retention is bounded to thirty days/512 MiB; forward security logs to protected storage using organizational rsyslog/journal configuration.
- `domain --domain new-domain.tld` inserts/reactivates a domain and produces a new protected DKIM DNS file. Add it to the reviewed desired-state domain list through `upgrade` first so configuration/backup/release evidence stays in sync. This command changes neither client whitelists nor certificates. It never grants relay trust.
- `mailbox --address ...` and `admin --address ...` use confirmed hidden prompts; secrets are not command-line arguments. Bootstrap passwords are 16–72 UTF-8 bytes. Use the restricted PostfixAdmin portal for ongoing account/alias administration. Provision and test `postmaster` and `abuse` mailboxes. Multi-recipient aliases may forward mail but are intentionally not granted sender identity ownership automatically; a single alias pointing directly to an enabled mailbox may submit as that alias. Recursive/delegated send-as rules need an explicit reviewed extension.

Watch authentication failures, outbound bursts and filter rejects in logs/your centralized alert system. Per-IP bans and per-authenticated-user recipient buckets complement one another. Maintain independent external synthetic send-and-retrieve probes with dedicated accounts, protecting their credentials separately. `tests/probe.py` provides a deliberate one-shot SMTP probe; schedule an external canary with your monitoring service. The local health probe alerts on at least 100 authentication failures or ten rate-limit events over five minutes; tune these reviewed thresholds to your environment and retain centralized detection. Local health alone cannot observe public DNS, deliverability or a remote blocklist.

The baseline integrates spam and domain-authentication filtering, not an antivirus engine. If attachment malware scanning is required, connect a maintained, resource-bounded ClamAV service through Rspamd, keep signatures current, define scanner failure as deferral, and verify EICAR/archive-limit tests on staging. Do not describe attachments as safe solely because they were scanned.

## Certificate renewal and live identity checks

`renew-certificate` validates the chain, both configured DNS names and key match before touching services. It acquires the operation lock, reloads Nginx, restarts Postfix and Dovecot (fresh mail processes were required by issues #12/#16/#18), then checks health. It refuses to start deliberately stopped services or run during an incomplete deployment. Sharing the backup lock prevents certificate hooks from restarting writers during a consistent backup.

Health compares live HTTPS, IMAPS and submission leaf fingerprints against the configured fullchain. A valid but stale certificate is unhealthy even before it expires. A hook failure, including lock contention, requires investigation and an explicit retry after maintenance (`install.sh renew-certificate`); an ACME success alone does not prove every listener loaded the new certificate. The local tests use real certificates to verify both accepted and rejected names and key mismatch, and check that failed validation causes no restart.

## Updates

Assign an owner to OS, PHP, Roundcube, PostfixAdmin, Composer dependencies, Rspamd and signing-key advisories. Triage critical exposures immediately; target a tested critical fix within 24 hours. Verify distribution backports and update reviewed version floors. The toolkit has no mutable remote self-update and no automatic application downgrade.

1. Obtain/review the new source bundle and complete application archives. Record verified digests and compatible versions in a new config, preserving stable hostnames/interface and all existing domains. Inspect the schema migration notes and bundled dependency audit.
2. Rehearse the exact OS/application upgrade and full rollback on a disposable clone. Preserve an isolated pre-upgrade configuration copy and protected offsite snapshot. Validate snapshot recovery credentials before the maintenance window.
3. Run the **new reviewed bundle**: `sudo ./install.sh upgrade --config /root/new-site.json --previous-config /root/previous-site.json`. It checks the previous fingerprint, verifies archives/certificates, backs up old state, retains old application trees and snapshot references under `/var/lib/eric-mail/upgrades/`, closes public ingress, applies migrations and validates the new stack.
4. A failure leaves public ingress restricted and affected web/mail services stopped. It does not swap old code over a changed database and declare success. Recover the coordinated snapshot using the procedure below. A successful upgrade remains management-only until fresh acceptance evidence and activation.
5. Verify quota/delivery/login/aliases, schema versions, TOTP, installed package inventory, certificates, external probes and a new backup. Re-run `activate` with evidence for the new fingerprint. Keep recovery material until retention policy permits removal.

Rerunning unchanged `deploy` reapplies deterministic files without generating new keys/secrets, but intentionally performs validation, a maintenance restart and backup and returns ingress to restricted mode. It is not a zero-downtime configuration API. Hostname, interface and topology migrations are deliberately rejected by the generic upgrade command.

## Restore drill and coordinated recovery

`restore` only accepts an explicit Restic snapshot ID and a **new** `/var/lib/eric-mail/restore-*` directory. It verifies restored data and refuses direct restoration over live files. Example:

```bash
sudo /opt/eric-mail/current/install.sh restore --snapshot 01234567 --output /var/lib/eric-mail/restore-drill
```

Use the actual ID from `restic snapshots --tag eric-mail` with the protected backup environment. This command only materializes files; successful extraction does not prove a functioning restored service.

For a full drill/recovery:

1. Record failure time and approved RPO/RTO. Fence the old host and restrict networking on the recovery VM; prevent two active delivery writers. Keep a console session and preserve incident evidence where relevant. Use offline recovery credentials if the original server is unavailable.
2. Restore the chosen coordinated snapshot into an isolated directory on a fresh compatible host. Verify its host/config fingerprint, package inventory, application release digests and backup-stage SQL file. Do not run restored scripts blindly if compromise is suspected.
3. Install compatible signed OS packages and the **matching reviewed application/runtime release**. Keep all mail/web writers stopped. Restore `/var/vmail`, the application databases from `var/lib/eric-mail/backup-stage/databases.sql`, configuration, application code, webmail encryption key, DKIM keys and persistent service data as one recovery point. Review and re-provision credentials with root Unix-socket authentication; database dumps contain application schemas, while server account grants are recreated from the protected secrets under a trusted provisioning procedure. Never combine old application code with an incompatible newer schema.
4. Restore ownership/modes, enforcing SELinux labels, systemd units and firewall restrictions. Reissue public certificates if necessary; do not expose expired/revoked keys. Check hostname/IP/DNS/routing. Restore or deliberately reset Redis rate-limit state according to the incident plan.
5. Run every daemon validator, SQL grants tests, mailbox quota/delivery/retrieval checks, webmail session checks and external canaries from restricted test sources. Confirm postmaster/abuse mail, DKIM alignment, bounce behavior, monitoring, backups and notifications. Verify a selected mailbox's messages and attachments against the snapshot. Record actual data loss and recovery duration.
6. Complete new release evidence and publish deliberately. Monitor deferred remote deliveries and queue drains. Reconcile any old-host queues under a reviewed duplicate-safe procedure; the backup excludes volatile Postfix queue files and does not promise zero loss of accepted-but-undelivered mail. If the required RPO includes queued mail, implement and test queue/volume snapshots before release.

Automatic live restore, database down-migrations, split-brain promotion and multi-node replication remain intentionally unsupported. The former replication helpers exit with an error. Availability engineering must include consistent mailbox/database replication, authenticated private links, fencing and real failure drills rather than an all-interface database listener.

## Incident response

Restrict ingress (`close`), disable affected accounts, preserve relevant logs/snapshots and assess credential/key exposure. Rotate known/default/reused secrets from any legacy deployment, including independent database credentials and webmail session keys, with a coordinated change. Logging passwords is prohibited; review historical log disclosure if legacy debugging was used. Rebuild from a trusted release if host integrity is uncertain. Apply retention rules to sensitive incident evidence and report through your organization's process.
