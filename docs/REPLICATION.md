# Private SQL disaster-recovery replica

Issue #4 requests SQL replication accounts and a minimal secondary installation without PostfixAdmin. This workflow supplies **one asynchronous, read-only MariaDB replica** of `postfixadmin` and `roundcubemail`. It does not replicate mailboxes, Postfix queues or application files; does not receive mail; and never promotes itself. Continue encrypted offsite backups. A synchronized database is not a complete mail backup or an automatic availability solution.

## Prepare two dedicated Rocky Linux 9 hosts

The primary must already be a healthy managed mail server with a working encrypted offsite backup. The replica must be a fresh dedicated host with an uninitialized MariaDB data directory and no mail/web stack. Both need enforcing SELinux, accurate synchronized clocks, supported signed repositories, the same MariaDB major/minor series, and a replica patch version no older than the primary. Minimal installation installs only MariaDB, OpenSSL, firewalld and SELinux tooling; no PHP, PostfixAdmin, Roundcube, Postfix, Dovecot or Rspamd is installed on the replica.

Provide a dedicated private interface on each host, distinct from the primary's public mail interface. The private addresses must be RFC1918 IPv4 or IPv6 unique-local addresses, with unique nonzero MariaDB server IDs. The primary binds TCP only to its private address. A dedicated DROP firewall zone allows port 3306 from the **single configured replica address**; it does not grant global MySQL service access. The replica has no database TCP listener. Management SSH is limited to configured CIDRs. Keep console access available and enforce the same private-peer restriction in upstream network policy. Additional host interfaces and upstream routes are not automatically managed.

Provision a private CA and separate server/client certificates outside this toolkit. The server certificate must cover the configured `primary_hostname` and have serverAuth use; the replica certificate needs clientAuth. The example assumes one CA directly issues both certificates. Set `peer_subject` on the primary to the exact replica subject in OpenSSL compat notation (for example `/CN=mail-replica`). The primary replication account requires that subject **and** that CA issuer; possession of the password alone is insufficient. Distribute the CA trust anchor independently. Server and client private keys are root-only at their source paths; installed copies are restricted to MariaDB under its SELinux-labeled data directory. Use short-lived certificates plus rotation/revocation procedures appropriate to your PKI. No CA private key is copied to either node.

Prepare a root-owned executable mode 0700 independent notification hook as in DEPLOYMENT.md. Example configurations live in `config/replication-primary.example.json` and `config/replication-replica.example.json`; edit every address, interface, certificate path and alert hook. Configuration fingerprints and bootstrap metadata must agree on peer identities and IDs. Keep sources of TLS credentials under `/etc/eric-mail` or include them in your separate secure recovery set.

## Configure the primary and export a consistent seed

From the reviewed bundle on the primary:

```bash
sudo ./scripts/mail-replication-primary.sh --config /root/replication-primary.json
sudo python3 /opt/eric-mail/current/lib/replication.py export --output /root/mail-replica-seed
```

Primary setup takes a verified backup before restarting MariaDB, briefly stops active mail/web writers, enables durable row-based binary logging with fourteen-day retention, creates a peer-specific `REPLICATION SLAVE` account using an independent generated password, requires encrypted database transport and saves the protected configuration. It preserves existing mail runtime SQL grants and does not create a wildcard replication account. Failure closes database TCP and resumes previously active mail/web services; operator inspection is required for partial setup rather than silently replacing an existing account/configuration.

The export uses `mariadb-dump --single-transaction --master-data=2` to capture a consistent seed and exact binary-log coordinates in the same operation. It never uses separate, ineffective lock/unlock client sessions. The bundle contains `databases.sql`, matching metadata/digest and root-only replication credentials. It contains mailbox password hashes and sensitive application data: transfer it only over an authenticated encrypted administrator channel, verify its provenance independently, keep every file mode 0600 and its directory mode 0700, and remove transfer copies after the recovery retention period. Digest validation detects corruption, not an attacker who can replace both data and metadata. Metadata and private file modes do not replace an authenticated transfer.

No schema migrations/DDL may run during export outside the toolkit's operation lock. Retain binary logs until the replica has caught up; if required logs have expired, generate a fresh seed and follow a deliberate reseed procedure.

## Bootstrap the minimal replica

Transfer the reviewed toolkit, replica-role config, client TLS inputs and fresh bundle to the isolated replica. Set `primary_hostname` DNS to the primary private address; certificate hostname validation stays enabled, so do not use an unverified address override. Then:

```bash
sudo ./scripts/mail-replication-secondary.sh --config /root/replication-replica.json --bundle /root/mail-replica-seed
sudo python3 /opt/eric-mail/current/lib/replication.py health
```

The seed must be less than a day old. Bootstrap verifies the dump digest, unique binlog coordinates, IDs, endpoint identities, certificate/key pair and MariaDB version compatibility. It refuses an existing initialized data directory or existing application databases. It imports the trusted seed through stdin, configures server certificate verification and mutual TLS for replication, starts both replication threads and verifies read-only/no-network state and bounded lag. The password is never put in argv. MariaDB must necessarily persist replication authentication material; protect its data directory and replication metadata files from local users.

A partial seed retains `skip-slave-start` and a failure marker, stops replication on error and requires explicit recovery. A completed seed removes that boot guard so MariaDB restarts replication automatically after reboot. A repeat with the same completed config only checks health; it does not reimport data or reset coordinates. Changed configuration and destructive reseeding are deliberately rejected. Keep root-only CLI and Unix-socket access restricted: MariaDB's `read_only` stops ordinary accounts, not privileged recovery administrators.

The primary and replica install a one-minute health timer with an independent OnFailure notification hook. It checks certificate validity, both replica threads, verified TLS, expected primary identity, lag and read-only/no-listener policy. The primary updates a replicated heartbeat, so an idle replica cannot appear healthy solely because `Seconds_Behind_Master` reports zero. The heartbeat threshold includes the timer interval; use at least 120 seconds in production unless you adjust scheduling. Unsynchronized clocks or stale heartbeats fail health. Monitor notification delivery independently and run an actual insert/update/delete canary, not just a process check.

## Required acceptance before relying on the replica

1. Run the full disposable two-VM workflow with enforcing SELinux and the real PKI, network interfaces and package sources. Check private listener binding, denied unapproved source addresses, password-only/TLS-without-client-certificate rejection and valid peer connection. Do not use production accounts or mailboxes for probes.
2. Verify a seeded record and subsequent insert/update/delete in each replicated database; confirm unrelated/system schemas and root user changes do not replicate. Application identities should not exist on the minimal replica, and no HTTP or mail port should be listening.
3. Attempt a write as an ordinary local test identity and verify read-only rejection. Stop IO/SQL threads, interrupt the link, exceed lag limits and corrupt/expire a test certificate; each failure must notify and recover only with validated TLS. Reboot both nodes and confirm replication resumes without resetting coordinates.
4. Verify heartbeat freshness and clock-skew behavior, binary-log retention/lag alerting, database consistency after interruption, and a restore from an independent offsite backup. Measure actual RPO/RTO. Practice a manual, fenced recovery of a complete mail host; SQL replication alone must not be treated as mailbox recovery.
5. Protect/remove seed copies and audit replication credentials. For key/password/peer changes or reseeding, take a new backup, stop the replica, coordinate primary account/config changes, verify certificates and regenerate a seed where needed. There is no automatic promotion or destructive reset option.

The CI Docker integration exercises real MariaDB configuration, consistent seeding, live changes to both databases, mutual TLS, denied password-only access, read-only enforcement, failure detection and restart. It uses disposable MariaDB 10.5 compatibility fixtures without exposing host ports. It does **not** establish Rocky service integration, SELinux behavior, upstream network restrictions, production PKI revocation or full mail recovery.

References: [MariaDB replication setup](https://mariadb.com/docs/server/ha-and-performance/standard-replication/setting-up-replication), [replication variables](https://mariadb.com/docs/server/ha-and-performance/standard-replication/replication-and-binary-log-system-variables).
