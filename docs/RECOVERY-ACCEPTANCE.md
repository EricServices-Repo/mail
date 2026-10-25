# Full-host acceptance and durable queue recovery

Routine backups now cold-copy the stopped Postfix spool into `backup-stage/postfix-spool`, alongside the consistent application database dump and mailbox data. Protect this copy as sensitive mail. Restore queued mail only into an isolated host using the same Postfix version, ownership, queue layout and configuration; recreate runtime sockets/PIDs rather than starting copied processes. Verify queue IDs/recipients and duplicate handling before controlled requeue. Never restore a live spool or attest zero loss solely from SQL replication.

Optional low-pause backup: provision `/var/vmail` as a dedicated ordinary thick LVM LV (XFS/ext4), then install root-owned mode 0600 `/etc/eric-mail/snapshot.json` using the example. Install `lvm2` and `util-linux`. The backup stops writers, dumps SQL/copies queues, freezes/flushed mail storage, creates a bounded COW snapshot, unfreezes and resumes writers before remote upload. The read-only snapshot is removed after backup; COW usage must stay below 90%. Size/monitor it for peak write churn. A thaw marker is retained on failure: recover with `fsfreeze --unfreeze /var/vmail` after inspecting the failed operation. An unmount failure leaves the LV for deliberate cleanup. This mode requires an actual filesystem crash/interruption/restore drill; the default remains the slower consistent writer pause.

`tests/lab_scenarios.py` plus the manual protected GitHub workflow records measured install/rerun, reboot, isolated restore extraction, upgrade and interrupted-install scenarios. It refuses hosts without the disposable marker and explicit environment acknowledgement. Run interruption on a fresh throwaway clone and restore the VM snapshot before another scenario. Reboot is performed deliberately by the lab operator between install/reboot-check; the checker refuses an unchanged boot ID. Credentials, certificates, trusted archives, backup repository and lab VM must be supplied independently.

Restore extraction validates the recovery set, not a working recovered mail host. On a SECOND isolated compatible VM import the dump, restore mailbox paths using `backup-stage/installation.json` mapping (`mail_source` differs in snapshot mode), recreate credentials/grants and start services under enforcing SELinux. Run SMTP→LMTP→IMAP retrieval and attachment/queue comparison against known fixtures, then execute certificate renewal, TOTP/browser and external relay/IPv6 probes. Record measured data loss/recovery duration and separately retain results; the workflow never fabricates release approval booleans. Offsite immutability and independent recovery keys remain required infrastructure settings.


A guarded second-host import is available as `tests/recover_host.py`. On a separate
empty, pre-provisioned, network-isolated disposable VM, restore the explicit source
snapshot using the normal restore command, then create a root-owned mode-0600
`/etc/eric-mail-recovery-target` containing `EMPTY_SECOND_LAB_HOST`. With the existing
disposable marker and `ERIC_MAIL_DISPOSABLE_LAB=I_ACCEPT_DESTRUCTIVE_LAB_PROVISIONING`,
run `python3 tests/recover_host.py --restored-directory /var/lib/eric-mail/restore-NAME`.
The tool requires identical runtime release/package inventory/configuration and no
existing target accounts/mail/queues. It imports SQL, mailbox data, seed encryption
key and DKIM material, recreates configuration/grants, restores enforcing labels,
holds recovered queues, checks services and takes a fresh backup. A failed import
leaves services stopped and an interruption marker: reset the VM before retrying.
It deliberately supports baseline/MFA hosts only; network/PKI/LVM/security profiles
need a separate site-specific recovery drill, and detected profiles are rejected.
It never unholds recovered mail or opens public ingress. Run an independent
canary/retrieval and compare known messages/attachments before recording acceptance.
The recovery result reports measured import duration and does not assert an RPO
without comparison against independently recorded source fixtures.
