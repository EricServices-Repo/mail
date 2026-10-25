# Domain lifecycle

A deployment inserts missing domains but never reactivates or changes the suspension state of existing domains. Removing a name from site.json does not delete its mail or silently alter database policy: decommission it explicitly before removing it from desired state. Destructive mailbox/domain removal is intentionally a separate retention operation.

Use `install.sh domain-disable --domain example.com` to disable a domain and terminate matching IMAP sessions. Disabled domains cannot authenticate, forward aliases, or use existing SMTP authenticated sessions to submit as an owned sender. Use `domain-enable` explicitly after adding the domain to reviewed desired state. These commands never delete messages. Check that in-flight delivery/retries and retained web sessions follow the incident/retention policy. Creation through PostfixAdmin still requires coordinated desired-state/DKIM/DNS provisioning.
