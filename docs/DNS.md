# DNS, identity and transport policy

DNS changes are not made by this repository. Verify all records using authoritative DNS and an independent receiver before activation.

For each hosted domain, publish an MX pointing to the stable mail hostname. Publish its A and, only if fully routed/tested, AAAA record. Arrange matching PTR records with the address provider and verify the SMTP HELO name. Do not publish untested IPv6 or a backup MX that cannot enforce the same recipient/security policy.

Publish a narrowly scoped SPF record describing every legitimate sender (for example, `v=spf1 mx -all` only when the MX machines really are the complete sender set). Create dedicated DKIM TXT records using `/var/lib/eric-mail/dns/<domain>.txt`. Split long TXT data into DNS-provider-compatible quoted segments. Verify the published key matches the private key before sending; limit private-key readability to the filter. For selector rotation, publish the new selector first, change the reviewed selector/config, validate signatures, and retain the old public key until previously signed mail has aged out. Retain old private keys only according to recovery policy.

Start DMARC with reporting (`p=none`) to a monitored, authorized reporting mailbox. Confirm alignment for all legitimate senders, forwarding and business applications before moving to quarantine/reject. Protect report access and retention. Test alias/delegation behavior and mailing-list/forwarded mail; SPF failure alone is not a reason to reject forwarded mail. Rspamd supplies SPF/DKIM/DMARC evaluation and scoring; tune policy with measured false-positive outcomes.

Create actual postmaster and abuse mailboxes and test external delivery. A DNS record does not create a mailbox. Do not use sender-domain or client-hostname whitelists as relay authorization.

## Stronger interdomain TLS

Port 25 offers opportunistic TLS for SMTP interoperability. Client access requires TLS 1.2 or later. For stronger authenticated interdomain delivery, deploy MTA-STS and TLS-RPT or DNSSEC/DANE after certificate/DNS operations are reliable.

For MTA-STS, host the exact `/.well-known/mta-sts.txt` policy over HTTPS on `mta-sts.<domain>`, publish the `_mta-sts` policy ID and `_smtp._tls` report address, and start in testing mode. Use a separately maintained static policy endpoint; the default mail web vhost does not pretend to serve a policy for another hostname. Validate all MX names/certificates before enforcing and document cache-aware rollback.

DANE requires a DNSSEC-signed and validated zone, accurate SMTP TLSA records and certificate/key rollover procedures. Test DNSSEC failures and key rollover in staging. Do not publish TLSA or enforce a TLS policy without verifying the full chain of trust. Outbound Postfix TLS policy/DANE configuration must be added and tested for the chosen resolver and deployment; default outbound `may` does not authenticate arbitrary remote mail servers.
