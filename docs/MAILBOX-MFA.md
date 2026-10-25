# Built-in mailbox MFA

New deployments enforce the bundled `eric_mfa` Roundcube plugin. Before activating an existing deployment after this upgrade, enroll every mailbox through the trusted administrator CLI: `python3 /opt/eric-mail/current/lib/mail_auth.py enroll --address user@example.com`. It prints an otpauth enrollment URI and ten recovery codes once; deliver them through an authenticated separate channel, confirm authenticator enrollment with the user, and keep recovery codes offline. No email or chat messages are automatically sent. Re-enrollment invalidates existing factors/recovery codes and terminates IMAP sessions; perform identity verification before an administrator resets MFA.

Webmail requires the mailbox password plus TOTP or a one-use recovery code before contacting IMAP. Codes use RFC 6238 SHA-1, six digits, 30-second periods, +/- one step, persisted replay protection, and five failures trigger a ten-minute account lockout. Recovery codes are consumed even if the subsequent password check fails. Seeds are authenticated-encrypted using libsodium; protect/back up `/etc/eric-mail/mfa.key`. Missing schema/key, unenrolled users, database errors and invalid CSRF checks fail closed. Existing webmail sessions without MFA verification are invalidated; account/domain suspension is checked on each authenticated request.

For external IMAP/SMTP clients, issue a unique expiring credential: `mail_auth.py device --address user@example.com --label Thunderbird --days 90`. Configure the exact returned username (`address#device-id`) and random password; the canonical mailbox identity is returned by Dovecot so paths/sender ownership stay unchanged. Primary mailbox passwords are accepted only from loopback for the trusted webmail backend, whose TLS peer name remains verified. Device passwords are single-factor bearer credentials, not MFA. Revoke with `revoke --address ... --id ...`; all active IMAP sessions for that mailbox are kicked. `suspend` disables login/submission and revokes all device credentials.

There is no public enrollment/reset endpoint. Administrator-mediated enrollment is deliberately conservative. The web tier remains a trusted component; restrict its egress and local access. Test the full Roundcube form/session flow, clock skew, replay, lockout, recovery consumption, client credentials, revocation and suspension on the supported Rocky host before production activation. Do not interpret PHP lint or pure TOTP vectors as complete browser/IMAP acceptance.

Web sessions are bound to the enrollment seed version and account identity. Resetting
enrollment invalidates existing web sessions on their next request; the short-lived
pending login state is cleared on every attempt and cannot be reused across accounts.
Administrative enrollment/device/revocation/suspension actions emit authpriv audit
events without enrollment seeds, recovery codes or device passwords.
