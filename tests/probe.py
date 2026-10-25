#!/usr/bin/env python3
"""Run only against your authorized staging host and controlled test addresses."""
import argparse
import getpass
import json
import smtplib
import socket
import ssl
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True)
    p.add_argument('--connect-address', required=True, help='Specific IPv4/IPv6 address to test')
    p.add_argument('--recipient', required=True, help='Existing controlled local recipient')
    p.add_argument('--external-recipient', required=True, help='Controlled recipient at an external domain')
    p.add_argument('--username', help='Optional controlled submission account; password prompted')
    p.add_argument('--deliver', action='store_true', help='Send a real test message to the local recipient')
    args = p.parse_args()
    results = {}
    ctx = ssl.create_default_context()

    def connect(port):
        client = smtplib.SMTP(timeout=15)
        client._host = args.host  # STARTTLS must validate the DNS name, not the selected IP
        client.sock = socket.create_connection((args.connect_address, port), timeout=15)
        code, _ = client.getreply()
        if code != 220: raise RuntimeError('SMTP greeting rejected')
        client.ehlo()
        return client

    with connect(25) as mx:
        results['mx_auth_hidden'] = 'auth' not in mx.esmtp_features
        mx.mail('probe@' + args.external_recipient.split('@')[-1])
        code, _ = mx.rcpt(args.external_recipient)
        results['unauthenticated_relay_rejected'] = 500 <= code < 600
        mx.rset()
        mx.mail('probe@' + args.external_recipient.split('@')[-1])
        code, _ = mx.rcpt(args.recipient)
        results['inbound_recipient_without_starttls'] = 200 <= code < 300
    with connect(587) as smtp:
        results['submission_auth_hidden_before_tls'] = 'auth' not in smtp.esmtp_features
        smtp.mail(args.recipient)
        code, _ = smtp.rcpt(args.recipient)
        results['submission_without_tls_rejected'] = 500 <= code < 600
        smtp.rset()
        smtp.starttls(context=ctx); smtp.ehlo()
        results['submission_auth_after_verified_tls'] = 'auth' in smtp.esmtp_features
        smtp.mail(args.recipient)
        code, _ = smtp.rcpt(args.recipient)
        results['submission_without_auth_rejected'] = 500 <= code < 600
        smtp.rset()
        if args.username:
            smtp.login(args.username, getpass.getpass('Test account password: '))
            smtp.mail(args.external_recipient)
            code, _ = smtp.rcpt(args.recipient)
            results['unauthorized_envelope_sender_rejected'] = 500 <= code < 600
            smtp.rset()
            if args.deliver:
                smtp.sendmail(args.username, [args.recipient],
                              'From: ' + args.username + '\r\nTo: ' + args.recipient +
                              '\r\nSubject: Authorized mail acceptance probe\r\n\r\nTest delivery.\r\n')
                results['authenticated_submission_accepted'] = True
    with socket.create_connection((args.connect_address, 993), timeout=15) as raw:
        with ctx.wrap_socket(raw, server_hostname=args.host) as tls:
            results['imaps_verified'] = tls.recv(1024).startswith(b'* OK')
    for port in (110, 143, 465, 995, 3306, 6379, 11332, 11334):
        try:
            with socket.create_connection((args.connect_address, port), timeout=3):
                results['closed_' + str(port)] = False
        except (TimeoutError, OSError):
            results['closed_' + str(port)] = True
    print(json.dumps(results, indent=2))
    return 0 if all(results.values()) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, smtplib.SMTPException):
        print('Protocol probe failed; inspect authorized target and private service logs.', file=sys.stderr)
        sys.exit(1)
