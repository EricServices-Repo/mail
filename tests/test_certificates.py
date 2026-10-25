import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('certificate_mailctl', Path(__file__).resolve().parents[1] / 'lib/mailctl.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = '/opt/homebrew/opt/openssl@3/bin/openssl'
        if not Path(cls.openssl).exists(): cls.openssl = shutil.which('openssl')
        if not cls.openssl: raise unittest.SkipTest('OpenSSL required')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cert = self.root / 'cert.pem'; self.key = self.root / 'key.pem'
        result = subprocess.run([self.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30',
                                 '-subj', '/CN=mail.example.test', '-addext', 'subjectAltName=DNS:mail.example.test,DNS:admin.example.test',
                                 '-addext', 'extendedKeyUsage=serverAuth', '-keyout', str(self.key), '-out', str(self.cert)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0)
        self.c = {'hostname': 'mail.example.test', 'admin_hostname': 'admin.example.test',
                  'certificate': str(self.cert), 'private_key': str(self.key)}

    def verify(self, c):
        original = m.run
        def run(argv, **kwargs): return original([self.openssl, *argv[1:]], **kwargs)
        with mock.patch.object(m, 'run', side_effect=run):
            m.verify_server_certificate(c, ca_bundle=str(self.cert))

    def test_chain_and_both_hostnames_are_verified(self):
        self.verify(self.c)
        for key in ('hostname', 'admin_hostname'):
            wrong = dict(self.c); wrong[key] = 'wrong.example.test'
            with self.subTest(key=key):
                with self.assertRaises(m.MailError): self.verify(wrong)

    def test_different_private_key_is_rejected(self):
        other = self.root / 'other.key'
        subprocess.run([self.openssl, 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(other)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        wrong = dict(self.c, private_key=str(other))
        with self.assertRaises(m.MailError): self.verify(wrong)

    def test_fingerprint_uses_leaf_even_with_chain(self):
        content = self.cert.read_text(); self.cert.write_text(content + content)
        expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(content)).hexdigest()
        self.assertEqual(m.certificate_fingerprint(self.cert), expected)

    def test_renewal_serializes_validates_restarts_and_checks_live_state(self):
        state = self.root / 'state'; state.mkdir()
        m.atomic(state / 'installed.json', json.dumps({'fingerprint': m.fingerprint(self.c)}))
        events = []
        @contextlib.contextmanager
        def lock():
            events.append('lock'); yield; events.append('unlock')
        with mock.patch.object(m, 'STATE', state), mock.patch.object(m, 'lock', lock), \
             mock.patch.object(m, 'validate', side_effect=lambda c: events.append('validate')), \
             mock.patch.object(m, 'health', side_effect=lambda c: events.append('health')), \
             mock.patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)), \
             mock.patch.object(m, 'run', side_effect=lambda argv: events.append(argv)):
            m.renew_certificate(self.c)
        self.assertEqual(events, ['lock', 'validate', ['systemctl', 'reload', 'nginx'],
                                  ['systemctl', 'restart', 'postfix', 'dovecot'], 'health', 'unlock'])

    def test_invalid_renewal_never_restarts_services(self):
        state = self.root / 'state'; state.mkdir()
        m.atomic(state / 'installed.json', json.dumps({'fingerprint': m.fingerprint(self.c)}))
        with mock.patch.object(m, 'STATE', state), mock.patch.object(m, 'lock', contextlib.nullcontext), \
             mock.patch.object(m, 'validate', side_effect=m.MailError('Invalid renewed certificate')), \
             mock.patch.object(m, 'run') as run:
            with self.assertRaises(m.MailError): m.renew_certificate(self.c)
            run.assert_not_called()


if __name__ == '__main__': unittest.main()
