import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('mailctl', Path(__file__).resolve().parents[1] / 'lib/mailctl.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.c = json.loads((m.ROOT / 'config/site.example.json').read_text())
        self.c.update(operator='Test operator', roundcube_sha256='a' * 64, postfixadmin_sha256='b' * 64)
        self.config_path = self.root / 'site.json'
        self.config_path.write_text(json.dumps(self.c))
        self.secret_path = self.root / 'secrets.json'
        self.s = {n: str(i) * 64 for i, n in enumerate(('mail_admin', 'mail_lookup', 'mail_auth', 'roundcube'), 1)}
        self.s.update(des_key='a' * 24, setup_hash='$2y$10$' + 'a' * 53)
        m.atomic(self.secret_path, json.dumps(self.s))

    def config(self, c=None):
        self.config_path.write_text(json.dumps(c or self.c))
        return m.configuration(self.config_path)

    def test_valid_configuration(self):
        self.assertEqual(self.config(), self.c)

    def test_reject_config_injections_and_stale_versions(self):
        invalid = [('hostname', 'mail.example.com; touch /tmp/pwn'),
                   ('hostname', '../mail.example.com'), ('domains', ['bad\nname.com']),
                   ('management_networks', ['0.0.0.0/0']), ('management_networks', ['::/0']),
                   ('management_networks', ['10.0.0.1/24']), ('private_key', '/etc/key;id'),
                   ('interface', 'eth0;id'), ('dkim_selector', '../../key'),
                   ('roundcube_version', '1.6.5'), ('postfixadmin_version', '3.3.13'),
                   ('roundcube_sha256', 'unknown'), ('alert_command', 'echo done'),
                   ('outbound_burst', True), ('mailbox_quota_mb', 0)]
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                c = copy.deepcopy(self.c); c[key] = value
                with self.assertRaises((m.MailError, ValueError)):
                    self.config(c)

    def test_unknown_keys_rejected(self):
        c = dict(self.c, password='do not accept unstructured secrets')
        with self.assertRaises(m.MailError): self.config(c)

    def test_private_credentials_and_no_reuse(self):
        self.assertEqual(m.secrets_file(self.secret_path), self.s)
        os.chmod(self.secret_path, 0o644)
        with self.assertRaises(m.MailError): m.secrets_file(self.secret_path)
        self.s['mail_auth'] = self.s['mail_lookup']
        m.atomic(self.secret_path, json.dumps(self.s))
        with self.assertRaises(m.MailError): m.secrets_file(self.secret_path)

    def test_render_is_idempotent_and_preserves_native_variables(self):
        out = self.root / 'render'
        first = m.render(self.config(), self.s, out)
        times = {x['path']: (out / x['path'].lstrip('/')).stat().st_mtime_ns for x in first}
        self.assertEqual(first, m.render(self.c, self.s, out))
        for x in first:
            p = out / x['path'].lstrip('/')
            self.assertEqual(m.digest(p), x['sha256'])
            self.assertEqual(p.stat().st_mtime_ns, times[x['path']])
            self.assertEqual(p.stat().st_mode & 0o777, x['mode'])
            self.assertNotIn('@@', p.read_text())
        nginx = (out / 'etc/nginx/nginx.conf').read_text()
        self.assertIn('$document_root$fastcgi_script_name', nginx)
        self.assertIn('$host$request_uri', nginx)
        self.assertIn('ssl_verify_client on', nginx)
        php = (out / 'opt/eric-mail/apps/roundcube/config/config.inc.php').read_text()
        self.assertIn("$config['des_key']", php)
        self.assertIn('rawurlencode', php)

    def test_listener_and_privilege_boundaries(self):
        out = self.root / 'render'; entries = m.render(self.config(), self.s, out)
        postfix = (out / 'etc/postfix/main.cf').read_text()
        master = (out / 'etc/postfix/master.cf').read_text()
        dovecot = (out / 'etc/dovecot/dovecot.conf').read_text()
        self.assertIn('mynetworks = 127.0.0.0/8, [::1]/128', postfix)
        self.assertIn('smtpd_sasl_auth_enable = no', postfix)
        self.assertIn('smtpd_tls_security_level = may', postfix)
        self.assertIn('milter_default_action = tempfail', postfix)
        self.assertIn('smtpd_relay_restrictions=permit_sasl_authenticated,reject', master)
        self.assertIn('reject_authenticated_sender_login_mismatch', master)
        self.assertNotIn('smtps', master)  # unused optional port is closed
        self.assertIn('auth_debug_passwords = no', dovecot)
        self.assertIn('ssl = required', dovecot)
        self.assertNotIn('pop3', dovecot)
        self.assertIn('service auth {', dovecot)
        lookup = (out / 'etc/postfix/sql/domains.cf').read_text()
        auth = (out / 'etc/dovecot/mail-sql.conf.ext').read_text()
        self.assertIn('mail_lookup', lookup); self.assertIn('mail_auth', auth)
        self.assertNotIn(self.s['mail_admin'], lookup + auth)
        self.assertEqual(next(x for x in entries if x['path'].endswith('mail-sql.conf.ext'))['mode'], 0o600)

    @unittest.skipUnless(shutil.which('php'), 'PHP required for generated config lint')
    def test_all_php_templates_lint(self):
        out = self.root / 'render'; m.render(self.config(), self.s, out)
        php = list(out.rglob('*.php')) + list((m.ROOT / 'templates').glob('*.php'))
        for p in php:
            with self.subTest(path=p.name):
                result = subprocess.run(['php', '-l', str(p)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('php'), 'PHP required to verify password hashing')
    def test_setup_password_hashes_actual_input_and_secrets_persist(self):
        path = self.root / 'new.json'
        original_run = m.run
        captured = []
        def capture(argv, **kw):
            if argv[0] == 'php': captured.append(kw['data'])
            return original_run(argv, **kw)
        with mock.patch.object(m, 'run', side_effect=capture): s = m.init_secrets(path)
        test = '[$h,$p]=json_decode(stream_get_contents(STDIN),true); echo password_verify($p,$h)&&!password_verify("",$h)?"ok":"bad";'
        self.assertEqual(m.run(['php', '-r', test], data=json.dumps([s['setup_hash'], captured[0]])), 'ok')
        self.assertNotIn(captured[0], path.read_text())
        self.assertEqual(m.init_secrets(path), s)
        self.assertEqual(len(s['des_key'].encode()), 24)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_atomic_write_refuses_symlink(self):
        target = self.root / 'target'; target.write_text('safe')
        link = self.root / 'link'; link.symlink_to(target)
        with self.assertRaises(m.MailError): m.atomic(link, 'unsafe')
        self.assertEqual(target.read_text(), 'safe')

    def test_archive_checks_digest_traversal_links_and_devices(self):
        for name, kind in [('app/../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE),
                           ('app/link', tarfile.SYMTYPE), ('app/dev', tarfile.CHRTYPE),
                           ('../escape', tarfile.REGTYPE)]:
            archive = self.root / 'test.tar.gz'
            with tarfile.open(archive, 'w:gz') as tf:
                member = tarfile.TarInfo(name); member.type = kind
                if kind == tarfile.REGTYPE: member.size = 4
                tf.addfile(member, io.BytesIO(b'test') if kind == tarfile.REGTYPE else None)
            with self.subTest(name=name, kind=kind):
                with self.assertRaises(m.MailError): m.archive_check(archive, m.digest(archive))
        with self.assertRaises(m.MailError): m.archive_check(archive, 'f' * 64)

    def test_valid_archive(self):
        archive = self.root / 'valid.tar.gz'
        with tarfile.open(archive, 'w:gz') as tf:
            member = tarfile.TarInfo('app/vendor/autoload.php'); member.size = 4
            tf.addfile(member, io.BytesIO(b'test'))
        self.assertEqual(m.archive_check(archive, m.digest(archive)), 'app')

    def test_command_failures_do_not_leak_stdout_stderr(self):
        with mock.patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, 'secret', 'secret')):
            with self.assertRaises(m.MailError) as caught: m.run(['php', 'tool'])
        self.assertNotIn('secret', str(caught.exception))

    def test_backup_environment_is_literal_not_shell(self):
        password = self.root / 'restic-password'; m.atomic(password, 'secret')
        envfile = self.root / 'restic.env'
        m.atomic(envfile, 'RESTIC_REPOSITORY=s3:https://backup.example.com/bucket\n'
                 'RESTIC_PASSWORD_FILE=' + str(password) + '\nAWS_SECRET_ACCESS_KEY=$(touch /tmp/unsafe)\n')
        env = m.load_backup_environment(envfile)
        self.assertEqual(env['AWS_SECRET_ACCESS_KEY'], '$(touch /tmp/unsafe)')
        m.atomic(envfile, envfile.read_text() + 'PATH=/tmp\n')
        with self.assertRaises(m.MailError): m.load_backup_environment(envfile)

    def test_publication_rejects_stale_or_incomplete_evidence(self):
        state = self.root / 'state'; state.mkdir()
        m.atomic(state / 'installed.json', json.dumps({'fingerprint': m.fingerprint(self.c), 'release': 'test-release'}))
        proof = self.root / 'proof.json'
        for checks, timestamp in [({}, time.time()), ({k: True for k in m.EVIDENCE}, 1)]:
            m.atomic(proof, json.dumps({'fingerprint': m.fingerprint(self.c), 'operator': self.c['operator'],
                                       'checks': checks, 'completed_at': timestamp}))
            with mock.patch.object(m, 'STATE', state), mock.patch.object(m, 'lock', m.contextlib.nullcontext), mock.patch.object(m, 'firewall') as fw:
                with self.assertRaises(m.MailError): m.activate(self.c, proof)
                fw.assert_not_called()

    def test_backup_failure_always_restarts_original_services_and_never_marks_success(self):
        state = self.root / 'state'; state.mkdir()
        m.atomic(state / 'configuration-manifest.json', '[]')
        events = []
        def command(argv, **kwargs):
            events.append(argv)
            if argv[:2] == ['restic', 'backup']: raise m.MailError('simulated backup failure')
            return ''
        def proc(argv, **kwargs): return subprocess.CompletedProcess(argv, 0, '', '')
        with mock.patch.object(m, 'STATE', state), mock.patch.object(m, 'directory', side_effect=lambda p, *a: Path(p).mkdir(parents=True, exist_ok=True)), mock.patch.object(m, 'load_backup_environment', return_value={'RESTIC_PASSWORD_FILE': '/root/private-key'}), mock.patch.object(m, 'run', side_effect=command), mock.patch.object(m.subprocess, 'run', side_effect=proc):
            with self.assertRaises(m.MailError): m.backup(self.c, already_locked=True)
        self.assertTrue(any(x[:2] == ['systemctl', 'start'] for x in events))
        self.assertFalse((state / 'last-backup.json').exists())
        self.assertFalse((state / 'backup-stage/databases.sql').exists())


    def test_release_hash_and_runtime_health_gate_publication(self):
        state = self.root / 'state'; state.mkdir()
        m.atomic(state / 'installed.json', json.dumps({'fingerprint': m.fingerprint(self.c), 'release': 'reviewed-release'}))
        evidence = self.root / 'evidence.json'
        proof = {'fingerprint': m.fingerprint(self.c), 'release': 'old-release', 'operator': self.c['operator'],
                 'completed_at': time.time(), 'checks': {k: True for k in m.EVIDENCE}}
        with mock.patch.object(m, 'STATE', state), mock.patch.object(m, 'lock', m.contextlib.nullcontext), mock.patch.object(m, 'firewall') as fw, mock.patch.object(m, 'health') as health:
            m.atomic(evidence, json.dumps(proof))
            with self.assertRaises(m.MailError): m.activate(self.c, evidence)
            fw.assert_not_called()
            proof['release'] = 'reviewed-release'; m.atomic(evidence, json.dumps(proof))
            health.side_effect = m.MailError('Unhealthy runtime')
            with self.assertRaises(m.MailError): m.activate(self.c, evidence)
            fw.assert_not_called()
            health.side_effect = None
            m.activate(self.c, evidence)
            fw.assert_called_once_with(self.c, True)
            self.assertTrue((state / 'published.json').exists())

    def test_restic_command_environment_is_rejected(self):
        password = self.root / 'password'; m.atomic(password, 'secret')
        envfile = self.root / 'restic.env'
        m.atomic(envfile, 'RESTIC_REPOSITORY=s3:https://backup.example.com/bucket\n'
                 'RESTIC_PASSWORD_FILE=' + str(password) + '\nRESTIC_PASSWORD_COMMAND=unsafe\n')
        with self.assertRaises(m.MailError): m.load_backup_environment(envfile)

    @unittest.skipUnless(shutil.which('php'), 'PHP required for secret serialization check')
    def test_php_secret_values_are_data_not_executable_code(self):
        fake = self.root / 'roundcube.json'
        special = "spaces ' \\ / @ : $config\n"
        fake.write_text(json.dumps({'password': special, 'hostname': 'mail.example.com', 'des_key': 'a' * 24}))
        source = (m.ROOT / 'templates/roundcube.php').read_text().replace('/etc/eric-mail/roundcube.json', str(fake))
        script = self.root / 'roundcube.php'
        script.write_text(source + "\necho json_encode([$config['db_dsnw'], $config['des_key']]);\n")
        result = json.loads(m.run(['php', script]))
        from urllib.parse import quote
        self.assertEqual(result[0], 'mysql://roundcube:' + quote(special, safe='') + '@localhost/roundcubemail')
        self.assertEqual(result[1], 'a' * 24)


if __name__ == '__main__': unittest.main()
