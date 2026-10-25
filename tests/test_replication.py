import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import replication as r


class ReplicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.primary = json.loads((r.m.ROOT / 'config/replication-primary.example.json').read_text())
        self.replica = json.loads((r.m.ROOT / 'config/replication-replica.example.json').read_text())

    def config(self, value):
        file = self.root / 'config.json'; file.write_text(json.dumps(value))
        return r.config(file)

    def bundle(self):
        bundle = self.root / 'bundle'; bundle.mkdir(mode=0o700)
        sql = "-- CHANGE MASTER TO MASTER_LOG_FILE='eric-mail-bin.000003', MASTER_LOG_POS=1234;\nCREATE DATABASE postfixadmin;\n"
        r.m.atomic(bundle / 'databases.sql', sql)
        meta = {'primary_hostname': self.replica['primary_hostname'], 'primary_address': '10.44.0.1',
                'replica_address': '10.44.0.2', 'primary_server_id': 1001, 'replica_server_id': 1002,
                'dump_sha256': r.m.digest(bundle / 'databases.sql'), 'log_file': 'eric-mail-bin.000003',
                'log_position': 1234, 'created_at': time.time(), 'source_version': '10.5.27-MariaDB'}
        r.m.atomic(bundle / 'metadata.json', json.dumps(meta))
        secret = {'username': 'mail_replica', 'password': 'a' * 64, 'primary_address': '10.44.0.1', 'replica_address': '10.44.0.2'}
        r.m.atomic(bundle / 'credentials.json', json.dumps(secret))
        return bundle, meta, secret

    def test_roles_have_narrow_private_endpoints_and_unique_ids(self):
        self.assertEqual(self.config(self.primary), self.primary)
        self.assertEqual(self.config(self.replica), self.replica)
        for key, value in [('bind_address', '0.0.0.0'), ('peer_address', '8.8.8.8'),
                           ('peer_address', '127.0.0.1'), ('peer_address', '10.44.0.1'),
                           ('peer_server_id', 1001), ('server_id', True),
                           ('management_networks', ['0.0.0.0/0']), ('tls_key', '/root/a;id'),
                           ('replication_user', 'replica@%'), ('private_interface', 'eth0;id')]:
            c = copy.deepcopy(self.primary); c[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises((r.m.MailError, ValueError)): self.config(c)

    def test_replica_has_no_listener_or_webmail_packages(self):
        text = r.mysql_configuration(self.replica)
        self.assertIn('skip-networking=1', text)
        self.assertIn('read-only=ON', text)
        self.assertIn('skip-slave-start', text)  # partial seeds must not auto-run
        self.assertIn('replicate-wild-do-table=postfixadmin.%', text)
        self.assertIn('replicate-wild-do-table=roundcubemail.%', text)
        for name in ('php-fpm', 'nginx', 'dovecot', 'postfix', 'rspamd'):
            self.assertNotIn(name, r.MINIMAL_PACKAGES)
        self.assertIn('require-secure-transport=ON', r.mysql_configuration(self.primary))
        self.assertIn('bind-address=10.44.0.1', r.mysql_configuration(self.primary))

    def test_primary_account_is_exact_peer_and_certificate_bound(self):
        with mock.patch.object(r.m, 'run', return_value='subject=/CN=Mail CA\n'):
            statement = r.primary_account(self.primary, {'password': 'a' * 64})
        self.assertIn("'mail_replica'@'10.44.0.2'", statement)
        self.assertIn("REQUIRE SUBJECT '/CN=mail-replica' AND ISSUER '/CN=Mail CA'", statement)
        self.assertIn('GRANT REPLICATION SLAVE ON *.*', statement)
        self.assertNotIn('ALL PRIVILEGES', statement)
        self.assertNotIn("@'%'", statement)

    def test_sql_literals_and_secret_stdin(self):
        self.assertEqual(r.sql("a'\\b"), "'a''\\b'")
        with mock.patch.object(r.m, 'run', return_value='') as run:
            r.database("SELECT 'secret';")
        args, kwargs = run.call_args
        self.assertNotIn('secret', ' '.join(args[0]))
        self.assertIn("sql_mode='NO_BACKSLASH_ESCAPES'", kwargs['data'])

    def test_bundle_checks_identity_digest_coordinates_and_age(self):
        bundle, meta, secret = self.bundle()
        self.assertEqual(r.validate_bundle(self.replica, bundle), (meta, secret))
        for field, value in [('primary_server_id', 999), ('log_position', 999),
                             ('created_at', 1), ('dump_sha256', 'f' * 64)]:
            bad = dict(meta); bad[field] = value
            r.m.atomic(bundle / 'metadata.json', json.dumps(bad))
            with self.subTest(field=field):
                with self.assertRaises(r.m.MailError): r.validate_bundle(self.replica, bundle)
        r.m.atomic(bundle / 'metadata.json', json.dumps(meta))
        os.chmod(bundle / 'credentials.json', 0o644)
        with self.assertRaises(r.m.MailError): r.validate_bundle(self.replica, bundle)

    def test_change_master_requires_verified_mutual_tls(self):
        _, meta, secret = self.bundle()
        statement = r.change_master(self.replica, secret, meta)
        self.assertIn('MASTER_SSL=1, MASTER_SSL_VERIFY_SERVER_CERT=1', statement)
        self.assertIn('MASTER_SSL_CERT=', statement)
        self.assertIn('MASTER_SSL_KEY=', statement)
        self.assertIn("MASTER_HOST='sql-primary.internal.example.com'", statement)
        self.assertIn('MASTER_LOG_POS=1234', statement)
        self.assertNotIn('MASTER_USE_GTID=current_pos', statement)

    def test_health_rejects_stopped_threads_unknown_lag_and_unverified_tls(self):
        row = {'Slave_IO_Running': 'Yes', 'Slave_SQL_Running': 'Yes', 'Master_SSL_Allowed': 'Yes',
               'Master_SSL_Verify_Server_Cert': 'Yes', 'Seconds_Behind_Master': '0'}
        self.assertEqual(r.check_replica_status(row, 300), 0)
        for key, value in [('Slave_IO_Running', 'Connecting'), ('Slave_SQL_Running', 'No'),
                           ('Master_SSL_Verify_Server_Cert', 'No'), ('Master_SSL_Allowed', 'No'),
                           ('Seconds_Behind_Master', 'NULL'), ('Seconds_Behind_Master', '301')]:
            bad = dict(row); bad[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(r.m.MailError): r.check_replica_status(bad, 300)

    def test_dump_rejects_multiple_or_unsafe_coordinates(self):
        path = self.root / 'dump.sql'
        for content in ["-- CHANGE MASTER TO MASTER_LOG_FILE='../../file', MASTER_LOG_POS=123;\n", '',
                        "-- CHANGE MASTER TO MASTER_LOG_FILE='eric-mail-bin.000001', MASTER_LOG_POS=4;\n" * 2]:
            path.write_text(content)
            with self.assertRaises(r.m.MailError): r.dump_coordinates(path)

    def test_firewall_never_opens_global_mysql_port(self):
        commands = []
        def run(cmd, **kwargs):
            commands.append(cmd)
            if '--get-zones' in cmd: return 'public eric-mail-replication'
            return ''
        with mock.patch.object(r.m, 'run', side_effect=run): r.firewall(self.primary)
        rules = [x[-1] for x in commands if x[-1].startswith('--add-rich-rule=')]
        mysql = [x for x in rules if '3306' in x]
        self.assertEqual(len(mysql), 1)
        self.assertIn('source address="10.44.0.2"', mysql[0])
        self.assertFalse(any('--add-port=3306/tcp' in cmd for cmd in commands))


if __name__ == '__main__': unittest.main()
