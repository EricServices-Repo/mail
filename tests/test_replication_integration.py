"""Isolated real-MariaDB TLS/replication exercise; never attaches to a host database."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import replication as r


@unittest.skipUnless(os.environ.get('ERIC_MAIL_SQL_INTEGRATION') == '1' and shutil.which('docker'),
                     'Requires explicit isolated Docker integration opt-in')
class MariaDBIntegration(unittest.TestCase):
    def command(self, argv, data=None):
        p = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if p.returncode: self.fail('Integration command failed: ' + argv[0] + ' (' + str(p.returncode) + ')')
        return p.stdout

    def db(self, node, sql):
        return self.command(['docker', 'exec', '-i', node, 'mariadb', '--user=root', '--batch', '--raw', '--skip-column-names'],
                            data="SET SESSION sql_mode='NO_BACKSLASH_ESCAPES';\n" + sql)

    def ready(self, node):
        for _ in range(90):
            p = subprocess.run(['docker', 'exec', node, 'mariadb-admin', '--user=root', 'ping'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if not p.returncode: return
            time.sleep(1)
        self.fail('Isolated MariaDB did not become ready')

    def status(self):
        text = self.command(['docker', 'exec', '-i', self.replica_name, 'mariadb', '--user=root', '--vertical'], 'SHOW SLAVE STATUS;')
        return r.parse_status(text)

    def wait_replication(self):
        for _ in range(60):
            try:
                row = self.status()
                r.check_replica_status(row, 300)
                return row
            except r.m.MailError:
                time.sleep(1)
        self.fail('Replica did not reach verified TLS / running IO and SQL state')

    def test_mutual_tls_seed_live_changes_read_only_restart_and_failure(self):
        suffix = uuid.uuid4().hex[:10]
        network = 'mail-replication-' + suffix
        self.primary_name = 'mail-primary-' + suffix
        self.replica_name = 'mail-replica-' + suffix
        names = [self.primary_name, self.replica_name]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            try:
                self.command(['docker', 'network', 'create', '--subnet', '10.197.0.0/24', network])
                self.command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30',
                              '-subj', '/CN=Eric Mail integration CA', '-keyout', str(root / 'ca.key'), '-out', str(root / 'ca.pem')])
                configs = {}
                for role, ip, peer in [('primary', '10.197.0.2', '10.197.0.3'), ('replica', '10.197.0.3', '10.197.0.2')]:
                    c = json.loads((r.m.ROOT / ('config/replication-' + role + '.example.json')).read_text())
                    c.update(bind_address=ip, peer_address=peer, primary_hostname='sql-primary.integration.test', tls_ca=str(root / 'ca.pem'))
                    configs[role] = c
                    folder = root / role; folder.mkdir()
                    host = 'sql-primary.integration.test' if role == 'primary' else 'mail-replica'
                    self.command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + host,
                                  '-keyout', str(folder / 'key.pem'), '-out', str(folder / 'cert.csr')])
                    (folder / 'extensions').write_text('subjectAltName=DNS:' + host + '\nextendedKeyUsage=' +
                                                       ('serverAuth' if role == 'primary' else 'clientAuth') + '\n')
                    self.command(['openssl', 'x509', '-req', '-in', str(folder / 'cert.csr'), '-CA', str(root / 'ca.pem'),
                                  '-CAkey', str(root / 'ca.key'), '-CAcreateserial', '-days', '30',
                                  '-extfile', str(folder / 'extensions'), '-out', str(folder / 'cert.pem')])
                    shutil.copyfile(root / 'ca.pem', folder / 'ca.pem')
                    (folder / 'server.cnf').write_text(r.mysql_configuration(c))
                    os.chmod(folder / 'server.cnf', 0o644)
                    name = names[0 if role == 'primary' else 1]
                    argv = ['docker', 'create', '--name', name, '--network', network, '--ip', ip,
                            '-e', 'MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1', '-e', 'MARIADB_ROOT_HOST=localhost']
                    if role == 'primary': argv += ['--network-alias', c['primary_hostname']]
                    # Disposable compatibility fixture only; production uses signed Rocky packages.
                    argv += ['mariadb:10.5.29']
                    self.command(argv)
                    self.command(['docker', 'cp', str(folder / 'server.cnf'), name + ':/etc/mysql/conf.d/eric-mail.cnf'])
                    tls = folder / 'eric-mail-tls'; tls.mkdir()
                    for filename in ('ca.pem', 'cert.pem', 'key.pem'): shutil.copyfile(folder / filename, tls / filename)
                    os.chmod(tls / 'key.pem', 0o600)
                    self.command(['docker', 'cp', str(tls), name + ':/var/lib/mysql/eric-mail-tls'])
                    self.command(['docker', 'start', name]); self.ready(name)
                self.db(self.primary_name, 'CREATE DATABASE postfixadmin; CREATE DATABASE roundcubemail; '
                        'CREATE TABLE postfixadmin.replica_test (id INT PRIMARY KEY); INSERT INTO postfixadmin.replica_test VALUES (1); '
                        'CREATE TABLE roundcubemail.replica_test (id INT PRIMARY KEY); INSERT INTO roundcubemail.replica_test VALUES (1);')
                secret = {'username': 'mail_replica', 'password': 'a' * 64}
                self.db(self.primary_name, r.primary_account(configs['primary'], secret))
                dump = self.command(['docker', 'exec', self.primary_name, 'mariadb-dump', '--user=root', '--single-transaction',
                                     '--master-data=2', '--databases', 'postfixadmin', 'roundcubemail'])
                dump_path = root / 'dump.sql'; dump_path.write_text(dump)
                log, pos = r.dump_coordinates(dump_path)
                self.db(self.replica_name, dump)
                self.db(self.replica_name, r.change_master(configs['replica'], secret, {'log_file': log, 'log_position': pos}) + ' START SLAVE;')
                self.wait_replication()
                self.db(self.primary_name, 'INSERT INTO postfixadmin.replica_test VALUES (2); INSERT INTO roundcubemail.replica_test VALUES (2);')
                for _ in range(30):
                    if self.db(self.replica_name, 'SELECT COUNT(*) FROM postfixadmin.replica_test; SELECT COUNT(*) FROM roundcubemail.replica_test;').strip() == '2\n2': break
                    time.sleep(1)
                else: self.fail('Live mail database changes did not replicate')
                self.assertEqual(self.db(self.replica_name, 'SELECT @@read_only,@@skip_networking;').strip(), '1\t1')
                # Normal database identities cannot bypass read-only; root is deliberately privileged for recovery.
                self.db(self.replica_name, "CREATE USER 'test_writer'@'localhost'; GRANT ALL ON postfixadmin.* TO 'test_writer'@'localhost';")
                denied = subprocess.run(['docker', 'exec', '-i', self.replica_name, 'mariadb', '--user=test_writer'],
                                        input='INSERT INTO postfixadmin.replica_test VALUES (99);', text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertNotEqual(denied.returncode, 0)
                self.db(self.replica_name, 'STOP SLAVE;')
                with self.assertRaises(r.m.MailError): r.check_replica_status(self.status(), 300)
                self.db(self.replica_name, 'START SLAVE;'); self.wait_replication()
                # Complete the seed exactly as the production provisioner does, then exercise automatic restart.
                conf = root / 'replica/server.cnf'
                conf.write_text(r.mysql_configuration(configs['replica']).replace('skip-slave-start\n', ''))
                self.command(['docker', 'cp', str(conf), self.replica_name + ':/etc/mysql/conf.d/eric-mail.cnf'])
                self.command(['docker', 'restart', self.replica_name]); self.ready(self.replica_name); self.wait_replication()
                # Possessing the replication password without the client certificate must not authenticate.
                opts = root / 'no-certificate.cnf'
                opts.write_text('[client]\nuser=mail_replica\npassword=' + secret['password'] + '\n'
                                'host=sql-primary.integration.test\nssl-ca=/var/lib/mysql/eric-mail-tls/ca.pem\nssl-verify-server-cert\n')
                os.chmod(opts, 0o600)
                self.command(['docker', 'cp', str(opts), self.replica_name + ':/tmp/no-certificate.cnf'])
                missing_cert = subprocess.run(['docker', 'exec', '-i', self.replica_name, 'mariadb',
                                               '--defaults-extra-file=/tmp/no-certificate.cnf', '--protocol=tcp'],
                                              input='SELECT 1;', text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertNotEqual(missing_cert.returncode, 0)
            finally:
                for name in names:
                    subprocess.run(['docker', 'rm', '-fv', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == '__main__': unittest.main()
