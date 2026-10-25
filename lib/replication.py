#!/usr/bin/env python3
"""Explicit, private MariaDB disaster-recovery replication, not mail failover."""
import argparse
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time

import mailctl as m

FIELDS = {'role', 'bind_address', 'peer_address', 'primary_hostname', 'server_id',
          'peer_server_id', 'private_interface', 'management_networks', 'tls_ca',
          'tls_certificate', 'tls_key', 'replication_user', 'credential_file',
          'max_lag_seconds', 'alert_command'}
CONFIG = Path('/etc/eric-mail/replication.json')
MYSQL_CONFIG = Path('/etc/my.cnf.d/zz-eric-mail-replication.cnf')
TLS_DIR = Path('/var/lib/mysql/eric-mail-tls')
DBS = ('postfixadmin', 'roundcubemail')
MINIMAL_PACKAGES = ('mariadb-server', 'firewalld', 'openssl', 'policycoreutils-python-utils')


def config(path):
    c = m.read_json(path)
    m.require(isinstance(c, dict) and c.get('role') in ('primary', 'replica'), 'Invalid replication role')
    expected = FIELDS | ({'peer_subject'} if c['role'] == 'primary' else set())
    m.require(set(c) == expected, 'Replication fields do not match role example')
    for k in ('bind_address', 'peer_address'):
        address = ipaddress.ip_address(c[k])
        private_ranges = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7')
        m.require(any(address in ipaddress.ip_network(n) for n in private_ranges),
                  'Replication endpoints must use RFC1918 or unique-local private addresses')
    m.require(c['bind_address'] != c['peer_address'] and
              ipaddress.ip_address(c['bind_address']).version == ipaddress.ip_address(c['peer_address']).version,
              'Replication peers must be distinct addresses of the same family')
    m.domain(c['primary_hostname'])
    for k in ('server_id', 'peer_server_id'):
        m.require(type(c[k]) is int and 1 <= c[k] <= 4294967295, 'Invalid MariaDB server ID')
    m.require(c['server_id'] != c['peer_server_id'], 'Peers need unique server IDs')
    m.require(isinstance(c['private_interface'], str) and
              re.fullmatch('[A-Za-z0-9_.:-]{1,32}', c['private_interface']), 'Invalid private interface')
    m.require(isinstance(c['management_networks'], list) and c['management_networks'], 'Management CIDRs required')
    for n in c['management_networks']:
        net = ipaddress.ip_network(n, strict=True)
        m.require(isinstance(n, str) and net.prefixlen >= (24 if net.version == 4 else 64), 'Management networks must be narrow')
    for k in ('tls_ca', 'tls_certificate', 'tls_key', 'credential_file'):
        m.path_value(c[k])
    m.require(isinstance(c['replication_user'], str) and re.fullmatch('[a-z][a-z0-9_]{0,31}', c['replication_user']),
              'Invalid replication account name')
    m.require(type(c['max_lag_seconds']) is int and 1 <= c['max_lag_seconds'] <= 86400, 'Invalid lag threshold')
    cmd = c['alert_command']
    m.require(isinstance(cmd, list) and cmd and all(isinstance(x, str) and '\x00' not in x for x in cmd), 'Alert hook must be argv')
    m.path_value(cmd[0])
    if c['role'] == 'primary':
        m.require(isinstance(c['peer_subject'], str) and re.fullmatch(r'/[A-Za-z0-9= /._@,-]{1,250}', c['peer_subject']),
                  'Set the exact authorized client certificate subject in OpenSSL compat form')
    return c


def sql(value):
    # Every batch sets NO_BACKSLASH_ESCAPES before these literals are used.
    m.require(isinstance(value, str) and '\x00' not in value, 'Invalid SQL literal')
    return "'" + value.replace("'", "''") + "'"


def database(statement):
    return m.run(['mariadb', '--protocol=socket', '--socket=/var/lib/mysql/mysql.sock',
                  '--batch', '--raw', '--skip-column-names'],
                 data="SET SESSION sql_mode='NO_BACKSLASH_ESCAPES';\n" + statement + '\n')


def certificate_check(c):
    for key in ('tls_ca', 'tls_certificate', 'tls_key'):
        p = Path(c[key]); st = p.stat()
        m.require(p.is_file() and st.st_uid == 0 and not st.st_mode & 0o022,
                  'Replication TLS inputs must be root-owned and not writable by others')
    m.private_file(c['tls_key'])
    purpose = 'sslserver' if c['role'] == 'primary' else 'sslclient'
    verify = ['openssl', 'verify', '-purpose', purpose, '-CAfile', c['tls_ca']]
    if c['role'] == 'primary': verify.extend(['-verify_hostname', c['primary_hostname']])
    m.run(verify + [c['tls_certificate']])
    m.run(['openssl', 'x509', '-in', c['tls_certificate'], '-noout', '-checkend', '1209600'])
    cert = m.run(['openssl', 'x509', '-in', c['tls_certificate'], '-pubkey', '-noout'])
    key = m.run(['openssl', 'pkey', '-in', c['tls_key'], '-pubout'])
    m.require(cert == key, 'Replication TLS key does not match certificate')
    m.private_file(c['alert_command'][0])
    m.require(os.access(c['alert_command'][0], os.X_OK), 'Replication alert hook must be executable')


def mysql_configuration(c):
    common = (f'[mysqld]\nserver-id={c["server_id"]}\nsocket=/var/lib/mysql/mysql.sock\n'
              'skip-name-resolve\nlocal-infile=0\nbinlog-format=ROW\n'
              'innodb-flush-log-at-trx-commit=1\n')
    if c['role'] == 'primary':
        return (common + f'skip-networking=0\nbind-address={c["bind_address"]}\n'
                'log-bin=/var/lib/mysql/eric-mail-bin\nsync-binlog=1\nexpire-logs-days=14\n'
                'ssl-ca=/var/lib/mysql/eric-mail-tls/ca.pem\n'
                'ssl-cert=/var/lib/mysql/eric-mail-tls/cert.pem\n'
                'ssl-key=/var/lib/mysql/eric-mail-tls/key.pem\n'
                'tls-version=TLSv1.2,TLSv1.3\nrequire-secure-transport=ON\n')
    return (common + 'skip-networking=1\nread-only=ON\nskip-slave-start\n'
            'relay-log=/var/lib/mysql/eric-mail-relay\nrelay-log-recovery=ON\n'
            'replicate-wild-do-table=postfixadmin.%\nreplicate-wild-do-table=roundcubemail.%\n')


def credentials(c, create=False):
    path = Path(c['credential_file'])
    if create and not path.exists():
        value = {'username': c['replication_user'], 'password': secrets.token_hex(32),
                 'primary_address': c['bind_address'], 'replica_address': c['peer_address']}
        m.atomic(path, json.dumps(value) + '\n')
    m.private_file(path)
    value = m.read_json(path)
    primary = c['bind_address'] if c['role'] == 'primary' else c['peer_address']
    replica = c['peer_address'] if c['role'] == 'primary' else c['bind_address']
    m.require(set(value) == {'username', 'password', 'primary_address', 'replica_address'} and
              value['username'] == c['replication_user'] and value['primary_address'] == primary and
              value['replica_address'] == replica and isinstance(value['password'], str) and
              re.fullmatch('[a-f0-9]{64}', value['password']), 'Credential bundle does not match configured peer')
    return value


def primary_account(c, secret):
    issuer = m.run(['openssl', 'x509', '-in', c['tls_ca'], '-noout', '-subject', '-nameopt', 'compat']).strip().split('=', 1)[1].strip()
    name = sql(c['replication_user']) + '@' + sql(c['peer_address'])
    return (f'CREATE USER {name} IDENTIFIED BY {sql(secret["password"])} '
            f'REQUIRE SUBJECT {sql(c["peer_subject"])} AND ISSUER {sql(issuer)};\n'
            f'GRANT REPLICATION SLAVE ON *.* TO {name};')


def firewall(c):
    zone = 'eric-mail-replication'
    if zone not in m.run(['firewall-cmd', '--permanent', '--get-zones']).split():
        m.run(['firewall-cmd', '--permanent', '--new-zone=' + zone])
    cmd = ['firewall-cmd', '--permanent', '--zone=' + zone]
    m.run(cmd + ['--set-target=DROP'])
    m.run(cmd + ['--change-interface=' + c['private_interface']])
    # This dedicated zone never grants a global service/port or an entire source zone.
    m.require(not m.run(cmd + ['--list-ports']).strip() and not m.run(cmd + ['--list-services']).strip(),
              'Replication zone contains unexpected broad port/service grants')
    for rule in m.run(cmd + ['--list-rich-rules']).splitlines():
        m.run(cmd + ['--remove-rich-rule=' + rule])
    for net in c['management_networks']:
        family = 'ipv6' if ':' in net else 'ipv4'
        m.run(cmd + [f'--add-rich-rule=rule family="{family}" source address="{net}" service name="ssh" accept'])
    if c['role'] == 'primary':
        family = 'ipv6' if ':' in c['peer_address'] else 'ipv4'
        m.run(cmd + [f'--add-rich-rule=rule family="{family}" source address="{c["peer_address"]}" port port="3306" protocol="tcp" accept'])
    m.run(['firewall-cmd', '--reload'])


def install_tls(c):
    m.directory(TLS_DIR, 0o750, 'root', 'mysql')
    for source, filename in [('tls_ca', 'ca.pem'), ('tls_certificate', 'cert.pem'), ('tls_key', 'key.pem')]:
        destination = TLS_DIR / filename
        m.atomic(destination, Path(c[source]).read_bytes(), 0o600 if source == 'tls_key' else 0o644)
        shutil.chown(destination, user='mysql', group='mysql')
    m.run(['restorecon', '-RF', TLS_DIR])


def timer(c):
    m.atomic(CONFIG, json.dumps(c, sort_keys=True, indent=2) + '\n')
    m.atomic('/etc/systemd/system/eric-mail-replication-monitor.service',
             '[Unit]\nDescription=Check private SQL replication health\nAfter=mariadb.service\n'
             'OnFailure=eric-mail-replication-alert.service\n[Service]\nType=oneshot\n'
             'ExecStart=/opt/eric-mail/current/lib/replication.py health\nUMask=0077\n'
             'PrivateTmp=true\nProtectHome=true\nProtectSystem=strict\nReadWritePaths=/var/lib/eric-mail\n', 0o644)
    m.atomic('/etc/systemd/system/eric-mail-replication-monitor.timer',
             '[Unit]\nDescription=Check SQL replication every five minutes\n[Timer]\n'
             'OnBootSec=2min\nOnUnitActiveSec=1min\nPersistent=true\n[Install]\nWantedBy=timers.target\n', 0o644)
    m.atomic('/etc/systemd/system/eric-mail-replication-alert.service',
             '[Unit]\nDescription=Notify operator of replication failure\n[Service]\nType=oneshot\n'
             'ExecStart=/opt/eric-mail/current/lib/replication.py alert\nUMask=0077\n', 0o644)
    m.run(['systemctl', 'daemon-reload'])
    m.run(['systemctl', 'enable', '--now', 'eric-mail-replication-monitor.timer'])


def primary(c):
    with m.lock():
        m.host_check(); m.require(c['role'] == 'primary', 'Primary role configuration required')
        site = m.configuration('/etc/eric-mail/site.json')
        installed = m.read_json(m.STATE / 'installed.json')
        m.require(installed['fingerprint'] == m.fingerprint(site), 'Primary must be a managed mail server')
        m.require(c['private_interface'] != site['interface'], 'SQL requires a separate private ingress interface')
        marker = m.STATE / 'replication-primary.json'
        if marker.exists():
            m.require(m.read_json(marker)['fingerprint'] == m.fingerprint(c), 'Replication changes require a coordinated reconfiguration')
            health(c); return
        m.require(not MYSQL_CONFIG.exists(), 'Existing replication configuration requires manual recovery, not overwrite')
        certificate_check(c)
        m.run(['ip', 'link', 'show', 'dev', c['private_interface']])
        m.require(database('SELECT COUNT(*) FROM mysql.user WHERE User=' + sql(c['replication_user']) + ';').strip() == '0',
                  'Replication account already exists; refusing to replace its credentials/grants')
        m.backup(site, already_locked=True)
        secret = credentials(c, create=True)
        active = [s for s in m.SERVICES if subprocess.run(['systemctl', 'is-active', '--quiet', s]).returncode == 0]
        try:
            if active: m.run(['systemctl', 'stop', *active])
            install_tls(c)
            firewall(c)
            m.atomic(MYSQL_CONFIG, mysql_configuration(c), 0o644)
            m.run(['systemctl', 'restart', 'mariadb'])
            m.require(database("SHOW VARIABLES LIKE 'have_ssl';").strip().endswith('\tYES'), 'MariaDB TLS is unavailable')
            database(primary_account(c, secret))
            database('CREATE TABLE IF NOT EXISTS postfixadmin.eric_replication_heartbeat (id TINYINT PRIMARY KEY, updated_at BIGINT UNSIGNED NOT NULL);')
            m.runtime_install(); timer(c)
            health(c)
            m.atomic(marker, json.dumps({'fingerprint': m.fingerprint(c), 'configured_at': time.time()}) + '\n')
        except BaseException:
            # Preserve diagnostics and close TCP even if SQL configuration/account creation failed.
            with contextlib.suppress(Exception):
                m.atomic(MYSQL_CONFIG, '[mysqld]\nskip-networking=1\n', 0o644)
                m.run(['systemctl', 'restart', 'mariadb'])
            raise
        finally:
            if active: m.run(['systemctl', 'start', *active])
        print('Primary configured for one certificate-authenticated private replica. Export a fresh bootstrap bundle next.')


def dump_coordinates(path):
    matches = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            if line.startswith('-- CHANGE MASTER TO '):
                match = re.fullmatch(r"-- CHANGE MASTER TO MASTER_LOG_FILE='(eric-mail-bin\.[0-9]+)', MASTER_LOG_POS=([0-9]+);\s*", line)
                m.require(match is not None, 'Invalid bootstrap binlog coordinates')
                matches.append((match[1], int(match[2])))
    m.require(len(matches) == 1 and matches[0][1] >= 4, 'Bootstrap dump needs exactly one valid binlog position')
    return matches[0]


def export(c, output):
    with m.lock():
        m.require(c['role'] == 'primary', 'Export requires the primary configuration')
        m.require(m.read_json(m.STATE / 'replication-primary.json')['fingerprint'] == m.fingerprint(c), 'Primary configuration mismatch')
        health(c)
        target = Path(output)
        m.path_value(str(target)); m.require(not target.exists(), 'Export directory must be new')
        target.mkdir(parents=True, mode=0o700)
        try:
            dump = target / 'databases.sql'
            with open(dump, 'wb') as f:
                result = subprocess.run(['mariadb-dump', '--protocol=socket', '--socket=/var/lib/mysql/mysql.sock',
                                         '--single-transaction', '--master-data=2', '--routines', '--events',
                                         '--databases', *DBS], stdout=f, stderr=subprocess.PIPE, check=False)
            m.require(result.returncode == 0, 'Consistent replica bootstrap dump failed')
            os.chmod(dump, 0o600)
            log_file, position = dump_coordinates(dump)
            metadata = {'primary_hostname': c['primary_hostname'], 'primary_address': c['bind_address'],
                        'replica_address': c['peer_address'], 'primary_server_id': c['server_id'],
                        'replica_server_id': c['peer_server_id'], 'dump_sha256': m.digest(dump),
                        'log_file': log_file, 'log_position': position, 'created_at': time.time(),
                        'source_version': database('SELECT VERSION();').strip()}
            m.atomic(target / 'metadata.json', json.dumps(metadata, indent=2) + '\n')
            m.atomic(target / 'credentials.json', json.dumps(credentials(c)) + '\n')
        except BaseException:
            shutil.rmtree(target)
            raise
        print('Private bootstrap bundle created. Transfer using an authenticated encrypted administrator channel.')


def validate_bundle(c, bundle):
    p = Path(bundle)
    m.require(p.is_dir() and not p.is_symlink() and p.stat().st_uid == os.geteuid()
              and not p.stat().st_mode & 0o077, 'Bootstrap directory must be private and locally owned')
    for name in ('metadata.json', 'credentials.json', 'databases.sql'):
        m.private_file(p / name)
    data = m.read_json(p / 'metadata.json')
    m.require(data['primary_hostname'] == c['primary_hostname'] and data['primary_address'] == c['peer_address']
              and data['replica_address'] == c['bind_address'] and data['primary_server_id'] == c['peer_server_id']
              and data['replica_server_id'] == c['server_id'], 'Bootstrap metadata identifies different peers')
    m.require(0 <= time.time() - data['created_at'] < 86400, 'Bootstrap must be less than one day old')
    m.require(m.digest(p / 'databases.sql') == data['dump_sha256'], 'Bootstrap dump integrity mismatch')
    log_file, position = dump_coordinates(p / 'databases.sql')
    m.require(data['log_file'] == log_file and data['log_position'] == position, 'Bootstrap coordinate mismatch')
    other = dict(c, credential_file=str(p / 'credentials.json'))
    secret = credentials(other)
    return data, secret


def change_master(c, secret, data):
    return (f'CHANGE MASTER TO MASTER_HOST={sql(c["primary_hostname"])}, MASTER_PORT=3306, '
            f'MASTER_USER={sql(secret["username"])}, MASTER_PASSWORD={sql(secret["password"])}, '
            f'MASTER_LOG_FILE={sql(data["log_file"])}, MASTER_LOG_POS={data["log_position"]}, '
            "MASTER_USE_GTID=no, MASTER_SSL=1, MASTER_SSL_VERIFY_SERVER_CERT=1, "
            "MASTER_SSL_CA='/var/lib/mysql/eric-mail-tls/ca.pem', "
            "MASTER_SSL_CERT='/var/lib/mysql/eric-mail-tls/cert.pem', "
            "MASTER_SSL_KEY='/var/lib/mysql/eric-mail-tls/key.pem', MASTER_CONNECT_RETRY=10;")


def replica(c, bundle):
    with m.lock():
        m.host_check(); m.require(c['role'] == 'replica', 'Replica role configuration required')
        marker = m.STATE / 'sql-replica.json'
        if marker.exists():
            m.require(m.read_json(marker)['fingerprint'] == m.fingerprint(c), 'Replica reconfiguration/reseed requires manual recovery')
            health(c); return
        m.require(not (m.STATE / 'installed.json').exists() and not MYSQL_CONFIG.exists()
                  and not Path('/opt/eric-mail/apps').exists(), 'Minimal replica requires a fresh dedicated database host')
        m.require(not m.run(['systemctl', 'list-units', '--state=active', '--no-legend',
                            *[s + '.service' for s in m.SERVICES]]).strip(), 'Replica refuses an active mail/web stack')
        m.require(not Path('/var/lib/mysql/mysql').exists(), 'Replica requires a fresh uninitialized MariaDB data directory')
        data, secret = validate_bundle(c, bundle)
        certificate_check(c)
        m.run(['ip', 'link', 'show', 'dev', c['private_interface']])
        m.run(['dnf', '-y', '--setopt=gpgcheck=1', '--setopt=*.gpgcheck=1',
               '--setopt=localpkg_gpgcheck=1', 'install', *MINIMAL_PACKAGES])
        m.run(['systemctl', 'enable', '--now', 'firewalld'])
        firewall(c)
        m.atomic(MYSQL_CONFIG, mysql_configuration(c), 0o644)
        m.run(['systemctl', 'enable', '--now', 'mariadb'])
        # Do not seed over existing application databases, even if the host was only partially configured.
        existing = database("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN "
                            "('mysql','information_schema','performance_schema','sys','test');").strip()
        m.require(not existing, 'Replica database is not empty; refusing destructive reseed')
        target_version = database('SELECT VERSION();').strip().split('-')[0]
        source_version = data['source_version'].split('-')[0]
        m.require(m.version(target_version)[:2] == m.version(source_version)[:2] and
                  m.version(target_version) >= m.version(source_version), 'Replica must use the same MariaDB series and no older patch version')
        m.directory(m.ETC, 0o755)
        install_tls(c)
        m.atomic(MYSQL_CONFIG, mysql_configuration(c), 0o644)
        firewall(c)
        m.atomic(m.STATE / 'replication-incomplete', 'Replica provisioning is incomplete\n')
        try:
            m.run(['systemctl', 'restart', 'mariadb'])
            # Remove only existing insecure bootstrap accounts; root remains Unix-socket authenticated.
            for line in database("SELECT User,Host FROM mysql.user WHERE User='' OR (User='root' AND Host NOT IN ('localhost','127.0.0.1','::1'));").splitlines():
                user, host = line.split('\t')
                database('DROP USER ' + sql(user) + '@' + sql(host) + ';')
            database('DROP DATABASE IF EXISTS test;')
            with open(Path(bundle) / 'databases.sql', 'rb') as f:
                result = subprocess.run(['mariadb', '--protocol=socket', '--socket=/var/lib/mysql/mysql.sock'],
                                        stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=False)
            m.require(result.returncode == 0, 'Bootstrap database import failed')
            m.atomic(c['credential_file'], json.dumps(secret) + '\n')
            database(change_master(c, secret, data)); database('START SLAVE;')
            for attempt in range(15):
                try:
                    health(c); break
                except m.MailError:
                    if attempt == 14: raise
                    time.sleep(1)
            m.runtime_install(); timer(c)
            m.atomic(marker, json.dumps({'fingerprint': m.fingerprint(c), 'seed_sha256': data['dump_sha256'],
                                        'configured_at': time.time()}) + '\n')
            # Only a completely configured replica may auto-start replication after reboot.
            m.atomic(MYSQL_CONFIG, mysql_configuration(c).replace('skip-slave-start\n', ''), 0o644)
            (m.STATE / 'replication-incomplete').unlink()
        except BaseException:
            with contextlib.suppress(Exception): database('STOP SLAVE;')
            raise
        print('Read-only SQL replica initialized. Verify live replication and restore drills before relying on it.')


def parse_status(text):
    return {line.split(':', 1)[0].strip(): line.split(':', 1)[1].strip()
            for line in text.splitlines() if ':' in line and not line.startswith('*')}


def check_replica_status(row, max_lag):
    m.require(row.get('Slave_IO_Running') == 'Yes' and row.get('Slave_SQL_Running') == 'Yes', 'Replica IO/SQL thread is not running')
    m.require(row.get('Master_SSL_Allowed') == 'Yes' and row.get('Master_SSL_Verify_Server_Cert') == 'Yes', 'Replica transport lacks verified TLS')
    lag = row.get('Seconds_Behind_Master', '')
    m.require(lag.isdecimal() and int(lag) <= max_lag, 'Replica lag is unknown or above the limit')
    return int(lag)


def health(c):
    purpose = 'sslserver' if c['role'] == 'primary' else 'sslclient'
    m.run(['openssl', 'verify', '-purpose', purpose, '-CAfile', TLS_DIR / 'ca.pem', TLS_DIR / 'cert.pem'])
    m.run(['openssl', 'x509', '-in', TLS_DIR / 'cert.pem', '-noout', '-checkend', '1209600'])
    if c['role'] == 'primary':
        m.require(database('SELECT @@server_id;').strip() == str(c['server_id']), 'Primary server ID mismatch')
        m.require(database("SHOW VARIABLES LIKE 'have_ssl';").strip().endswith('\tYES') and
                  database('SELECT @@log_bin,@@require_secure_transport;').strip() == '1\t1', 'Primary needs TLS and binary logging')
        m.require(database('SELECT @@bind_address,@@binlog_format;').strip() == c['bind_address'] + '\tROW', 'Primary must bind only its private address and use row logging')
        database('INSERT INTO postfixadmin.eric_replication_heartbeat VALUES (1,UNIX_TIMESTAMP()) ON DUPLICATE KEY UPDATE updated_at=UNIX_TIMESTAMP();')
        result = {'healthy': True, 'role': 'primary', 'checked_at': time.time(), 'tls': True, 'binary_logging': True}
    else:
        m.require(database('SELECT @@server_id,@@read_only,@@skip_networking;').strip() == str(c['server_id']) + '\t1\t1',
                  'Replica must have the configured identity, be read-only and have no TCP listener')
        # --vertical overrides --batch formatting and never includes the saved master password.
        row = parse_status(m.run(['mariadb', '--protocol=socket', '--socket=/var/lib/mysql/mysql.sock', '--vertical'], data='SHOW SLAVE STATUS;\n'))
        lag = check_replica_status(row, c['max_lag_seconds'])
        m.require(row.get('Master_Host') == c['primary_hostname'] and row.get('Master_User') == c['replication_user']
                  and row.get('Master_Server_Id') == str(c['peer_server_id']), 'Replica is connected to the wrong primary/account')
        age = database('SELECT UNIX_TIMESTAMP()-updated_at FROM postfixadmin.eric_replication_heartbeat WHERE id=1;').strip()
        m.require(re.fullmatch(r'-?[0-9]+', age) and -30 <= int(age) <= c['max_lag_seconds'], 'Replication heartbeat is stale or clocks are unsynchronized')
        result = {'healthy': True, 'heartbeat_age_seconds': int(age), 'role': 'replica', 'checked_at': time.time(), 'lag_seconds': lag, 'tls': True, 'read_only': True}
    m.atomic(m.STATE / 'replication-health.json', json.dumps(result) + '\n')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['primary', 'replica', 'export', 'health', 'resume', 'alert'])
    parser.add_argument('--config', default=str(CONFIG))
    parser.add_argument('--bundle')
    parser.add_argument('--output')
    args = parser.parse_args()
    try:
        m.root_only(); c = config(args.config)
        if args.command == 'primary': primary(c)
        elif args.command == 'replica':
            m.require(args.bundle, '--bundle required'); replica(c, args.bundle)
        elif args.command == 'export':
            m.require(args.output, '--output required'); export(c, args.output)
        elif args.command == 'health': health(c)
        elif args.command == 'resume':
            with m.lock():
                m.require(c['role'] == 'replica' and (m.STATE / 'sql-replica.json').exists()
                          and not (m.STATE / 'replication-incomplete').exists(), 'Only a completed replica may resume')
                database('START SLAVE;')
        else:
            m.run(c['alert_command'] + ['sql-replication-failure', str(m.STATE / 'replication-health.json')])
    except (m.MailError, OSError, ValueError, KeyError, TypeError) as exc:
        if args.command == 'health':
            with contextlib.suppress(Exception):
                m.atomic(m.STATE / 'replication-health.json', json.dumps({'healthy': False, 'checked_at': time.time()}) + '\n')
        print('ERROR: ' + (str(exc) if isinstance(exc, m.MailError) else type(exc).__name__ + '; inspect private replication inputs'), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__': main()
