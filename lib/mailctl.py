#!/usr/bin/env python3
"""Eric Mail: offline rendering and fail-closed, dedicated-host provisioning.

No shell interpolation, remote code execution, or implicit publication. Configuration
and credentials never appear in command-line arguments passed to database tools.
"""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import smtplib
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
STATE = Path('/var/lib/eric-mail')
ETC = Path('/etc/eric-mail')
REPLICATION_RECOVERY = (Path('/etc/my.cnf.d/zz-eric-mail-replication.cnf'),
                        Path('/var/lib/mysql/eric-mail-tls'))
SERVICES = ('nginx', 'postfix', 'dovecot', 'php-fpm')
PACKAGES = ('postfix', 'postfix-mysql', 'dovecot', 'dovecot-mysql', 'mariadb-server',
            'nginx', 'php-cli', 'php-fpm', 'php-mysqlnd', 'php-mbstring', 'php-xml',
            'php-intl', 'php-gd', 'php-opcache', 'php-process', 'php-sodium',
            'rspamd', 'redis', 'fail2ban', 'fail2ban-firewalld', 'firewalld',
            'restic', 'rsync', 'certbot', 'policycoreutils-python-utils', 'rsyslog', 'openssl')
FIELDS = {'hostname', 'admin_hostname', 'domains', 'management_networks', 'interface',
          'admin_client_ca', 'admin_client_crl', 'certificate', 'private_key', 'roundcube_archive',
          'roundcube_sha256', 'roundcube_version', 'postfixadmin_archive',
          'postfixadmin_sha256', 'postfixadmin_version', 'backup_environment',
          'alert_command', 'dkim_selector', 'mailbox_quota_mb', 'outbound_per_minute',
          'outbound_burst', 'queue_max_age_seconds', 'queue_max_messages', 'operator'}


class MailError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise MailError(message)


def run(argv, *, data=None, capture=True, env=None):
    """Never include stdout/stderr (which may contain secrets) in error messages."""
    result = subprocess.run([str(x) for x in argv], input=data, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None, env=env, check=False)
    if result.returncode:
        raise MailError(f'{Path(str(argv[0])).name} failed (exit {result.returncode}); '
                        'inspect restricted service logs')
    return result.stdout or ''


def read_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def domain(value):
    require(isinstance(value, str) and len(value) <= 253 and value == value.lower()
            and '.' in value and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
                                    for x in value.split('.')), 'Invalid lowercase DNS name')
    return value


def path_value(value):
    require(isinstance(value, str) and re.fullmatch(r'/[A-Za-z0-9_./-]+', value)
            and '..' not in Path(value).parts, 'Unsafe absolute path')
    return value


def version(value):
    require(isinstance(value, str) and re.fullmatch(r'\d+\.\d+\.\d+', value), 'Invalid version')
    return tuple(int(x) for x in value.split('.'))


def configuration(path):
    c = read_json(path)
    require(isinstance(c, dict) and set(c) == FIELDS, 'Configuration fields do not match site.example.json')
    for key in FIELDS - {'domains', 'management_networks', 'alert_command', 'mailbox_quota_mb',
                         'outbound_per_minute', 'outbound_burst', 'queue_max_age_seconds', 'queue_max_messages'}:
        require(isinstance(c[key], str), 'Configuration string fields must contain strings')
    domain(c['hostname']); domain(c['admin_hostname'])
    require(c['hostname'] != c['admin_hostname'], 'Admin and mail hostnames must differ')
    require(isinstance(c['domains'], list) and c['domains'] and len(c['domains']) <= 100,
            'Provide 1–100 hosted domains')
    for d in c['domains']:
        domain(d)
    require(len(set(c['domains'])) == len(c['domains']), 'Duplicate hosted domains')
    require(isinstance(c['management_networks'], list) and c['management_networks'], 'Management CIDRs required')
    for network in c['management_networks']:
        net = ipaddress.ip_network(network, strict=True)
        require(net.prefixlen >= (24 if net.version == 4 else 64) and not net.is_multicast
                and not net.is_unspecified, 'Management networks must be narrow canonical CIDRs')
    require(re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', c['interface']) is not None, 'Invalid interface')
    for key in ('admin_client_ca', 'admin_client_crl', 'certificate', 'private_key', 'roundcube_archive',
                'postfixadmin_archive', 'backup_environment'):
        path_value(c[key])
    for app in ('roundcube', 'postfixadmin'):
        require(re.fullmatch('[a-f0-9]{64}', c[app + '_sha256']) is not None,
                f'{app}: independently verified SHA-256 required')
    rv = version(c['roundcube_version'])
    require((rv[:2] == (1, 6) and rv >= (1, 6, 20)) or
            (rv[:2] == (1, 7) and rv >= (1, 7, 5)), 'Roundcube version below reviewed security floor')
    require(version(c['postfixadmin_version']) >= (4, 0, 5), 'PostfixAdmin version below reviewed floor')
    require(re.fullmatch('[a-z][a-z0-9]{0,30}', c['dkim_selector']) is not None, 'Invalid DKIM selector')
    for name, low, high in [('mailbox_quota_mb', 1, 1048576), ('outbound_per_minute', 1, 1000),
                            ('outbound_burst', 1, 10000), ('queue_max_age_seconds', 60, 259200),
                            ('queue_max_messages', 1, 100000)]:
        require(type(c[name]) is int and low <= c[name] <= high, f'Invalid {name}')
    require(isinstance(c['operator'], str) and 3 <= len(c['operator']) <= 200
            and not c['operator'].startswith('REPLACE') and '\n' not in c['operator'], 'Set responsible operator')
    require(all(isinstance(x, str) for x in c['management_networks']), 'CIDRs must be strings')
    cmd = c['alert_command']
    require(isinstance(cmd, list) and cmd and all(isinstance(x, str) and '\x00' not in x for x in cmd),
            'alert_command must be an argv array')
    path_value(cmd[0])
    return c


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def fingerprint(c):
    return hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()


def atomic(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not path.is_symlink(), f'Refusing symlink destination: {path}')
    payload = content.encode() if isinstance(content, str) else content
    if path.is_file() and path.read_bytes() == payload:
        os.chmod(path, mode)
        return False
    fd, tmp = tempfile.mkstemp(prefix='.mail-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode)
            f.write(payload); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return True


def private_file(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink(), 'A private regular file is required')
    st = p.stat()
    require(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) & 0o077 == 0,
            'Private input must be owned by the invoking user and mode 0600 or stricter')


def init_secrets(path):
    p = Path(path)
    if p.exists():
        private_file(p)
        return secrets_file(p)
    s = {name: secrets.token_hex(32) for name in ('mail_admin', 'mail_lookup', 'mail_auth', 'roundcube')}
    s['des_key'] = secrets.token_hex(12)  # exactly 24 ASCII bytes for Roundcube default cipher
    secret = secrets.token_urlsafe(48)
    s['setup_hash'] = run(['php', '-r', 'echo password_hash(stream_get_contents(STDIN), PASSWORD_DEFAULT);'], data=secret)
    # Only the hash is persisted. Web setup is denied and is never used for provisioning.
    atomic(p, json.dumps(s, sort_keys=True) + '\n')
    return s


def secrets_file(path):
    private_file(path)
    s = read_json(path)
    require(isinstance(s, dict) and set(s) == {'mail_admin', 'mail_lookup', 'mail_auth', 'roundcube', 'des_key', 'setup_hash'},
            'Invalid secrets schema')
    for name in ('mail_admin', 'mail_lookup', 'mail_auth', 'roundcube'):
        require(isinstance(s[name], str) and re.fullmatch('[a-f0-9]{64}', s[name]) is not None,
                'Database secrets must be generated by init-secrets (safe for all config grammars)')
    require(len({s[n] for n in ('mail_admin', 'mail_lookup', 'mail_auth', 'roundcube')}) == 4,
            'Database identities must not share passwords')
    require(isinstance(s['des_key'], str) and len(s['des_key'].encode()) == 24, 'Invalid Roundcube key length')
    require(isinstance(s['setup_hash'], str) and re.fullmatch(r'\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}', s['setup_hash']) is not None,
            'Invalid setup password hash')
    return s


def render(c, s, output):
    """Offline render: no host changes, network calls, shell evaluation or secrets in stdout."""
    out = Path(output)
    require(not out.is_symlink(), 'Render output cannot be a symlink')
    tokens = {'HOSTNAME': c['hostname'], 'ADMIN_HOSTNAME': c['admin_hostname'],
              'DOMAIN': c['domains'][0], 'CERTIFICATE': c['certificate'], 'PRIVATE_KEY': c['private_key'],
              'ADMIN_CLIENT_CA': c['admin_client_ca'], 'ADMIN_CLIENT_CRL': c['admin_client_crl'],
              'ADMIN_ALLOW': '\n'.join('    allow ' + n + ';' for n in c['management_networks']),
              'AUTH_PASSWORD': s['mail_auth'], 'QUOTA_MB': str(c['mailbox_quota_mb']),
              'QUOTA_BYTES': str(c['mailbox_quota_mb'] * 1048576),
              'DKIM_SELECTOR': c['dkim_selector'], 'OUTBOUND_BURST': str(c['outbound_burst']),
              'OUTBOUND_RATE': str(c['outbound_per_minute']),
              'MANAGEMENT_NETWORKS': ' '.join(c['management_networks'])}
    entries = []

    def put(dest, content, mode=0o640, owner='root', group='root'):
        target = out / dest.lstrip('/')
        atomic(target, content, mode)
        entries.append({'path': dest, 'mode': mode, 'owner': owner, 'group': group,
                        'sha256': digest(target)})

    def template(source, dest, mode=0o640, owner='root', group='root', extra=None):
        text = (ROOT / 'templates' / source).read_text()
        values = dict(tokens, **(extra or {}))
        for key, value in values.items():
            text = text.replace('@@' + key + '@@', value)
        require(re.search(r'@@[A-Z_]+@@', text) is None, f'Unresolved token in {source}')
        put(dest, text, mode, owner, group)

    template('postfix-main.cf', '/etc/postfix/main.cf', 0o644)
    template('postfix-master.cf', '/etc/postfix/master.cf', 0o644)
    template('dovecot.conf', '/etc/dovecot/dovecot.conf', 0o644)
    template('dovecot-sql.conf', '/etc/dovecot/mail-sql.conf.ext', 0o600)
    template('nginx.conf', '/etc/nginx/nginx.conf', 0o644)
    maps = {
        'domains': "SELECT domain FROM domain WHERE domain='%s' AND active=1 AND backupmx=0",
        'mailboxes': "SELECT username FROM mailbox WHERE username='%s' AND active=1",
        'aliases': "SELECT goto FROM alias WHERE address='%s' AND active=1",
        'senders': "SELECT username FROM mailbox WHERE username='%s' AND active=1 AND smtp_active=1 "
                   "UNION SELECT m.username FROM alias a JOIN mailbox m ON a.goto=m.username "
                   "WHERE a.address='%s' AND a.active=1 AND m.active=1 AND m.smtp_active=1"
    }
    for name, query in maps.items():
        put('/etc/postfix/sql/' + name + '.cf',
            f'user = mail_lookup\npassword = {s["mail_lookup"]}\nhosts = unix:/var/lib/mysql/mysql.sock\n'
            f'dbname = postfixadmin\nquery = {query}\n', group='postfix')
    for pool in ('roundcube', 'postfixadmin'):
        template('php-pool.conf', '/etc/php-fpm.d/' + pool + '.conf', 0o644, extra={'POOL': pool})
    template('roundcube.php', '/opt/eric-mail/apps/roundcube/config/config.inc.php', group='roundcube')
    template('postfixadmin.php', '/opt/eric-mail/apps/postfixadmin/config.local.php', group='postfixadmin')
    put('/etc/eric-mail/roundcube.json', json.dumps({'hostname': c['hostname'], 'password': s['roundcube'],
                                                  'des_key': s['des_key']}) + '\n', group='roundcube')
    put('/etc/eric-mail/postfixadmin.json', json.dumps({'password': s['mail_admin'], 'setup_hash': s['setup_hash'],
         'admin_hostname': c['admin_hostname'], 'quota_mb': c['mailbox_quota_mb']}) + '\n', group='postfixadmin')
    template('rspamd-header.lua', '/etc/rspamd/submission-identity.lua', 0o644)
    put('/etc/rspamd/rspamd.local.lua', "dofile('/etc/rspamd/submission-identity.lua')\n", 0o644)
    template('rspamd-proxy.conf', '/etc/rspamd/local.d/worker-proxy.inc', 0o644)
    template('rspamd-ratelimit.conf', '/etc/rspamd/local.d/ratelimit.conf', 0o644)
    template('rspamd-dkim.conf', '/etc/rspamd/local.d/dkim_signing.conf', 0o644)
    put('/etc/rspamd/local.d/redis.conf', 'servers = "127.0.0.1:6379";\n', 0o644)
    put('/etc/rspamd/local.d/worker-controller.inc', 'bind_socket = "127.0.0.1:11334";\n', 0o644)
    put('/etc/rspamd/local.d/worker-normal.inc', 'bind_socket = "127.0.0.1:11333";\n', 0o644)
    put('/etc/rspamd/local.d/actions.conf', 'reject = 15;\nadd_header = 6;\ngreylist = 4;\n', 0o644)
    put('/etc/redis/redis.conf', 'bind 127.0.0.1 ::1\nprotected-mode yes\nport 6379\n'
        'daemonize no\nsupervised systemd\ndir /var/lib/redis\nappendonly yes\n'
        'maxmemory 256mb\nmaxmemory-policy noeviction\n', group='redis')
    put('/etc/my.cnf.d/eric-mail.cnf', '[mysqld]\nskip-networking\nsocket=/var/lib/mysql/mysql.sock\n'
        'local-infile=0\ncharacter-set-server=utf8mb4\n')
    template('fail2ban.conf', '/etc/fail2ban/jail.d/eric-mail.local', 0o644)
    # System journal + rsyslog owns rotation; PHP/Dovecot do not create unrotated private logs.
    put('/etc/systemd/journald.conf.d/eric-mail.conf', '[Journal]\nStorage=persistent\n'
        'SystemMaxUse=512M\nMaxRetentionSec=30day\n', 0o644)
    for service in ('nginx', 'php-fpm', 'dovecot', 'rspamd'):
        template('service.conf', '/etc/systemd/system/' + service + '.service.d/eric-mail.conf', 0o644)
    for name in ('monitor', 'backup'):
        template(name + '.service', '/etc/systemd/system/eric-mail-' + name + '.service', 0o644)
        template(name + '.timer', '/etc/systemd/system/eric-mail-' + name + '.timer', 0o644)
    template('alert.service', '/etc/systemd/system/eric-mail-alert@.service', 0o644)
    for ext in ('service', 'timer'):
        template('debug-expire.' + ext, '/etc/systemd/system/eric-mail-debug-expire.' + ext, 0o644)
    template('renew-hook.sh', '/etc/letsencrypt/renewal-hooks/deploy/eric-mail.sh', 0o700)
    put('/etc/eric-mail/site.json', json.dumps(c, sort_keys=True, indent=2) + '\n', 0o600)
    atomic(out / 'manifest.json', json.dumps(entries, sort_keys=True, indent=2) + '\n')
    return entries


def root_only():
    require(os.geteuid() == 0, 'This operation requires root on the dedicated target host')


@contextlib.contextmanager
def lock():
    root_only()
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(STATE / 'operation.lock', 'a') as f:
        os.chmod(f.name, 0o600)
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MailError('Another mail operation is running')
        yield


def host_check():
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'rocky' and
            release.get('VERSION_ID', '').strip('"').split('.')[0] == '9', 'Only Rocky Linux 9 is supported')
    require(run(['getenforce']).strip() == 'Enforcing', 'SELinux must be enforcing')
    require(re.search(r'^SELINUX=enforcing$', Path('/etc/selinux/config').read_text(), re.M) is not None,
            'SELinux must remain enforcing after reboot')
    require(Path('/run/systemd/system').is_dir(), 'A full systemd host is required')


def certificate_check(c):
    for p in (c['certificate'], c['private_key'], c['admin_client_ca'], c['admin_client_crl']):
        require(Path(p).is_file(), 'Provision certificate, private key and admin client CA before deployment')
        st = Path(p).stat()
        require(st.st_uid == 0 and not st.st_mode & 0o022, 'Certificate files must be root-owned and not writable by others')
    require(not Path(c['private_key']).stat().st_mode & 0o077, 'TLS private key must be root-only')
    verify_server_certificate(c)
    run(['openssl', 'crl', '-in', c['admin_client_crl'], '-noout', '-verify', '-CAfile', c['admin_client_ca']])
    expiry = run(['openssl', 'crl', '-in', c['admin_client_crl'], '-noout', '-nextupdate']).strip().split('=', 1)[-1]
    expires_at = dt.datetime.strptime(expiry, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt.timezone.utc).timestamp()
    require(expires_at > time.time() + 86400, 'Admin client CRL must remain valid for at least one day')



def verify_server_certificate(c, ca_bundle='/etc/pki/tls/certs/ca-bundle.crt'):
    # x509 -checkhost may print a mismatch but return success. verify_hostname
    # participates in chain validation and fails the command on wrong identities.
    for name in (c['hostname'], c['admin_hostname']):
        run(['openssl', 'verify', '-purpose', 'sslserver', '-CAfile', ca_bundle,
             '-untrusted', c['certificate'], '-verify_hostname', name, c['certificate']])
    run(['openssl', 'x509', '-in', c['certificate'], '-noout', '-checkend', '1209600'])
    pub_cert = run(['openssl', 'x509', '-in', c['certificate'], '-pubkey', '-noout'])
    pub_key = run(['openssl', 'pkey', '-in', c['private_key'], '-pubout'])
    require(pub_cert == pub_key, 'Certificate and private key do not match')


def certificate_fingerprint(path):
    content = Path(path).read_text()
    match = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', content, re.S)
    require(match is not None, 'No leaf certificate found in fullchain')
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(match[0])).hexdigest()


def renew_certificate(c):
    # The same lock protects backup consistency: no writer restarts during a snapshot.
    with lock():
        require(not (STATE / 'deployment-incomplete').exists(), 'Deployment is incomplete')
        require(read_json(STATE / 'installed.json')['fingerprint'] == fingerprint(c), 'Renewal config differs from installed state')
        validate(c)
        for service in ('nginx', 'postfix', 'dovecot'):
            require(subprocess.run(['systemctl', 'is-active', '--quiet', service]).returncode == 0,
                    'Renewal refuses to start a deliberately stopped service')
        run(['systemctl', 'reload', 'nginx'])
        # Existing issues #12/#16/#18 require fresh mail processes after renewal.
        run(['systemctl', 'restart', 'postfix', 'dovecot'])
        health(c)

def archive_check(path, expected):
    require(Path(path).is_file() and digest(path) == expected, 'Application archive SHA-256 mismatch')
    with tarfile.open(path, 'r:gz') as tf:
        members = tf.getmembers()
        require(members and len(members) < 100000, 'Invalid archive member count')
        total = 0
        roots = set()
        for m in members:
            parts = Path(m.name).parts
            require(parts and not m.name.startswith('/') and '..' not in parts and
                    (m.isfile() or m.isdir()), 'Archive contains traversal, link or special file')
            require(not (m.mode & 0o6000), 'Archive contains privileged file modes')
            roots.add(parts[0]); total += m.size
        require(len(roots) == 1 and total < 1024 ** 3, 'Archive must have one top-level directory and be under 1 GiB')
    return next(iter(roots))


def install_app(c, app):
    base = Path('/opt/eric-mail/apps')
    base.mkdir(parents=True, exist_ok=True, mode=0o755)
    target = base / app
    archive = c[app + '_archive']; expected = c[app + '_sha256']
    top = archive_check(archive, expected)
    marker = target / '.eric-mail-sha256'
    if marker.is_file() and marker.read_text().strip() == expected:
        return
    require(not target.exists(), 'Application changes require the upgrade workflow')
    with tempfile.TemporaryDirectory(dir=base, prefix='.stage-') as td:
        with tarfile.open(archive, 'r:gz') as tf:
            # Members were exhaustively checked; extract as current root user, ignore archive ownership.
            for m in tf.getmembers():
                m.uid = m.gid = 0; m.uname = m.gname = ''
            tf.extractall(td, members=tf.getmembers(), numeric_owner=True)
        staged = Path(td) / top
        require((staged / 'vendor/autoload.php').is_file(), 'A complete release archive with dependencies is required')
        if app == 'roundcube':
            require((staged / 'SQL/mysql.initial.sql').is_file(), 'Missing Roundcube schema')
            require(c['roundcube_version'] in (staged / 'program/include/iniset.php').read_text(), 'Roundcube archive version mismatch')
        else:
            require((staged / 'public/upgrade.php').is_file(), 'Missing PostfixAdmin migration entry point')
            require(c['postfixadmin_version'] in (staged / 'config.inc.php').read_text(), 'PostfixAdmin archive version mismatch')
        for p in staged.rglob('*'):
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.chmod(staged, 0o755)
        atomic(staged / '.eric-mail-sha256', expected + '\n', 0o644)
        os.replace(staged, target)
    if app == 'roundcube':
        shutil.rmtree(target / 'installer', ignore_errors=True)


def account(name, uid=None):
    import pwd
    try:
        item = pwd.getpwnam(name)
        if uid is not None:
            require(item.pw_uid == uid, 'Existing vmail UID does not match')
    except KeyError:
        cmd = ['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/sbin/nologin']
        if uid is not None:
            cmd.extend(['--uid', str(uid)])
        run(cmd + [name])


def directory(path, mode=0o750, owner='root', group='root'):
    p = Path(path); p.mkdir(parents=True, exist_ok=True)
    require(not p.is_symlink(), 'Refusing directory symlink')
    os.chmod(p, mode); shutil.chown(p, user=owner, group=group)


def firewall(c, public=False):
    # A dedicated interface zone; management SSH remains possible while public services are gated.
    zones = run(['firewall-cmd', '--permanent', '--get-zones']).split()
    if 'eric-mail' not in zones:
        run(['firewall-cmd', '--permanent', '--new-zone=eric-mail'])
    base = ['firewall-cmd', '--permanent', '--zone=eric-mail']
    run(base + ['--set-target=DROP'])
    run(base + ['--change-interface=' + c['interface']])
    for old in run(base + ['--list-rich-rules']).splitlines():
        run(base + ['--remove-rich-rule=' + old])
    for net in c['management_networks']:
        family = 'ipv6' if ':' in net else 'ipv4'
        rule = f'rule family="{family}" source address="{net}" service name="ssh" accept'
        run(base + ['--add-rich-rule=' + rule])
        for port in (25, 80, 443, 587, 993):
            rule = f'rule family="{family}" source address="{net}" port port="{port}" protocol="tcp" accept'
            run(base + ['--add-rich-rule=' + rule])
    for port in (25, 80, 443, 587, 993):
        present = f'{port}/tcp' in run(base + ['--list-ports']).split()
        if public and not present:
            run(base + [f'--add-port={port}/tcp'])
        elif not public and present:
            run(base + [f'--remove-port={port}/tcp'])
    run(['firewall-cmd', '--reload'])
    if not public:
        (STATE / 'published.json').unlink(missing_ok=True)


def validate(c):
    certificate_check(c)
    postfix_version = run(['postconf', '-h', 'mail_version']).strip().split('-')[0]
    require(version(postfix_version) >= (3, 5, 0), 'Postfix must be 3.5 or newer with vendor security maintenance')
    require(run(['dovecot', '--version']).startswith('2.3.'), 'Only Dovecot 2.3 configuration is supported')
    # Conservative upstream floor: reject vendor builds below it unless policy/code is reviewed.
    pv = run(['php', '-r', 'echo PHP_VERSION;']).strip().split('-')[0]
    floors = {(8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
    vv = version(pv)
    require(vv[:2] in floors and vv >= floors[vv[:2]], 'PHP runtime is below the reviewed security floor')
    for p in ['/opt/eric-mail/apps/postfixadmin/config.local.php', '/opt/eric-mail/apps/roundcube/config/config.inc.php']:
        run(['php', '-l', p])
    for cmd in (['nginx', '-t'], ['php-fpm', '-t'], ['doveconf', '-n'], ['postfix', 'check'], ['rspamadm', 'configtest'], ['fail2ban-client', '-t']):
        run(cmd)
    require(run(['postconf', '-h', 'mynetworks']).strip() == '127.0.0.0/8, [::1]/128', 'Unexpected relay trust')
    dc = run(['doveconf', '-n'])
    require('auth_debug_passwords = yes' not in dc and 'auth_verbose_passwords = yes' not in dc, 'Secret logging is enabled')


def runtime_install():
    # Retain the exact reviewed source bundle used for provisioning; no mutable updater.
    h = hashlib.sha256()
    paths = [ROOT / 'install.sh'] + sorted((ROOT / 'lib').glob('*.py')) + sorted((ROOT / 'templates').glob('*'))
    for p in paths:
        h.update(str(p.relative_to(ROOT)).encode()); h.update(p.read_bytes())
    release = Path('/opt/eric-mail/releases') / h.hexdigest()
    for p in paths:
        dest = release / p.relative_to(ROOT)
        atomic(dest, p.read_bytes(), 0o700 if p.name in ('install.sh', 'replication.py') else 0o600)
    for parent in (release, release.parent):
        os.chmod(parent, 0o700)
    current = Path('/opt/eric-mail/current')
    tmp = current.with_name('.current-' + secrets.token_hex(8))
    tmp.symlink_to(release)
    os.replace(tmp, current)
    return h.hexdigest()


def deploy(c, source_config, already_locked=False):
    with (contextlib.nullcontext() if already_locked else lock()):
        host_check()
        require(not (STATE / 'sql-replica.json').exists(), 'A minimal SQL replica cannot be converted to a mail host by deploy')
        marker = STATE / 'installed.json'
        previous = read_json(marker) if marker.exists() else None
        if previous:
            require(previous['fingerprint'] == fingerprint(c),
                    'Configuration changes require upgrade; normal deploy only reruns identical desired state')
        else:
            require(not Path('/var/vmail').exists() and not Path('/opt/eric-mail/apps').exists(),
                    'Existing mail storage/application found: use the documented migration plan')
            require(not run(['systemctl', 'list-units', '--state=active', '--no-legend',
                             'postfix.service', 'dovecot.service', 'nginx.service', 'php-fpm.service']).strip(),
                    'Fresh-host provisioning refuses existing active mail/web services')
        # Validate all offline requirements before changing the target.
        certificate_check(c)
        for app in ('roundcube', 'postfixadmin'):
            archive_check(c[app + '_archive'], c[app + '_sha256'])
        private_file(c['backup_environment'])
        load_backup_environment(c['backup_environment'])
        private_file(c['alert_command'][0])
        require(os.access(c['alert_command'][0], os.X_OK), 'Alert command must be executable')
        require(c['operator'] and not any('.example.' in h or h.endswith('.example.com') for h in (c['hostname'], c['admin_hostname'])), 'Replace example hostnames')
        run(['ip', 'link', 'show', 'dev', c['interface']])
        # DNF enforces signatures even if an operator misconfigured an enabled repository.
        run(['dnf', '-y', '--setopt=gpgcheck=1', '--setopt=*.gpgcheck=1', '--setopt=localpkg_gpgcheck=1', 'install', 'firewalld'])
        run(['systemctl', 'enable', '--now', 'firewalld'])
        firewall(c, False)
        atomic(STATE / 'deployment-incomplete', 'Deployment in progress; publication denied\n')
        try:
            run(['systemctl', 'mask', *SERVICES])
            subprocess.run(['systemctl', 'stop', *SERVICES], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            run(['dnf', '-y', '--setopt=gpgcheck=1', '--setopt=*.gpgcheck=1', '--setopt=localpkg_gpgcheck=1', 'module', 'enable', 'php:8.3'])
            run(['dnf', '-y', '--setopt=gpgcheck=1', '--setopt=*.gpgcheck=1', '--setopt=localpkg_gpgcheck=1', 'upgrade', '--security'])
            run(['dnf', '-y', '--setopt=gpgcheck=1', '--setopt=*.gpgcheck=1', '--setopt=localpkg_gpgcheck=1', 'install', *PACKAGES])
            account('vmail', 2000); account('roundcube'); account('postfixadmin')
            directory('/opt/eric-mail', 0o755)
            directory(ETC, 0o755)
            directory('/var/vmail', 0o700, 'vmail', 'vmail')
            directory('/etc/postfix/sql', 0o750, 'root', 'postfix')
            directory('/var/lib/rspamd/dkim', 0o750, 'root', '_rspamd')
            for pool in ('roundcube', 'postfixadmin'):
                for sub in ('', '/sessions', '/temp'):
                    directory('/var/lib/' + pool + sub, 0o700, pool, pool)
                install_app(c, pool)
            # PFA expects its template cache at templates_c; isolate this one writable directory.
            directory('/opt/eric-mail/apps/postfixadmin/templates_c', 0o700, 'postfixadmin', 'postfixadmin')
            s = init_secrets(ETC / 'secrets.json')
            release = runtime_install()
            with tempfile.TemporaryDirectory(prefix='mail-render-', dir=STATE) as td:
                entries = render(c, s, td)
                for entry in entries:
                    p = Path(entry['path'])
                    if p.exists() and not previous:
                        backup = STATE / 'preinstall' / p.relative_to('/')
                        atomic(backup, p.read_bytes())
                    atomic(p, (Path(td) / p.relative_to('/')).read_bytes(), entry['mode'])
                    shutil.chown(p, user=entry['owner'], group=entry['group'])
                atomic(STATE / 'configuration-manifest.json', json.dumps(entries, indent=2) + '\n')
            default_pool = Path('/etc/php-fpm.d/www.conf')
            if default_pool.exists():
                default_pool.rename('/etc/php-fpm.d/www.conf.disabled')
            # Persist SELinux contexts rather than weakening enforcement.
            contexts = [('/var/vmail(/.*)?', 'mail_spool_t'),
                        ('/opt/eric-mail/apps(/.*)?', 'httpd_sys_content_t'),
                        ('/opt/eric-mail/apps/postfixadmin/templates_c(/.*)?', 'httpd_sys_rw_content_t'),
                        ('/var/lib/roundcube(/.*)?', 'httpd_sys_rw_content_t'),
                        ('/var/lib/postfixadmin(/.*)?', 'httpd_sys_rw_content_t'),
                        ('/etc/eric-mail/(roundcube|postfixadmin)\\.json', 'httpd_sys_content_t')]
            known = run(['semanage', 'fcontext', '-l', '-C'])
            for pattern, typ in contexts:
                action = '-m' if pattern in known else '-a'
                run(['semanage', 'fcontext', action, '-t', typ, pattern])
            run(['restorecon', '-RF', '/var/vmail', '/opt/eric-mail/apps', '/var/lib/roundcube', '/var/lib/postfixadmin', str(ETC)])
            run(['setsebool', '-P', 'httpd_can_network_connect_db', 'on', 'httpd_can_network_connect', 'on'])
            run(['systemctl', 'enable', '--now', 'mariadb', 'redis', 'rsyslog'])
            run(['systemctl', 'restart', 'mariadb', 'redis', 'systemd-journald'])
            run(['php', str(ROOT / 'templates/db-provision.php')], data=json.dumps(s))
            run(['php', str(ROOT / 'templates/migrate-postfixadmin.php')])
            run(['php', '/opt/eric-mail/apps/roundcube/bin/initdb.sh', '--dir=/opt/eric-mail/apps/roundcube/SQL', '--update'])
            run(['php', str(ROOT / 'templates/db-grants.php')])
            for d in c['domains']:
                add_domain(c, d)
            validate(c)
            run(['systemctl', 'daemon-reload'])
            run(['systemctl', 'unmask', *SERVICES])
            run(['systemctl', 'enable', '--now', 'rspamd', 'fail2ban', *SERVICES,
                 'eric-mail-monitor.timer', 'eric-mail-backup.timer'])
            run(['systemctl', 'restart', 'rspamd', 'fail2ban', *SERVICES])
            health(c, require_backup=False)
            inventory = run(['rpm', '-qa', '--qf', '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n'])
            atomic(STATE / 'packages.txt', inventory)
            backup(c, already_locked=True)
            atomic(marker, json.dumps({'fingerprint': fingerprint(c), 'release': release, 'installed_at': time.time()}) + '\n')
            (STATE / 'deployment-incomplete').unlink()
            print('Provisioned behind a closed public firewall. Complete staging acceptance and activate with evidence.')
        except BaseException:
            # No automatic database/file rollback: preserve closed ingress and diagnostics for consistent recovery.
            with contextlib.suppress(Exception):
                firewall(c, False)
                run(['systemctl', 'stop', *SERVICES])
            raise


def add_domain(c, value):
    domain(value)
    run(['php', str(ROOT / 'templates/add-domain.php')], data=json.dumps({'domain': value, 'quota_mb': c['mailbox_quota_mb']}))
    key = Path('/var/lib/rspamd/dkim') / (value + '.' + c['dkim_selector'] + '.key')
    if not key.exists():
        atomic(key, run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048']), 0o640)
        shutil.chown(key, user='root', group='_rspamd')
    public = run(['openssl', 'pkey', '-in', key, '-pubout', '-outform', 'PEM'])
    body = ''.join(line for line in public.splitlines() if not line.startswith('---'))
    atomic(STATE / 'dns' / (value + '.txt'),
           f'{c["dkim_selector"]}._domainkey.{value} TXT "v=DKIM1; k=rsa; p={body}"\n', 0o600)


def load_backup_environment(path):
    private_file(path)
    data = {}
    for line in Path(path).read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        require('=' in line, 'Backup environment must use literal KEY=value lines')
        key, value = line.split('=', 1)
        require(re.fullmatch('[A-Z][A-Z0-9_]+', key) is not None and key not in data,
                'Invalid/duplicate backup environment key')
        require(key in {'RESTIC_REPOSITORY', 'RESTIC_PASSWORD_FILE', 'RESTIC_CACERT', 'RESTIC_REST_USERNAME', 'RESTIC_REST_PASSWORD'} or key.startswith(('AWS_', 'B2_', 'AZURE_', 'GOOGLE_', 'OS_')),
                'Unsupported backup environment key')
        data[key] = value  # never source/eval; values are literal including spaces and quotes
    require(data.get('RESTIC_PASSWORD_FILE') and data.get('RESTIC_REPOSITORY'), 'Restic repository and password file required')
    private_file(path_value(data['RESTIC_PASSWORD_FILE']))
    repo = data['RESTIC_REPOSITORY']
    require(repo.startswith(('s3:https://', 'b2:', 'azure:', 'gs:', 'rest:https://')),
            'Use an encrypted offsite repository with an approved remote backend')
    return dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/root', LANG='C.UTF-8', **data)


def backup(c, already_locked=False):
    manager = contextlib.nullcontext() if already_locked else lock()
    with manager:
        env = load_backup_environment(c['backup_environment'])
        run(['restic', 'cat', 'config'], env=env)  # repository must be initialized deliberately
        # Stop writers for a consistent mailbox + database snapshot, then resume on ALL exit paths.
        active = [s for s in ('redis', 'rspamd', *SERVICES) if subprocess.run(['systemctl', 'is-active', '--quiet', s]).returncode == 0]
        resources = contextlib.ExitStack()
        mail_source = '/var/vmail'
        atomic(STATE / 'backup-active.json', json.dumps({'services': active, 'started_at': time.time()}) + '\n')
        try:
            run(['systemctl', 'stop', *active]) if active else None
            directory(STATE / 'backup-stage', 0o700)
            dump_path = STATE / 'backup-stage/databases.sql'
            with open(dump_path, 'w') as output:
                result = subprocess.run(['mariadb-dump', '--protocol=socket', '--socket=/var/lib/mysql/mysql.sock',
                                         '--single-transaction', '--routines', '--events', '--databases',
                                         'postfixadmin', 'roundcubemail'], stdout=output, stderr=subprocess.PIPE, check=False)
            require(result.returncode == 0, 'Database dump failed')
            run(['rsync', '-a', '--delete', '--exclude=/private/', '--exclude=/public/', '--exclude=/pid/',
                 '/var/spool/postfix/', str(STATE / 'backup-stage/postfix-spool') + '/'])
            profile = ETC / 'snapshot.json'
            if profile.exists():
                from mail_snapshot import policy, mailbox_snapshot
                mail_source = resources.enter_context(mailbox_snapshot(policy(profile)))
                if active: run(['systemctl', 'start', *active])
            atomic(STATE / 'backup-stage/installation.json', json.dumps({
                'fingerprint': fingerprint(c), 'release': Path('/opt/eric-mail/current').resolve().name,
                'configuration_manifest': read_json(STATE / 'configuration-manifest.json'),
                'created_at': time.time(), 'mail_source': mail_source, 'mail_target': '/var/vmail',
                'queue_source': str(STATE / 'backup-stage/postfix-spool')}) + '\n')
            replication_recovery = [str(p) for p in (*REPLICATION_RECOVERY, STATE / 'replication-primary.json') if p.exists()]
            report = run(['restic', 'backup', '--json', '--tag', 'eric-mail', mail_source, '/var/lib/rspamd/dkim',
                 '/var/lib/redis', '/var/lib/roundcube', '/var/lib/postfixadmin', str(ETC),
                 '/etc/postfix', '/etc/dovecot', '/etc/nginx', '/etc/php-fpm.d', '/etc/rspamd',
                 '/etc/letsencrypt', c['certificate'], c['private_key'], c['admin_client_ca'], c['admin_client_crl'],
                 '/opt/eric-mail', str(STATE / 'backup-stage'), str(STATE / 'packages.txt'), *replication_recovery,
                 '--exclude', c['backup_environment'], '--exclude', env['RESTIC_PASSWORD_FILE']], env=env)
            summary = [json.loads(line) for line in report.splitlines() if line.strip()]
            snapshot_ids = [x['snapshot_id'] for x in summary if x.get('message_type') == 'summary' and x.get('snapshot_id')]
            require(snapshot_ids and re.fullmatch('[a-f0-9]{8,64}', snapshot_ids[-1]) is not None, 'Backup did not produce a snapshot ID')
            run(['restic', 'check'], env=env)
            resources.close()  # COW validity and cleanup must pass before recording success.
            atomic(STATE / 'last-backup.json', json.dumps({'completed_at': time.time(), 'fingerprint': fingerprint(c), 'snapshot_id': snapshot_ids[-1]}) + '\n')
        finally:
            try:
                resources.close()
            finally:
                (STATE / 'backup-stage/databases.sql').unlink(missing_ok=True)
                resume_backup()


def resume_backup():
    state = STATE / 'backup-active.json'
    if state.exists():
        active = read_json(state)['services']
        require(isinstance(active, list) and set(active) <= {'redis', 'rspamd', *SERVICES}, 'Invalid backup recovery state')
        if active:
            run(['systemctl', 'start', *active])
        state.unlink()


def tls_probe(host, port):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def health(c, require_backup=True, allow_maintenance=False):
    maintenance = STATE / 'backup-active.json'
    if allow_maintenance and maintenance.exists() and 0 <= time.time() - read_json(maintenance)['started_at'] < 7200:
        return  # the backup unit has an independent timeout + OnFailure alert
    failures = []
    for s in ('mariadb', 'redis', 'rspamd', 'fail2ban', *SERVICES):
        if subprocess.run(['systemctl', 'is-active', '--quiet', s]).returncode:
            failures.append('service:' + s)
    for path in ('/var/vmail', '/var/spool/postfix', '/var/lib/mysql'):
        fs = os.statvfs(path)
        if fs.f_bavail * fs.f_frsize < 1024 ** 3 or (fs.f_files and fs.f_favail / fs.f_files < 0.1):
            failures.append('storage:' + path)
    try:
        certificate_check(c)
        expected = certificate_fingerprint(c['certificate'])
        require(tls_probe(c['hostname'], 993) == expected, 'IMAPS is serving a stale certificate')
        require(tls_probe(c['hostname'], 443) == expected, 'HTTPS is serving a stale certificate')
        with smtplib.SMTP(c['hostname'], 587, timeout=10) as smtp:
            smtp.ehlo()
            require('auth' not in smtp.esmtp_features, 'AUTH advertised before TLS')
            smtp.starttls(context=ssl.create_default_context()); smtp.ehlo()
            require('auth' in smtp.esmtp_features, 'Submission AUTH missing')
            require(hashlib.sha256(smtp.sock.getpeercert(binary_form=True)).hexdigest() == expected,
                    'Submission is serving a stale certificate')
        authlog = run(['journalctl', '--no-pager', '-n', '5000', '--since=-5min', '-u', 'postfix', '-u', 'dovecot'])
        if len(re.findall(r'authentication failed|auth failed|Login failed', authlog, re.I)) >= 100:
            failures.append('authentication-failure-spike')
        filterlog = run(['journalctl', '--no-pager', '-n', '5000', '--since=-5min', '-u', 'rspamd'])
        if len(re.findall(r'ratelimit.*(?:exceeded|limited)', filterlog, re.I)) >= 10:
            failures.append('outbound-abuse-spike')
        queue = run(['postqueue', '-j']).splitlines()
        messages = [json.loads(line) for line in queue if line]
        if len(messages) > c['queue_max_messages'] or any(time.time() - m['arrival_time'] > c['queue_max_age_seconds'] for m in messages):
            failures.append('mail-queue')
        if require_backup:
            state = read_json(STATE / 'last-backup.json')
            if time.time() - state['completed_at'] > 93600 or state['fingerprint'] != fingerprint(c):
                failures.append('backup-stale')
        validate(c)
    except (MailError, OSError, ValueError, smtplib.SMTPException):
        failures.append('protocol/configuration/backup')
    atomic(STATE / 'health.json', json.dumps({'checked_at': time.time(), 'failures': failures}) + '\n')
    require(not failures, 'Health check failed: ' + ', '.join(failures))


EVIDENCE = {'external_ipv4_relay_rejected', 'external_ipv6_relay_rejected', 'lan_relay_rejected',
            'inbound_delivery', 'submission_sender_ownership', 'imap_cleartext_rejected',
            'tls_policy', 'admin_mfa_and_mtls', 'protected_web_paths', 'dkim_spf_dmarc',
            'filter_outage_defers', 'rate_limits', 'certificate_renewal', 'restore_drill',
            'alert_delivery', 'reboot', 'selinux_enforcing', 'upgrade_rollback'}


def activate(c, evidence):
    with lock():
        require(not (STATE / 'deployment-incomplete').exists(), 'Deployment is incomplete')
        state = read_json(STATE / 'installed.json')
        require(state['fingerprint'] == fingerprint(c), 'Config differs from installed configuration')
        private_file(evidence)
        proof = read_json(evidence)
        require(proof.get('fingerprint') == fingerprint(c) and proof.get('operator') == c['operator'] and proof.get('release') == state['release'], 'Evidence must identify operator and installed configuration')
        require(set(proof.get('checks', {})) == EVIDENCE and all(v is True for v in proof['checks'].values()), 'All release acceptance checks must pass')
        require(0 <= time.time() - proof.get('completed_at', 0) < 7 * 86400, 'Acceptance evidence must be less than seven days old')
        health(c)
        # Evidence is an accountable operator attestation, never an automatic assertion of remote test success.
        atomic(STATE / 'release-evidence.json', json.dumps(proof, indent=2) + '\n')
        firewall(c, True)
        atomic(STATE / 'published.json', json.dumps({'published_at': time.time(), 'fingerprint': fingerprint(c)}) + '\n')
        print('Public ingress enabled. Monitor external delivery and authentication.')


def debug(enabled):
    with lock():
        path = Path('/etc/dovecot/dovecot.conf')
        text = path.read_text()
        require('Managed' in Path('/etc/postfix/main.cf').read_text(), 'Only managed installations are supported')
        # Secret settings are explicitly forced off, even if another operation changed them.
        for key, value in [('auth_debug_passwords', 'no'), ('auth_verbose_passwords', 'no'),
                           ('auth_debug', 'yes' if enabled else 'no')]:
            text = re.sub(r'^' + key + r'\s*=.*$', key + ' = ' + value, text, flags=re.M)
        atomic(path, text, 0o644)
        run(['doveconf', '-n']); run(['systemctl', 'reload', 'dovecot'])
        run(['systemctl', 'restart' if enabled else 'stop', 'eric-mail-debug-expire.timer'])


def restore(c, target, snapshot):
    with lock():
        p = Path(target)
        require(p.is_absolute() and not p.exists() and str(p).startswith('/var/lib/eric-mail/restore-'),
                'Restore must target a NEW /var/lib/eric-mail/restore-* directory, never the live filesystem')
        require(re.fullmatch('[a-f0-9]{8,64}', snapshot) is not None, 'Use an explicit restic snapshot ID')
        p.mkdir(mode=0o700)
        run(['restic', 'restore', snapshot, '--target', p, '--verify'], env=load_backup_environment(c['backup_environment']))
        print('Restored to an isolated directory. Follow docs/OPERATIONS.md to verify and recover.')



def create_identity(c, address, kind):
    with lock():
        require(isinstance(address, str) and address.count('@') == 1 and address == address.lower(),
                'Use a lowercase complete mailbox address')
        local, host = address.split('@')
        domain(host)
        require(re.fullmatch(r'[a-z0-9][a-z0-9._+-]{0,63}', local) is not None,
                'Unsafe local part; only simple ASCII mailbox names are supported')
        if kind == 'mailbox':
            require(host in c['domains'], 'Add the domain to desired configuration before creating a mailbox')
        pw = getpass.getpass('New password (minimum 16 characters): ')
        require(len(pw) >= 16 and len(pw.encode()) <= 72 and '\x00' not in pw,
                'Use a password of 16–72 UTF-8 bytes')
        require(pw == getpass.getpass('Confirm password: '), 'Passwords do not match')
        run(['php', str(ROOT / 'templates/mailbox.php')], data=json.dumps({
            'kind': kind, 'address': address, 'local': local, 'domain': host,
            'password': pw, 'quota': c['mailbox_quota_mb'] * 1048576}))
        print('Identity created. Administrators must enroll TOTP from the restricted admin site.')


def upgrade(c, previous):
    """Backup first; retain old code; failures stay private for coordinated restore.

    Database migrations cannot be safely reversed by swapping application files.
    The restore runbook intentionally requires a consistent database/mail restore.
    """
    with lock():
        host_check()
        installed = read_json(STATE / 'installed.json')
        require(installed['fingerprint'] == fingerprint(previous), 'Previous config does not match installed state')
        require(c['hostname'] == previous['hostname'] and c['admin_hostname'] == previous['admin_hostname']
                and c['interface'] == previous['interface'], 'Hostname/interface migrations need a separate migration plan')
        for app in ('roundcube', 'postfixadmin'):
            require(version(c[app + '_version']) >= version(previous[app + '_version']), 'Downgrades require consistent restore')
            archive_check(c[app + '_archive'], c[app + '_sha256'])
        certificate_check(c)
        backup(previous, already_locked=True)
        stamp = str(time.time_ns())
        rollback = STATE / 'upgrades' / stamp
        directory(rollback)
        atomic(rollback / 'site.json', json.dumps(previous, indent=2) + '\n')
        atomic(rollback / 'installed.json', json.dumps(installed) + '\n')
        # Capture the full verified configuration and a restic snapshot reference.
        atomic(rollback / 'restic-snapshots.json', run(['restic', 'snapshots', '--tag', 'eric-mail', '--json'],
               env=load_backup_environment(previous['backup_environment'])))
        firewall(previous, False)
        run(['systemctl', 'stop', *SERVICES])
        atomic(STATE / 'deployment-incomplete', 'Upgrade in progress; publication denied\n')
        try:
            for app in ('roundcube', 'postfixadmin'):
                if c[app + '_sha256'] != previous[app + '_sha256']:
                    (Path('/opt/eric-mail/apps') / app).rename(rollback / app)
                    install_app(c, app)
            # Allow the normal fail-closed deploy path to apply the new desired state.
            atomic(STATE / 'installed.json', json.dumps(dict(installed, fingerprint=fingerprint(c))) + '\n')
            deploy(c, None, already_locked=True)
        except BaseException:
            atomic(STATE / 'installed.json', json.dumps(installed) + '\n')
            with contextlib.suppress(Exception):
                firewall(previous, False)
                run(['systemctl', 'stop', *SERVICES])
            print('Upgrade failed; ingress remains restricted. Restore code/config AND databases together using docs/OPERATIONS.md.', file=sys.stderr)
            raise
        print('Upgrade complete in restricted mode. Re-run acceptance and activate; rollback material retained privately.')

def main():
    os.umask(0o077)
    def terminate(signum, frame):
        raise MailError('Operation interrupted; inspect restricted deployment/recovery state')
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init-secrets', 'render', 'deploy', 'validate', 'health',
                        'backup', 'resume-backup', 'restore', 'renew-certificate', 'activate', 'close', 'domain', 'mailbox', 'admin', 'upgrade', 'debug-on', 'debug-off', 'alert', 'fingerprint'])
    parser.add_argument('--config', default='/etc/eric-mail/site.json')
    parser.add_argument('--secrets', default='/etc/eric-mail/secrets.json')
    parser.add_argument('--output')
    parser.add_argument('--evidence')
    parser.add_argument('--domain')
    parser.add_argument('--address')
    parser.add_argument('--previous-config')
    parser.add_argument('--snapshot')
    parser.add_argument('--event', default='mail-health-failure')
    args = parser.parse_args()
    try:
        if args.command == 'init-secrets':
            require(args.output, '--output required'); init_secrets(args.output); return
        if args.command.startswith('debug-'):
            debug(args.command == 'debug-on'); return
        c = configuration(args.config)
        if args.command == 'fingerprint':
            print(fingerprint(c))
        elif args.command == 'render':
            require(args.output, '--output required')
            render(c, secrets_file(args.secrets), args.output)
            print('Configuration rendered; output contains secrets and must remain private.')
        else:
            root_only()
            if args.command == 'deploy': deploy(c, args.config)
            elif args.command == 'upgrade':
                require(args.previous_config, '--previous-config required'); upgrade(c, configuration(args.previous_config))
            elif args.command in ('mailbox', 'admin'):
                require(args.address, '--address required'); create_identity(c, args.address, args.command)
            elif args.command == 'validate': validate(c)
            elif args.command == 'renew-certificate': renew_certificate(c)
            elif args.command == 'health': health(c, allow_maintenance=True)
            elif args.command == 'backup': backup(c)
            elif args.command == 'resume-backup':
                with lock(): resume_backup()
            elif args.command == 'restore': restore(c, args.output or '', args.snapshot or '')
            elif args.command == 'activate':
                require(args.evidence, '--evidence required'); activate(c, args.evidence)
            elif args.command == 'close':
                with lock(): firewall(c, False)
            elif args.command == 'domain':
                require(args.domain, '--domain required')
                require(args.domain in c['domains'], 'Add the domain through a reviewed config upgrade first')
                with lock():
                    require(read_json(STATE / 'installed.json')['fingerprint'] == fingerprint(c), 'Domain config must match installed state')
                    add_domain(c, args.domain)
            elif args.command == 'alert':
                run(c['alert_command'] + [args.event, str(STATE / 'health.json')])
    except (MailError, OSError, ValueError, TypeError, KeyError, tarfile.TarError) as exc:
        # Do not echo inputs or exception text that may include secret-bearing data.
        print('ERROR: ' + (str(exc) if isinstance(exc, MailError) else type(exc).__name__ + '; inspect private inputs'), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
