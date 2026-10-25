"""Root-only ClamAV policy and native Postfix hold-queue administration."""
import argparse
import json
import re
import subprocess
import time
from pathlib import Path
import mailctl as m

ANTIVIRUS = '''clamav {
  type = "clamav";
  servers = "/run/clamd.eric-mail/clamd.sock";
  symbol = "CLAM_VIRUS";
  scan_mime_parts = false;
  action = "quarantine";
  timeout = 30s;
  retransmits = 1;
}
'''
FORCE = '''rules {
  SCANNER_UNAVAILABLE { action = "soft reject"; expression = "CLAM_VIRUS_FAIL"; }
  UNSCANNABLE { action = "quarantine"; expression = "CLAM_VIRUS_ENCRYPTED | CLAM_VIRUS_MACRO"; }
}
'''
CLAMD = '''LocalSocket /run/clamd.eric-mail/clamd.sock
LocalSocketGroup _rspamd
LocalSocketMode 660
FixStaleSocket yes
User clamscan
DatabaseDirectory /var/lib/clamav
ScanMail yes
ScanArchive yes
MaxFileSize 32M
MaxScanSize 100M
StreamMaxLength 32M
MaxRecursion 10
MaxFiles 1000
AlertExceedsMax yes
AlertEncrypted yes
AlertOLE2Macros yes
Foreground yes
'''

def audit(event, identifier):
    m.run(['logger', '-p', 'authpriv.notice', '-t', 'eric-mail', '--', event + ':' + identifier])

def enable():
    with m.lock():
        m.host_check()
        m.run(['dnf', '-y', '--setopt=gpgcheck=1', '--setopt=*.gpgcheck=1', '--setopt=localpkg_gpgcheck=1', 'install', 'clamav', 'clamav-update', 'clamd'])
        m.runtime_install()
        files = {
            '/etc/clamd.d/eric-mail.conf': CLAMD,
            '/etc/freshclam.conf': 'DatabaseDirectory /var/lib/clamav\nDatabaseOwner clamupdate\nDatabaseMirror database.clamav.net\n',
            '/etc/rspamd/local.d/antivirus.conf': ANTIVIRUS,
            '/etc/rspamd/override.d/actions.conf': 'reject = 15; add_header = 6; greylist = 4; quarantine { flags = ["no_threshold"]; }\n',
            '/etc/rspamd/local.d/force_actions.conf': FORCE,
            '/etc/systemd/system/eric-mail-signatures.service': '[Unit]\nDescription=Update malware signatures\nOnFailure=eric-mail-alert@%n.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/freshclam --quiet\n',
            '/etc/systemd/system/eric-mail-signatures.timer': '[Unit]\nDescription=Refresh malware signatures hourly\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n',
            '/etc/systemd/system/eric-mail-clamd.service': '[Unit]\nDescription=Eric Mail malware scanner\nAfter=network-online.target\nOnFailure=eric-mail-alert@%n.service\n[Service]\nType=simple\nExecStart=/usr/sbin/clamd --config-file=/etc/clamd.d/eric-mail.conf\nRuntimeDirectory=clamd.eric-mail\nRuntimeDirectoryMode=0750\nUser=clamscan\nGroup=_rspamd\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n',
        }
        Path('/etc/rspamd/override.d').mkdir(mode=0o755,parents=True,exist_ok=True)
        for path, text in files.items(): m.atomic(Path(path), text, 0o644)
        m.run(['restorecon', '-RF', '/etc/clamd.d', '/var/lib/clamav'])
        m.run(['rspamadm', 'configtest'])
        m.run(['systemctl', 'daemon-reload'])
        m.run(['systemctl', 'start', 'eric-mail-signatures.service'])
        m.run(['systemctl', 'enable', '--now', 'eric-mail-clamd.service', 'eric-mail-signatures.timer'])
        m.run(['systemctl', 'restart', 'rspamd'])
        health()
        m.atomic(m.STATE/'content-security.json', json.dumps({'enabled': True})+'\n')
        from security_ops import track
        track(files)
        audit('malware-policy-enabled', 'host')

def health():
    m.run(['systemctl', 'is-active', '--quiet', 'eric-mail-clamd.service', 'eric-mail-signatures.timer'])
    databases = list(Path('/var/lib/clamav').glob('daily.cl[vd]'))
    m.require(databases and max(p.stat().st_mtime for p in databases) > time.time()-172800,
              'Malware signatures missing or older than 48 hours')
    m.run(['clamdscan', '--config-file=/etc/clamd.d/eric-mail.conf', '--ping=3'])

def held():
    return {q['queue_id']: q for q in (json.loads(x) for x in m.run(['postqueue', '-j']).splitlines() if x)
            if q['queue_name'] == 'hold'}

def release(identifier, approved):
    m.require(approved and re.fullmatch(r'[A-Za-z0-9]{5,32}', identifier), 'Explicit approval and valid queue ID required')
    with m.lock():
        m.require(identifier in held(), 'Message is not on hold')
        health()
        # Never print message data or place it in an argv, log, or web-readable file.
        body = m.run(['postcat', '-bhq', identifier])
        m.run(['clamdscan', '--config-file=/etc/clamd.d/eric-mail.conf', '-'], data=body)
        scan = json.loads(m.run(['rspamc', '-j'], data=body))
        m.require(scan.get('action') in ('no action', 'add header', 'rewrite subject'), 'Content policy still blocks this message')
        m.require(identifier in held(), 'Queue state changed during review')
        audit('quarantine-release-approved', identifier)
        m.run(['postsuper', '-H', identifier])

def expire(days, approved):
    m.require(approved and 1 <= days <= 365, 'Explicit deletion approval and retention 1..365 days required')
    with m.lock():
        for identifier, item in held().items():
            m.require(re.fullmatch(r'[A-Za-z0-9]{5,32}', identifier), 'Invalid queue ID')
            if item['arrival_time'] < time.time()-days*86400:
                audit('quarantine-expire-approved', identifier)
                m.run(['postsuper', '-d', identifier])

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['enable','health','list','release','expire'])
    p.add_argument('--id');p.add_argument('--days',type=int,default=30);p.add_argument('--approve',action='store_true')
    a=p.parse_args();m.root_only()
    if a.command=='enable':enable()
    elif a.command=='health':health()
    elif a.command=='list':print(json.dumps(list(held().values()),indent=2))
    elif a.command=='release':release(a.id or '',a.approve)
    else:expire(a.days,a.approve)

if __name__=='__main__':
    try:main()
    except (m.MailError,OSError,ValueError):raise SystemExit('Content security operation failed; inspect restricted service logs')
