#!/usr/bin/env python3
"""Destructive baseline/MFA recovery drill on a SECOND, explicitly empty lab host."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import mailctl as m


def recovered_path(root, value):
    m.require(isinstance(value,str) and value.startswith('/') and '..' not in Path(value).parts,'Invalid recovery source mapping')
    p=root/value.lstrip('/')
    m.require(p.resolve().is_relative_to(root.resolve()) and not p.is_symlink(),'Recovery source escapes isolated restore directory')
    return p


def preflight(c,root):
    m.require(root.parent==m.STATE and root.name.startswith('restore-') and root.is_dir() and not root.is_symlink(),'Use an isolated restore directory on this target')
    marker=Path('/etc/eric-mail-recovery-target');m.private_file(marker)
    m.require(marker.read_text().strip()=='EMPTY_SECOND_LAB_HOST','Explicit empty recovery-target acknowledgement required')
    meta=m.read_json(recovered_path(root,'/var/lib/eric-mail/backup-stage/installation.json'))
    m.require(meta['fingerprint']==m.fingerprint(c),'Recovery configuration differs from source')
    m.require(meta['release']==m.read_json(m.STATE/'installed.json')['release'],'Recover with exactly the same reviewed runtime release')
    m.require(not any(p.is_file() for p in Path('/var/vmail').rglob('*')) and not m.run(['postqueue','-j']).strip(),'Recovery target already contains mail or queued messages')
    count=m.run(['php','-r',"$d=new PDO('mysql:unix_socket=/var/lib/mysql/mysql.sock','root','');echo $d->query('SELECT COUNT(*) FROM postfixadmin.mailbox')->fetchColumn();"])
    m.require(count.strip()=='0','Recovery target already contains accounts')
    source_inventory=recovered_path(root,'/var/lib/eric-mail/packages.txt').read_text().splitlines()
    current=m.run(['rpm','-qa','--qf','%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n']).splitlines()
    m.require(sorted(source_inventory)==sorted(current),'Recovery target package versions differ')
    # Profile recovery needs site-specific network/PKI/LVM setup. Reject it explicitly
    # rather than silently bringing up a less protected host.
    m.require(not meta.get('security_state'),'Restore security profiles on an isolated target using their acceptance procedure first; this drill supports baseline/MFA only')
    for name in ('web-egress.json','remote-audit.json'):
        m.require(not recovered_path(root,'/etc/eric-mail/'+name).exists(),'Target needs a separate profile-specific recovery procedure')
    for path in ('/etc/rspamd/local.d/antivirus.conf','/etc/rspamd/override.d/dkim_signing.conf'):
        m.require(not recovered_path(root,path).exists(),'Target needs profile-specific recovery acceptance')
    m.require(not (m.STATE/'recovery-import-started').exists(),'Do not repeat a partially imported drill; reset the target VM')
    return meta


def recover(c,root):
    with m.lock():
        meta=preflight(c,root);start=time.time();m.firewall(c,False)
        m.atomic(m.STATE/'recovery-import-started','Reset this disposable VM before retrying a failed recovery\n')
        m.run(['systemctl','stop','redis','rspamd',*m.SERVICES])
        # Credentials and seed encryption key must match restored application data.
        source=recovered_path(root,'/etc/eric-mail/secrets.json');m.secrets_file(source)
        m.atomic(m.ETC/'secrets.json',source.read_bytes())
        key=recovered_path(root,'/etc/eric-mail/mfa.key')
        if key.exists():
            m.require(key.is_file() and len(key.read_bytes())==32,'Invalid recovered MFA key')
            m.atomic(m.ETC/'mfa.key',key.read_bytes(),0o640);m.shutil.chown(m.ETC/'mfa.key',user='root',group='roundcube')
        # Recreate all configuration/grants from trusted source before loading data.
        m.deploy(c,str(m.ETC/'site.json'),already_locked=True)
        m.run(['systemctl','stop','redis','rspamd',*m.SERVICES])
        try:
            dump=recovered_path(root,'/var/lib/eric-mail/backup-stage/databases.sql')
            with dump.open('rb') as stream:
                result=subprocess.run(['mariadb','--protocol=socket','--socket=/var/lib/mysql/mysql.sock'],stdin=stream,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            m.require(result.returncode==0,'Recovered database import failed')
            for source_path,dest in ((meta['mail_source'],'/var/vmail'),('/var/lib/rspamd/dkim','/var/lib/rspamd/dkim')):
                source=recovered_path(root,source_path);m.require(source.is_dir(),'Missing recovery data')
                m.run(['rsync','-a','--delete',str(source)+'/',dest+'/'])
            queue=recovered_path(root,'/var/lib/eric-mail/backup-stage/postfix-spool');m.require(queue.is_dir(),'Missing durable queue')
            m.run(['rsync','-a','--delete','--exclude=/private/','--exclude=/public/','--exclude=/pid/',str(queue)+'/','/var/spool/postfix/'])
            m.run(['restorecon','-RF','/var/vmail','/var/lib/rspamd/dkim','/var/spool/postfix',str(m.ETC)])
            m.validate(c)
            # Do not automatically deliver recovered queues, including external mail.
            m.run(['postsuper','-h','ALL'])
        except BaseException:
            m.firewall(c,False)
            raise  # leave services stopped and the interruption marker intact
        m.run(['systemctl','start','redis','rspamd',*m.SERVICES]);m.health(c,require_backup=False)
        m.backup(c,already_locked=True)
        m.atomic(m.STATE/'recovery-imported.json',json.dumps({'completed_at':time.time(),'duration_seconds':time.time()-start,'fingerprint':m.fingerprint(c),'queues_held':True})+'\n')
        (m.STATE/'recovery-import-started').unlink()
        print('Recovered host is restricted; queues held. Run independent retrieval/canary and queue comparison before approval.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',default='/etc/eric-mail/site.json');p.add_argument('--restored-directory',required=True);a=p.parse_args()
    try:
        m.root_only();m.require(Path('/etc/eric-mail-disposable-lab').is_file() and os.environ.get('ERIC_MAIL_DISPOSABLE_LAB')=='I_ACCEPT_DESTRUCTIVE_LAB_PROVISIONING','Disposable lab acknowledgement required')
        recover(m.configuration(a.config),Path(a.restored_directory))
    except (m.MailError,OSError,ValueError,KeyError):raise SystemExit('Recovery drill failed; target remains restricted. Reset this disposable VM before retrying.')
