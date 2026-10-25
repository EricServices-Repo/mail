"""Inventory, advisory checks, signed artifact verification and credential rotation."""
import argparse
import datetime
import hashlib
import json
import os
import pwd
import grp
import secrets
import stat
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
import mailctl as m


def drift(entries=None):
    if entries is None:
        combined={e['path']:e for e in m.read_json(m.STATE/'configuration-manifest.json')}
        profile=m.STATE/'security-manifest.json'
        if profile.exists():combined.update({e['path']:e for e in m.read_json(profile)})
        entries=list(combined.values())
    failures=[]
    for entry in entries:
        path=Path(entry['path'])
        try:
            st=path.lstat()
            if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode)!=entry['mode'] or
                st.st_uid!=pwd.getpwnam(entry['owner']).pw_uid or st.st_gid!=grp.getgrnam(entry['group']).gr_gid or
                m.digest(path)!=entry['sha256']):failures.append(str(path))
        except (OSError,KeyError):failures.append(str(path))
    m.require(not failures,'Managed configuration drift: '+', '.join(failures))


def track(paths):
    """Record explicit administrator-applied profile files without blessing other drift."""
    dest=m.STATE/'security-manifest.json'
    entries={e['path']:e for e in m.read_json(dest)} if dest.exists() else {}
    for value in paths:
        p=Path(value);st=p.lstat()
        m.require(stat.S_ISREG(st.st_mode) and st.st_uid==0,'Profile file must be a root-owned regular file')
        entries[str(p)]={'path':str(p),'mode':stat.S_IMODE(st.st_mode),'owner':pwd.getpwuid(st.st_uid).pw_name,
                         'group':grp.getgrgid(st.st_gid).gr_name,'sha256':m.digest(p)}
    m.atomic(dest,json.dumps(list(entries.values()),indent=2)+'\n')


def inventory():
    rpm=m.run(['rpm','-qa','--qf','%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'])
    components=[]
    for line in rpm.splitlines():
        name,version,arch=line.split('\t')
        components.append({'type':'library','name':name,'version':version,
                           'properties':[{'name':'rpm:architecture','value':arch}]})
    c=m.read_json(m.ETC/'site.json')
    for app in ('roundcube','postfixadmin'):
        components.append({'type':'application','name':app,'version':c[app+'_version'],
                           'hashes':[{'alg':'SHA-256','content':c[app+'_sha256']}]})
    for lock in sorted(Path('/opt/eric-mail/apps').glob('*/composer.lock')):
        data=m.read_json(lock)
        for dep in data.get('packages',[]):
            components.append({'type':'library','name':dep['name'],'version':dep['version'],
                               'purl':'pkg:composer/'+dep['name']+'@'+dep['version'].lstrip('v')})
    return {'bomFormat':'CycloneDX','specVersion':'1.5','version':1,
            'metadata':{'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat()},
            'components':components}


def advisories():
    bom=inventory();m.atomic(m.STATE/'sbom.json',json.dumps(bom,indent=2)+'\n')
    # Distro advisory metadata accounts for vendor backports; upstream version-only
    # CVE matching would incorrectly flag patched Rocky packages.
    result=subprocess.run(['dnf','-q','--refresh','check-update','--security'],capture_output=True,text=True)
    m.require(result.returncode in (0,100),'Distribution advisory retrieval failed')
    queries=[{'package':{'ecosystem':'Packagist','name':x['name']},'version':x['version'].lstrip('v')}
             for x in bom['components'] if x.get('purl','').startswith('pkg:composer/')]
    for app,name in (('roundcube','roundcube/roundcubemail'),('postfixadmin','postfixadmin/postfixadmin')):
        config=m.read_json(m.ETC/'site.json')
        queries.append({'package':{'ecosystem':'Packagist','name':name},'version':config[app+'_version']})
    affected=[]
    for start in range(0,len(queries),100):
        batch=queries[start:start+100]
        req=urllib.request.Request('https://api.osv.dev/v1/querybatch',
                                  data=json.dumps({'queries':batch}).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=30) as response:
            body=response.read(8*1024*1024+1);m.require(len(body)<=8*1024*1024,'Oversized advisory response')
            results=json.loads(body)['results']
        m.require(len(results)==len(batch),'Incomplete advisory result')
        for q,r in zip(batch,results):
            if r.get('vulns'):affected.append({'package':q['package']['name'],'ids':[v['id'] for v in r['vulns']]})
    # Top-level application advisories use their upstream ecosystem names too.
    # Coverage intentionally states feed limitations rather than claiming no CVEs.
    report={'checked_at':time.time(),'distribution_updates':result.returncode==100,'upstream_vulnerabilities':affected,
            'coverage':['Rocky security errata','OSV Packagist installed production dependencies'],
            'manual_review_required':['Roundcube upstream advisories','PostfixAdmin upstream advisories','repository and ClamAV/Rspamd vendor feeds']}
    m.atomic(m.STATE/'advisories.json',json.dumps(report,indent=2)+'\n')
    m.require(result.returncode==0 and not affected,'Security updates or vulnerable dependencies require review')


def verify(archive,signature,public_key,pinned_fingerprint):
    for p in (archive,signature,public_key):m.private_file(p)
    expected=m.digest(public_key)
    m.require(len(pinned_fingerprint)==64 and secrets.compare_digest(expected,pinned_fingerprint.lower()),'Signing-key pin mismatch')
    m.run(['openssl','dgst','-sha256','-verify',public_key,'-signature',signature,archive])
    return {'archive_sha256':m.digest(archive),'signing_key_sha256':expected,'verified_at':time.time()}


def record_verification(archive,signature,key,pin,toolkit=False):
    report=verify(archive,signature,key,pin)
    if toolkit:
        root=m.archive_check(archive,report['archive_sha256'])
        with m.tarfile.open(archive,'r:gz') as tf:
            members={member.name:member for member in tf.getmembers()}
            m.require(len(members)==len(tf.getmembers()),'Duplicate archive members')
            for path in m.source_paths():
                member=members.get(root+'/'+str(path.relative_to(m.ROOT)))
                m.require(member is not None and member.isfile() and member.size==path.stat().st_size,
                          'Signed toolkit differs from executed source')
                m.require(tf.extractfile(member).read()==path.read_bytes(),'Signed toolkit differs from executed source')
        report['source_digest']=m.source_digest()
    m.atomic(m.STATE/'verified-artifacts'/report['archive_sha256'],json.dumps(report)+'\n')
    return report


def require_verified(c):
    reports=[]
    folder=m.STATE/'verified-artifacts'
    if folder.exists():
        for p in folder.iterdir():
            m.private_file(p);reports.append(m.read_json(p))
    for app in ('roundcube','postfixadmin'):
        m.require(any(r.get('archive_sha256')==c[app+'_sha256'] for r in reports),'Missing independently pinned application signature: '+app)
    m.require(any(r.get('source_digest')==m.source_digest() for r in reports),'Executed toolkit does not match a signed release')


def audit(event):
    m.run(['logger','-p','authpriv.notice','-t','eric-mail','--',event])


def rotate(c):
    """Stop consumers, rotate all SQL identities, validate, and roll back on failure.

    Durable journal intentionally holds old+new passwords root-only so a power
    loss can be recovered; never automatically removes evidence of a failed rollback.
    """
    with m.lock():
        journal=m.STATE/'credential-rotation.json'
        m.require(not journal.exists(),'Unfinished credential rotation requires recovery first')
        drift();m.health(c)
        old=m.secrets_file(m.ETC/'secrets.json');new=dict(old)
        for user in ('mail_admin','mail_lookup','mail_auth','roundcube'):new[user]=secrets.token_hex(32)
        m.atomic(journal,json.dumps({'old':old,'new':new,'started_at':time.time()})+'\n')
        audit('credential-rotation-started')
        consumers=('postfix','dovecot','php-fpm')
        m.run(['systemctl','stop',*consumers])
        changed=[];old_manifest=(m.STATE/'configuration-manifest.json').read_bytes()
        try:
            m.run(['php',str(m.ROOT/'templates/rotate-db.php')],data=json.dumps(new))
            with tempfile.TemporaryDirectory(dir=m.STATE,prefix='rotate-') as td:
                entries=m.render(c,new,td)
                for e in entries:
                    path=Path(e['path']);candidate=Path(td)/path.relative_to('/')
                    credential_paths={'/etc/dovecot/mail-sql.conf.ext','/etc/eric-mail/roundcube.json','/etc/eric-mail/postfixadmin.json'}
                    credential_paths.update('/etc/postfix/sql/'+x+'.cf' for x in ('domains','mailboxes','aliases','senders'))
                    if str(path) in credential_paths and path.read_bytes()!=candidate.read_bytes():
                        # Do not rewrite unrelated customizations or profile overrides.
                        m.require(path.suffix in ('.cf','.ext','.json'), 'Unexpected credential-dependent file')
                        st=path.stat();changed.append((path,path.read_bytes(),stat.S_IMODE(st.st_mode),st.st_uid,st.st_gid))
                        m.atomic(path,candidate.read_bytes(),e['mode']);m.shutil.chown(path,user=e['owner'],group=e['group'])
            m.atomic(m.ETC/'secrets.json',json.dumps(new)+'\n')
            m.validate(c);m.run(['systemctl','start',*consumers]);m.health(c,allow_rotation=True)
            # Preserve hashes of all unrelated managed/profile files.
            manifest=json.loads(old_manifest)
            for e in manifest:
                if e['path'] in {str(item[0]) for item in changed}:e['sha256']=m.digest(e['path'])
            m.atomic(m.STATE/'configuration-manifest.json',json.dumps(manifest,indent=2)+'\n')
            audit('credential-rotation-completed');journal.unlink()
        except Exception:
            m.run(['php',str(m.ROOT/'templates/rotate-db.php')],data=json.dumps(old))
            for path,content,mode,uid,gid in reversed(changed):
                m.atomic(path,content,mode);os.chown(path,uid,gid)
            m.atomic(m.ETC/'secrets.json',json.dumps(old)+'\n')
            m.atomic(m.STATE/'configuration-manifest.json',old_manifest)
            m.run(['systemctl','start',*consumers]);m.health(c,allow_rotation=True)
            audit('credential-rotation-rolled-back');journal.unlink();raise


def rotate_recover(use_new):
    with m.lock():
        journal=m.STATE/'credential-rotation.json';m.private_file(journal)
        data=m.read_json(journal);chosen=data['new' if use_new else 'old']
        # Stop mail publication while rebuilding configuration. Ordinary deploy is
        # idempotent and will recreate all runtime consumers from the chosen set.
        c=m.configuration(m.ETC/'site.json');m.firewall(c,False)
        m.run(['systemctl','stop','postfix','dovecot','php-fpm'])
        m.run(['php',str(m.ROOT/'templates/rotate-db.php')],data=json.dumps(chosen))
        m.atomic(m.ETC/'secrets.json',json.dumps(chosen)+'\n')
        m.deploy(c,str(m.ETC/'site.json'),already_locked=True,allow_rotation=True)
        audit('credential-rotation-recovered');journal.unlink()


def enable_checks():
    with m.lock():
        m.runtime_install()
        m.atomic(Path('/etc/systemd/system/eric-mail-advisories.service'),'''[Unit]
Description=Check vendor and dependency security advisories
After=network-online.target
OnFailure=eric-mail-alert@%n.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/eric-mail/current/lib/security_ops.py advisories
UMask=0077
''',0o644)
        m.atomic(Path('/etc/systemd/system/eric-mail-advisories.timer'),'''[Unit]
Description=Daily advisory check
[Timer]
OnBootSec=15min
OnUnitActiveSec=1day
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
''',0o644)
        m.run(['systemctl','daemon-reload']);m.run(['systemctl','enable','--now','eric-mail-advisories.timer'])
        m.atomic(m.STATE/'security-checks.json','{"enabled":true}\n')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['drift','sbom','advisories','enable-checks','verify','rotate-db','recover-rotation','enforce-signatures'])
    p.add_argument('--config',default='/etc/eric-mail/site.json');p.add_argument('--archive');p.add_argument('--signature');p.add_argument('--key');p.add_argument('--key-sha256');p.add_argument('--use-new',action='store_true');p.add_argument('--toolkit',action='store_true');a=p.parse_args();m.root_only()
    if a.command=='drift':drift()
    elif a.command=='sbom':print(json.dumps(inventory(),indent=2))
    elif a.command=='advisories':advisories()
    elif a.command=='enable-checks':enable_checks()
    elif a.command=='verify':
        with m.lock():print(json.dumps(record_verification(a.archive,a.signature,a.key,a.key_sha256 or '',a.toolkit)))
    elif a.command=='enforce-signatures':
        with m.lock():
            require_verified(m.configuration(a.config));m.atomic(m.STATE/'require-signatures.json','{"enabled":true}\n')
    elif a.command=='recover-rotation':rotate_recover(a.use_new)
    else:rotate(m.configuration(a.config))

if __name__=='__main__':
    try:main()
    except (m.MailError,OSError,ValueError,KeyError,TypeError):raise SystemExit('Security operation failed; inspect restricted service logs')
