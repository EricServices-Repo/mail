"""Forward host audit/service logs to an independent mutually authenticated receiver."""
import argparse
import json
from pathlib import Path
import mailctl as m


def configure(path):
    m.private_file(path);c=m.read_json(path)
    m.require(set(c)=={'hostname','port','ca','certificate','private_key'},'Invalid remote audit policy')
    m.domain(c['hostname']);m.require(type(c['port']) is int and 1<=c['port']<=65535,'Invalid audit port')
    for k in ('ca','certificate','private_key'):
        m.path_value(c[k]);p=Path(c[k]);st=p.stat()
        m.require(p.is_file() and not p.is_symlink() and st.st_uid==0 and not st.st_mode&0o022,'Audit TLS inputs must be protected root files')
    m.private_file(c['private_key'])
    m.run(['openssl','verify','-purpose','sslclient','-CAfile',c['ca'],c['certificate']])
    m.require(m.run(['openssl','x509','-in',c['certificate'],'-pubkey','-noout'])==
              m.run(['openssl','pkey','-in',c['private_key'],'-pubout']),'Audit key mismatch')
    with m.lock():
        m.run(['dnf','-y','--setopt=gpgcheck=1','--setopt=*.gpgcheck=1','--setopt=localpkg_gpgcheck=1','install','rsyslog-gnutls'])
        text=f'''# Dedicated receiver must authorize this client's certificate identity.
global(DefaultNetstreamDriver="gtls" DefaultNetstreamDriverCAFile="{c['ca']}"
       DefaultNetstreamDriverCertFile="{c['certificate']}" DefaultNetstreamDriverKeyFile="{c['private_key']}")
*.* action(type="omfwd" target="{c['hostname']}" port="{c['port']}" protocol="tcp"
  StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
  StreamDriverPermittedPeers="{c['hostname']}"
  action.resumeRetryCount="-1" queue.type="LinkedList" queue.filename="eric-mail-audit"
  queue.maxDiskSpace="1g" queue.saveOnShutdown="on")
'''
        dest=Path('/etc/rsyslog.d/60-eric-mail-remote.conf');old=dest.read_bytes() if dest.exists() else None
        try:
            m.atomic(dest,text,0o600);m.run(['rsyslogd','-N1']);m.run(['systemctl','restart','rsyslog'])
        except Exception:
            if old is None:dest.unlink(missing_ok=True)
            else:m.atomic(dest,old)
            m.run(['systemctl','restart','rsyslog']);raise
        m.atomic(m.ETC/'remote-audit.json',json.dumps(c)+'\n')
        from security_ops import track
        track([dest,m.ETC/'remote-audit.json',c['ca'],c['certificate'],c['private_key']])
        m.run(['logger','-p','authpriv.notice','-t','eric-mail','--','remote-audit-configured'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--policy',required=True);a=p.parse_args()
    try:m.root_only();configure(a.policy)
    except (m.MailError,OSError,ValueError):raise SystemExit('Remote audit configuration failed; inspect restricted service logs')
