"""Constrain PHP worker UIDs with an independent nftables output chain."""
import argparse
import ipaddress
import json
import pwd
from pathlib import Path
import mailctl as m

def policy(path):
    m.private_file(path); c=m.read_json(path)
    m.require(set(c)=={'mail_addresses','dns_addresses'}, 'Invalid web egress fields')
    for key in c:
        m.require(isinstance(c[key],list) and 0<len(c[key])<=16, 'Explicit address lists required')
        c[key]=[str(ipaddress.ip_address(a)) for a in c[key]]
    return c

def rules(c, uids, existing=False):
    m.require(set(uids)=={'roundcube','postfixadmin'} and all(type(v) is int and v>0 for v in uids.values())
              and len(set(uids.values()))==2, 'Distinct non-root worker UIDs required')
    text=('delete table inet eric_mail_web\n' if existing else '')
    text+='table inet eric_mail_web {\n chain output { type filter hook output priority -10; policy accept;\n'
    for addr in c['mail_addresses']:
        ip=ipaddress.ip_address(addr);family='ip6' if ip.version==6 else 'ip'
        text+=f' meta skuid {uids["roundcube"]} {family} daddr {ip} tcp dport {{ 587, 993 }} accept\n'
    for addr in c['dns_addresses']:
        ip=ipaddress.ip_address(addr);family='ip6' if ip.version==6 else 'ip'
        for proto in ('tcp','udp'):
            text+=f' meta skuid {uids["roundcube"]} {family} daddr {ip} {proto} dport 53 accept\n'
    text+=f' meta skuid {{ {uids["roundcube"]}, {uids["postfixadmin"]} }} counter reject\n }}\n}}\n'
    return text

def apply(path, persist=True):
    c=policy(path)
    uids={name:pwd.getpwnam(name).pw_uid for name in ('roundcube','postfixadmin')}
    if persist:
        from security_ops import profile_runtime
        profile_runtime()
    result=m.subprocess.run(['nft','list','table','inet','eric_mail_web'],stdout=m.subprocess.DEVNULL,stderr=m.subprocess.DEVNULL)
    text=rules(c,uids,result.returncode==0)
    m.run(['nft','--check','--file','-'],data=text)
    m.run(['nft','--file','-'],data=text)  # one atomic transaction; leaves firewalld tables alone
    if persist:
        m.atomic(m.ETC/'web-egress.json',json.dumps(c)+'\n')
        unit='''[Unit]
Description=Constrain Eric Mail web workers
After=firewalld.service
Before=php-fpm.service
Requires=firewalld.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/eric-mail/current/lib/web_egress.py apply --policy /etc/eric-mail/web-egress.json --boot
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''
        m.atomic(Path('/etc/systemd/system/eric-mail-web-egress.service'),unit,0o644)
        m.atomic(Path('/etc/systemd/system/php-fpm.service.d/web-egress.conf'),
                 '[Unit]\nRequires=eric-mail-web-egress.service\nAfter=eric-mail-web-egress.service\n',0o644)
        m.run(['systemctl','daemon-reload']);m.run(['systemctl','enable','eric-mail-web-egress.service'])
        from security_ops import track
        track([m.ETC/'web-egress.json', '/etc/systemd/system/eric-mail-web-egress.service', '/etc/systemd/system/php-fpm.service.d/web-egress.conf'])

def health():
    policy(m.ETC/'web-egress.json')
    live=json.loads(m.run(['nft','--json','list','table','inet','eric_mail_web']))
    m.require(live.get('nftables'), 'Web egress table missing')
    # Compare the kernel's normalized rule representation against a saved live baseline.
    import hashlib
    # Counters are mutable; inspect policy structurally through nft textual output instead.
    live_text=m.run(['nft','--stateless','--numeric','list','table','inet','eric_mail_web'])
    baseline=m.STATE/'web-egress-rules.sha256'
    m.require(baseline.exists() and baseline.read_text().strip()==hashlib.sha256(live_text.encode()).hexdigest(), 'Web egress rules drifted')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['apply','health'])
    p.add_argument('--policy',default='/etc/eric-mail/web-egress.json');p.add_argument('--boot',action='store_true');a=p.parse_args()
    m.root_only()
    if a.command=='health':health();return
    with m.lock():
        apply(a.policy,persist=not a.boot)
        import hashlib
        text=m.run(['nft','--stateless','--numeric','list','table','inet','eric_mail_web'])
        m.atomic(m.STATE/'web-egress-rules.sha256',hashlib.sha256(text.encode()).hexdigest()+'\n')
    if not a.boot:m.run(['systemctl','start','eric-mail-web-egress.service'])

if __name__=='__main__':
    try:main()
    except (m.MailError,OSError,ValueError,KeyError):raise SystemExit('Web egress operation failed; inspect restricted service logs')
