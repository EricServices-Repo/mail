"""DNS readiness, MTA-STS policy export, staged DKIM rotation and opt-in DANE."""
import argparse
import base64
import hashlib
import ipaddress
import json
import re
import shlex
import ssl
import urllib.request
from pathlib import Path
import mailctl as m


def dns(name, kind):
    m.require(re.fullmatch(r'[A-Za-z0-9_.:-]+',name) and kind in ('TXT','MX','A','AAAA','PTR','TLSA'),'Invalid DNS query')
    text=m.run(['dig','+time=3','+tries=1','+short',name,kind])
    if kind=='TXT':return [''.join(shlex.split(line)) for line in text.splitlines() if line]
    return text.splitlines()


def tags(text):
    result={}
    for item in text.split(';'):
        if not item.strip():continue
        key,sep,value=item.strip().partition('=')
        m.require(sep and key not in result,'Malformed or duplicate DNS tag')
        result[key]=value.strip()
    return result


def one_record(name,prefix):
    found=[r for r in dns(name,'TXT') if r.startswith(prefix)]
    m.require(len(found)==1,'Missing or ambiguous DNS policy: '+name)
    return found[0]


def sts_policy(host,mode='testing',age=86400):
    m.domain(host);m.require(mode in ('testing','enforce') and 86400<=age<=31557600,'Invalid MTA-STS policy')
    return f'version: STSv1\nmode: {mode}\nmx: {host}\nmax_age: {age}\n'


def check_sts(text,host):
    pairs=[line.strip().split(':',1) for line in text.splitlines() if line.strip()]
    m.require(all(len(p)==2 for p in pairs),'Malformed MTA-STS policy')
    values={}
    for k,v in pairs:values.setdefault(k.strip(),[]).append(v.strip())
    m.require(values.get('version')==['STSv1'] and values.get('mode')==['enforce'] and
              values.get('mx')==[host] and len(values.get('max_age',[]))==1 and
              values['max_age'][0].isdigit() and 86400<=int(values['max_age'][0])<=31557600,
              'MTA-STS must enforce the expected MX and a valid lifetime')


def readiness(c,name,selector,addresses):
    m.domain(name);m.require(name in c['domains'],'Domain outside desired configuration')
    m.require(re.fullmatch('[a-z][a-z0-9]{0,30}',selector),'Invalid selector')
    expected={str(ipaddress.ip_address(a)) for a in addresses}
    m.require(expected,'Expected mail IPs required')
    mx=[line.split() for line in dns(name,'MX')]
    m.require(mx and all(len(x)==2 and x[0].isdigit() and x[1].rstrip('.')==c['hostname'] for x in mx),'MX mismatch')
    actual={str(ipaddress.ip_address(a)) for kind in ('A','AAAA') for a in dns(c['hostname'],kind)}
    m.require(actual==expected,'Forward address set differs from approved IPs')
    for a in expected:
        reverse=ipaddress.ip_address(a).reverse_pointer
        m.require([x.rstrip('.') for x in dns(reverse,'PTR')]==[c['hostname']],'PTR mismatch')
    spf=one_record(name,'v=spf1')
    # Conservative gate: indirect include/redirect policies require separate review.
    mechanisms=spf.split();approved={'ip4:'+a for a in expected if ':' not in a}|{'ip6:'+a for a in expected if ':' in a}
    m.require(mechanisms[0]=='v=spf1' and mechanisms[-1]=='-all' and set(mechanisms[1:-1])==approved,'SPF must authorize exactly the approved IPs with -all')
    dmarc=tags(one_record('_dmarc.'+name,'v=DMARC1'))
    m.require(dmarc.get('p') in ('quarantine','reject') and dmarc.get('pct','100')=='100' and dmarc.get('rua','').startswith('mailto:'),'DMARC enforcement/reporting missing')
    key=Path('/var/lib/rspamd/dkim')/(name+'.'+selector+'.key')
    public=m.run(['openssl','pkey','-in',key,'-pubout','-outform','PEM'])
    encoded=''.join(public.splitlines()[1:-1])
    dkim=tags(one_record(selector+'._domainkey.'+name,'v=DKIM1'))
    m.require(dkim.get('p')==encoded and dkim.get('k','rsa')=='rsa','Published DKIM key mismatch')
    sts=tags(one_record('_mta-sts.'+name,'v=STSv1'))
    m.require(sts.get('id') and re.fullmatch('[A-Za-z0-9]{1,32}',sts['id']),'MTA-STS policy ID missing')
    rpt=tags(one_record('_smtp._tls.'+name,'v=TLSRPTv1'))
    m.require(rpt.get('rua','').startswith(('mailto:','https://')),'TLS reporting destination missing')
    url='https://mta-sts.'+name+'/.well-known/mta-sts.txt'
    # Disallow redirects: policy must originate at the domain's authenticated endpoint.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kw):return None
    opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),NoRedirect())
    with opener.open(url,timeout=10) as response:
        text=response.read(65537);m.require(len(text)<=65536,'Oversized MTA-STS policy')
        check_sts(text.decode('utf-8'),c['hostname'])
    return {'domain':name,'selector':selector,'addresses':sorted(expected),'ready':True}


def stage(c,name,selector):
    m.require(name in c['domains'] and re.fullmatch('[a-z][a-z0-9]{0,30}',selector),'Invalid domain or selector')
    key=Path('/var/lib/rspamd/dkim')/(name+'.'+selector+'.key')
    m.require(not key.exists(),'Selector already exists; choose a new selector')
    secret=m.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048'])
    m.atomic(key,secret,0o640);m.shutil.chown(key,user='root',group='_rspamd')
    m.run(['restorecon',str(key)])
    public=m.run(['openssl','pkey','-in',key,'-pubout'])
    print(selector+'._domainkey.'+name+' TXT "v=DKIM1; k=rsa; p='+''.join(public.splitlines()[1:-1])+'"')


def promote(c,name,selector,addresses):
    report=readiness(c,name,selector,addresses)
    path=Path('/etc/rspamd/override.d/dkim_signing.conf')
    state=m.STATE/'dkim-selectors.json';selectors=m.read_json(state) if state.exists() else {}
    selectors[name]=selector
    for domain,sel in selectors.items():
        m.domain(domain);m.require(re.fullmatch('[a-z][a-z0-9]{0,30}',sel),'Invalid stored selector')
    text='domain {\n'+''.join(f' {domain} {{ selector = "{sel}"; path = "/var/lib/rspamd/dkim/{domain}.{sel}.key"; }}\n' for domain,sel in sorted(selectors.items()))+'}\n'
    path.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    old=path.read_bytes() if path.exists() else None
    try:
        m.atomic(path,text,0o644);m.run(['rspamadm','configtest']);m.run(['systemctl','reload','rspamd'])
    except Exception:
        if old is None:path.unlink(missing_ok=True)
        else:m.atomic(path,old,0o644)
        m.run(['systemctl','reload','rspamd']);raise
    m.atomic(state,json.dumps(selectors)+'\n')
    from security_ops import track
    track([path,Path('/var/lib/rspamd/dkim')/(name+'.'+selector+'.key')])
    print(json.dumps(report))
    m.run(['logger','-p','authpriv.notice','-t','eric-mail','--','dkim-promoted:'+name+':'+selector])


def local_resolver():
    resolvers=[line.split()[1] for line in Path('/etc/resolv.conf').read_text().splitlines() if line.split() and line.split()[0]=='nameserver' and len(line.split())>=2]
    m.require(resolvers and all(ipaddress.ip_address(a).is_loopback for a in resolvers),'DANE requires a local validating resolver on loopback')


def dane(reload=True):
    # Operators must provide a local validating resolver. The deliberate BOGUS
    # test prevents enabling DANE against a resolver that merely passes DNS through.
    local_resolver()
    good=m.run(['dig','+dnssec','+time=3','+tries=1','cloudflare.com','A'])
    bad=m.run(['dig','+dnssec','+time=3','+tries=1','dnssec-failed.org','A'])
    m.require(re.search(r'flags:[^;]*\bad\b',good) and 'status: SERVFAIL' in bad,'Local resolver must validate DNSSEC (including BOGUS rejection)')
    m.run(['postconf','-e','smtp_dns_support_level=dnssec','smtp_tls_security_level=dane'])
    m.run(['postfix','check'])
    if reload:m.run(['systemctl','reload','postfix'])
    m.atomic(m.STATE/'dane-enabled.json','{"enabled":true}\n')
    from security_ops import track
    track(['/etc/postfix/main.cf'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['check','sts-policy','dkim-stage','dkim-promote','dane-enable'])
    p.add_argument('--config',default='/etc/eric-mail/site.json');p.add_argument('--domain');p.add_argument('--selector');p.add_argument('--address',action='append',default=[])
    p.add_argument('--mode',choices=['testing','enforce'],default='testing');a=p.parse_args()
    m.root_only();c=m.configuration(a.config)
    if a.command=='sts-policy':print(sts_policy(c['hostname'],a.mode));return
    if a.command=='check':print(json.dumps(readiness(c,a.domain,a.selector or c['dkim_selector'],a.address)));return
    with m.lock():
        if a.command=='dkim-stage':stage(c,a.domain,a.selector or '')
        elif a.command=='dkim-promote':promote(c,a.domain,a.selector or '',a.address)
        else:dane()

if __name__=='__main__':
    try:main()
    except (m.MailError,OSError,ValueError,TypeError):raise SystemExit('Domain security operation failed; inspect restricted service logs')
