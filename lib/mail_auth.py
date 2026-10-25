#!/usr/bin/env python3
"""Root-only enrollment/recovery/device administration; secrets are displayed once."""
import argparse,base64,json,re,secrets,time
from urllib.parse import urlencode
import mailctl as m

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['enroll','device','revoke','suspend']);p.add_argument('--address',required=True);p.add_argument('--id');p.add_argument('--label',default='Mail client');p.add_argument('--days',type=int,default=90);a=p.parse_args()
    m.root_only();m.require(re.fullmatch(r'[a-z0-9][a-z0-9._+-]*@[a-z0-9.-]+',a.address),'Use canonical ASCII mailbox address')
    m.require(1<=a.days<=365 and len(a.label)<=64,'Invalid device expiration or label')
    s={'op':a.operation,'username':a.address};result=None
    if a.operation=='enroll':
        seed=base64.b32encode(secrets.token_bytes(20)).decode();codes=[secrets.token_hex(16) for _ in range(10)]
        s.update(seed=seed,recovery=codes);result={'otpauth_uri':'otpauth://totp/'+a.address+'?'+urlencode({'secret':seed,'issuer':'Eric Mail','digits':6,'period':30}),'recovery_codes':codes}
    elif a.operation=='device':
        token=secrets.token_hex(32);identifier=secrets.token_hex(12);s.update(password=token,id=identifier,label=a.label,expires=int(time.time())+a.days*86400);result={'username':a.address+'#'+identifier,'password':token,'expires_at':s['expires']}
    elif a.operation=='revoke':
        m.require(a.id and re.fullmatch('[a-f0-9]{24}',a.id),'Device ID required');s['id']=a.id
    with m.lock():
        m.run(['php',str(m.ROOT/'templates/mfa-admin.php')],data=json.dumps(s))
        if a.operation in ('enroll','revoke','suspend'):m.run(['doveadm','kick',a.address])
    if result:print(json.dumps(result,indent=2))
if __name__=='__main__':main()
