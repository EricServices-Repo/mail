"""Run outside the mail host: send and retrieve a unique controlled canary."""
import argparse
import email.message
import imaplib
import json
import secrets
import smtplib
import ssl
import time
from pathlib import Path
import mailctl as m


def check(c, timeout=120):
    m.require(set(c)=={'hostname','username','password','sender','recipient'},'Invalid canary configuration')
    m.domain(c['hostname'])
    for key in ('username','password','sender','recipient'):
        m.require(isinstance(c[key],str) and c[key] and not any(x in c[key] for x in '\r\n\x00'),'Invalid canary credential/address')
    token=secrets.token_hex(24);message=email.message.EmailMessage()
    message['From']=c['sender'];message['To']=c['recipient'];message['Subject']='Eric Mail canary '+token
    message['Message-ID']='<'+token+'@'+c['hostname']+'>';message.set_content('Controlled delivery monitor '+token)
    started=time.monotonic();ctx=ssl.create_default_context()
    with smtplib.SMTP(c['hostname'],587,timeout=15) as smtp:
        smtp.ehlo();smtp.starttls(context=ctx);smtp.ehlo();smtp.login(c['username'],c['password'])
        m.require(not smtp.send_message(message),'Canary recipient rejected')
    while time.monotonic()-started<timeout:
        with imaplib.IMAP4_SSL(c['hostname'],993,ssl_context=ctx,timeout=15) as imap:
            imap.login(c['username'],c['password']);m.require(imap.select('INBOX')[0]=='OK','Cannot select canary inbox')
            typ,ids=imap.uid('search',None,'HEADER','Message-ID','"<'+token+'@'+c['hostname']+'>"')
            m.require(typ=='OK','Canary lookup failed')
            if ids and ids[0]:
                # Do not EXPUNGE: it could delete unrelated operator messages.
                for uid in ids[0].split():imap.uid('store',uid,'+FLAGS.SILENT','(\\Deleted)')
                return {'checked_at':time.time(),'delivery_seconds':round(time.monotonic()-started,3),'delivered':True}
        time.sleep(5)
    raise m.MailError('Canary delivery deadline exceeded')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--credentials',required=True);p.add_argument('--output');a=p.parse_args()
    m.private_file(a.credentials);report=check(m.read_json(a.credentials));text=json.dumps(report)+'\n'
    if a.output:m.atomic(Path(a.output),text)
    print(text,end='')

if __name__=='__main__':
    try:main()
    except (m.MailError,OSError,ValueError,smtplib.SMTPException,imaplib.IMAP4.error):raise SystemExit('Canary failed: delivery or protocol check failed')
