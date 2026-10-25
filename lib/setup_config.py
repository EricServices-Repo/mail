"""Serialize and validate responses collected by the Bash installer; no provisioning."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tempfile
import mailctl as m

NUMBERS={'mailbox_quota_mb','outbound_per_minute','outbound_burst','queue_max_age_seconds','queue_max_messages'}
LISTS={'domains','management_networks'}


def defaults():
    return m.read_json(m.ROOT/'config/site.example.json')


def response(key,value):
    if key in NUMBERS:
        m.require(re.fullmatch('[0-9]+',value) is not None,'Enter a whole decimal number')
        return int(value)
    if key in LISTS:return value.split()
    if key=='alert_command':return shlex.split(value,posix=True)
    return value


def configuration(directory,complete=False):
    directory=Path(directory);m.require(directory.is_dir() and not directory.is_symlink(),'Invalid setup directory')
    st=directory.stat();m.require(st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)&0o077==0,'Setup directory must be private')
    c=defaults();present=set()
    for key in m.FIELDS:
        p=directory/key
        if p.exists():
            m.private_file(p);c[key]=response(key,p.read_text());present.add(key)
    if complete:m.require(present==m.FIELDS,'Setup responses are incomplete')
    else:
        # Temporary validation placeholders never reach the saved configuration.
        for key in ('roundcube_sha256','postfixadmin_sha256'):
            if key not in present:c[key]='0'*64
        if 'operator' not in present:c['operator']='Setup validation'
        if c['hostname']==c['admin_hostname']:
            unset='admin_hostname' if 'admin_hostname' not in present else 'hostname'
            if unset not in present:c[unset]='validation.invalid' if c['hostname']!='validation.invalid' else 'unused.invalid'
    with tempfile.NamedTemporaryFile(mode='w',dir=directory,encoding='utf-8') as f:
        json.dump(c,f);f.flush();return m.configuration(f.name)


def save(directory,target):
    c=configuration(directory,complete=True);p=Path(target)
    m.require(p.is_absolute() and '..' not in p.parts and p.name not in ('','.','..'),'Choose an absolute configuration filename')
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        m.require(st.st_uid==os.geteuid() and not st.st_mode&0o022,'Configuration directory must be owned by you and not writable by others')
        out=os.open(p.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        try:
            with os.fdopen(out,'w',encoding='utf-8') as f:
                os.fchmod(f.fileno(),0o600);json.dump(c,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        except BaseException:
            os.unlink(p.name,dir_fd=fd);raise
    finally:os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['default','validate','save'])
    p.add_argument('--field',choices=sorted(m.FIELDS));p.add_argument('--directory');p.add_argument('--output');a=p.parse_args()
    if a.command=='default':
        m.require(a.field is not None,'Field required');value=defaults()[a.field]
        print(shlex.join(value) if isinstance(value,list) else value)
    elif a.command=='validate':configuration(a.directory)
    else:save(a.directory,a.output)

if __name__=='__main__':
    try:main()
    except FileExistsError:raise SystemExit('Configuration already exists; choose another filename or reuse it with --config')
    except (m.MailError,OSError,ValueError,TypeError,KeyError) as e:
        print('Setup: '+(str(e) if isinstance(e,(m.MailError,ValueError)) else 'Cannot read/write setup files; check the path and permissions'),file=sys.stderr);sys.exit(1)
