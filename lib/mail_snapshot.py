"""Optional thick-LVM mailbox snapshots. Call only while mail writers are stopped."""
import contextlib,json,re,secrets,tempfile
from pathlib import Path
import mailctl as m

def policy(path):
    m.private_file(path);c=m.read_json(path)
    m.require(set(c)=={'source_lv','filesystem','cow_gib'},'Invalid snapshot policy')
    m.require(isinstance(c['source_lv'],str) and re.fullmatch(r'/dev/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+',c['source_lv']),'Explicit LVM source required')
    m.require(c['filesystem'] in ('xfs','ext4') and type(c['cow_gib']) is int and 1<=c['cow_gib']<=1024,'Invalid snapshot filesystem/size')
    return c

@contextlib.contextmanager
def mailbox_snapshot(c):
    source=Path(c['source_lv']);name='em-backup-'+secrets.token_hex(6);device=source.parent/name
    actual=m.run(['findmnt','-n','-o','SOURCE,FSTYPE,TARGET','--target','/var/vmail']).split()
    m.require(len(actual)==3 and Path(actual[0]).resolve()==source.resolve() and actual[1:]==[c['filesystem'],'/var/vmail'],'Mailbox must be a dedicated matching mounted LV')
    m.require(m.run(['lvs','--noheadings','-o','lv_attr',source]).strip().startswith('-'),'Only ordinary thick LVs are supported')
    created=False;mounted=False
    with tempfile.TemporaryDirectory(prefix='mail-snapshot-',dir=m.STATE) as td:
        frozen=False
        try:
            try:
                frozen=True;m.atomic(m.STATE/'thaw-required.json',json.dumps({'mount':'/var/vmail'})+'\n')
                m.run(['fsfreeze','--freeze','/var/vmail'])
                m.run(['lvcreate','--snapshot','--size',str(c['cow_gib'])+'G','--name',name,source]);created=True
            finally:
                if frozen:
                    m.run(['fsfreeze','--unfreeze','/var/vmail']);(m.STATE/'thaw-required.json').unlink()
            options='ro,nouuid,norecovery' if c['filesystem']=='xfs' else 'ro,noload'
            m.run(['mount','-t',c['filesystem'],'-o',options,device,td]);mounted=True
            yield td
            usage=m.run(['lvs','--noheadings','-o','data_percent',device]).strip()
            m.require(usage and float(usage)<90,'Snapshot COW space exhausted or approaching exhaustion')
        finally:
            if mounted:m.run(['umount',td])
            if created:m.run(['lvremove','--yes',device])
