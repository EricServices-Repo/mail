#!/usr/bin/env python3
"""Destructive, resumable full-host acceptance on explicitly marked disposable VMs."""
import argparse,hashlib,json,os,secrets,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import mailctl as m

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('scenario',choices=['install','reboot-check','restore-check','upgrade','interrupt-install']);p.add_argument('--config',default='/root/eric-mail-lab-site.json');p.add_argument('--previous-config');a=p.parse_args()
    m.root_only();m.require(Path('/etc/eric-mail-disposable-lab').is_file() and os.environ.get('ERIC_MAIL_DISPOSABLE_LAB')=='I_ACCEPT_DESTRUCTIVE_LAB_PROVISIONING','Disposable lab acknowledgement required')
    c=m.configuration(a.config);start=time.time();state=m.STATE/'lab-evidence.json';result=m.read_json(state) if state.exists() else {'checks':{}}
    if a.scenario=='install':
        m.deploy(c,a.config);before=m.digest(m.STATE/'configuration-manifest.json');secret=m.digest(m.ETC/'secrets.json')
        m.deploy(c,a.config);m.require(before==m.digest(m.STATE/'configuration-manifest.json') and secret==m.digest(m.ETC/'secrets.json'),'Rerun changed desired files/secrets')
        result['boot_id']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    elif a.scenario=='reboot-check':
        m.require(result.get('boot_id')!=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Reboot the disposable VM before this scenario');m.health(c)
    elif a.scenario=='upgrade':
        m.require(a.previous_config,'Previous config required');m.upgrade(c,m.configuration(a.previous_config));m.health(c)
    elif a.scenario=='restore-check':
        last=m.read_json(m.STATE/'last-backup.json');target=m.STATE/('restore-lab-'+secrets.token_hex(6));m.restore(c,str(target),last['snapshot_id'])
        dump=target/'var/lib/eric-mail/backup-stage/databases.sql';queue=target/'var/lib/eric-mail/backup-stage/postfix-spool'
        m.require(dump.is_file() and dump.stat().st_size>0 and queue.is_dir(),'Recovery set missing database dump or durable queue')
        # Import into a SECOND isolated VM, never this source host, before attesting full recovery.
        result['restored_directory']=str(target)
    else:
        proc=subprocess.Popen([str(m.ROOT/'install.sh'),'deploy','--config',a.config],start_new_session=True)
        try:
            deadline=time.monotonic()+120
            while not (m.STATE/'deployment-incomplete').exists() and time.monotonic()<deadline:
                m.require(proc.poll() is None,'Provisioning exited before interruption');time.sleep(.2)
            os.killpg(proc.pid,15);proc.wait(timeout=120)
            ports=m.run(['firewall-cmd','--zone=eric-mail','--list-ports']).split()
            m.require(not any(x in ports for x in ['25/tcp','443/tcp','587/tcp','993/tcp']),'Interrupted provisioning exposed public ports')
        finally:
            if proc.poll() is None:os.killpg(proc.pid,9);proc.wait()
    result['checks'][a.scenario]={'completed_at':time.time(),'duration_seconds':time.time()-start,'fingerprint':m.fingerprint(c)}
    m.atomic(state,json.dumps(result,indent=2)+'\n');print('Scenario completed; measured evidence recorded. Unrun gates remain unapproved.')
if __name__=='__main__':main()
