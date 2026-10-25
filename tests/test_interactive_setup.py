"""Real terminal-driven Bash setup without installing services on the test host."""
import json
import os
from pathlib import Path
import pty
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import mailctl as m
import setup_config as setup
ROOT=Path(__file__).resolve().parents[1]

class InteractiveSetupTests(unittest.TestCase):
    def answers(self,marker):
        return [
            ('Mail hostname','mail.example.test'),('Hosted domains','example.test other.example.test'),
            ('Admin hostname','admin.example.test'),('Management CIDRs','192.0.2.10/32 2001:db8::10/128'),
            ('Dedicated network interface','ens192'),('Full-chain server certificate path',''),('Server private-key path',''),
            ('Admin client CA path',''),('Admin client CRL path',''),('Roundcube archive version',''),
            ('Complete Roundcube tar.gz archive path',''),('Independently verified Roundcube SHA-256','0'*64),
            ('PostfixAdmin archive version',''),('Complete PostfixAdmin tar.gz archive path',''),
            ('Independently verified PostfixAdmin SHA-256','1'*64),('Private backup environment file path',''),
            ('Alert executable',"/usr/local/sbin/notify --label 'mail ops' '$(touch "+str(marker)+")'"),
            ('Default DKIM selector',''),('Mailbox quota',''),('Outbound recipients per minute',''),
            ('Outbound burst limit',''),('Queue age alert threshold',''),('Queue count alert threshold',''),
            ('Responsible operator name','Ops "Name"\\Team')]

    def terminal(self,script,args,answers,temporary):
        master,slave=pty.openpty();env=dict(os.environ,TMPDIR=str(temporary))
        proc=subprocess.Popen(['bash',str(script),*args],stdin=slave,stdout=slave,stderr=slave,env=env)
        os.close(slave);output=b'';cursor=0;deadline=time.monotonic()+40
        def read_more():
            nonlocal output
            if time.monotonic()>deadline:raise AssertionError('Terminal setup timed out: '+output[-3000:].decode(errors='replace'))
            if select.select([master],[],[],.2)[0]:
                try:chunk=os.read(master,65536)
                except OSError:chunk=b''
                output+=chunk
                return bool(chunk)
            return proc.poll() is None
        try:
            for prompt,answer in answers:
                token=prompt.encode()
                while token not in output[cursor:]:
                    if not read_more():raise AssertionError('Missing prompt '+prompt+': '+output[-3000:].decode(errors='replace'))
                cursor=output.index(token,cursor)+len(token)
                os.write(master,b'\x04' if answer is None else answer.encode()+b'\n')
            while proc.poll() is None:read_more()
            # Drain terminal output already buffered by the child.
            while select.select([master],[],[],0)[0]:
                try:
                    chunk=os.read(master,65536)
                    if not chunk:break
                    output+=chunk
                except OSError:break
            return proc.returncode,output.decode(errors='replace')
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
            os.close(master)

    def test_wizard_saves_valid_private_json_without_evaluating_responses(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);target=root/'site with spaces.json';marker=root/'must-not-exist'
            rc,text=self.terminal(ROOT/'install.sh',['configure','--output',str(target)],self.answers(marker),root)
            self.assertEqual(rc,0,text)
            c=m.configuration(target)
            self.assertEqual(c['domains'],['example.test','other.example.test'])
            self.assertEqual(c['management_networks'],['192.0.2.10/32','2001:db8::10/128'])
            self.assertEqual(c['alert_command'],['/usr/local/sbin/notify','--label','mail ops','$(touch '+str(marker)+')'])
            self.assertEqual(c['operator'],'Ops "Name"\\Team')
            self.assertIs(type(c['mailbox_quota_mb']),int)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)
            self.assertFalse(marker.exists());self.assertFalse(list(root.glob('eric-mail-setup.*')))

    def test_invalid_answers_retry_and_do_not_escape_existing_validation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);answers=self.answers(root/'must-not-exist')
            answers.insert(0,('Mail hostname','INVALID HOST'))
            pos=next(i for i,x in enumerate(answers) if x[0]=='Management CIDRs');answers.insert(pos,('Management CIDRs','0.0.0.0/0'))
            pos=next(i for i,x in enumerate(answers) if x[0]=='Independently verified Roundcube SHA-256');answers.insert(pos,('Independently verified Roundcube SHA-256','unverified'))
            pos=next(i for i,x in enumerate(answers) if x[0]=='Mailbox quota');answers.insert(pos,('Mailbox quota','0'))
            target=root/'site.json';rc,text=self.terminal(ROOT/'install.sh',['configure','--output',str(target)],answers,root)
            self.assertEqual(rc,0,text);m.configuration(target)
            self.assertIn('Invalid lowercase DNS name',text);self.assertIn('Management networks must be narrow',text)
            self.assertIn('independently verified SHA-256 required',text);self.assertIn('Invalid mailbox_quota_mb',text)

    def test_cancel_and_existing_output_never_leave_partial_or_overwritten_config(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);target=root/'site.json'
            rc,text=self.terminal(ROOT/'install.sh',['configure','--output',str(target)],[('Mail hostname',None)],root)
            self.assertNotEqual(rc,0);self.assertIn('Setup cancelled',text);self.assertFalse(target.exists())
            self.assertFalse(list(root.glob('eric-mail-setup.*')))
            target.write_text('existing configuration');target.chmod(0o600)
            rc,text=self.terminal(ROOT/'install.sh',['configure','--output',str(target)],self.answers(root/'must-not-exist'),root)
            self.assertNotEqual(rc,0);self.assertIn('already exists',text)
            self.assertEqual(target.read_text(),'existing configuration');self.assertFalse(list(root.glob('eric-mail-setup.*')))

    def test_unattended_missing_json_fails_instead_of_prompting_or_installing(self):
        for args in ([],['deploy'],['configure']):
            result=subprocess.run(['bash',str(ROOT/'install.sh'),*args],stdin=subprocess.DEVNULL,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertTrue('terminal' in result.stderr or 'requires root' in result.stderr,result.stderr)
        result=subprocess.run(['bash',str(ROOT/'install.sh'),'--config','/nonexistent-eric-mail-site.json'],stdin=subprocess.DEVNULL,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0);self.assertNotIn('Mail hostname',result.stdout)

    def test_incomplete_answers_and_linked_output_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);work=root/'answers';work.mkdir(mode=0o700)
            with self.assertRaises(m.MailError):setup.save(work,root/'site.json')
            self.assertFalse((root/'site.json').exists())
            c=setup.defaults();c.update(roundcube_sha256='0'*64,postfixadmin_sha256='1'*64,operator='Test operator')
            for key,value in c.items():
                text=' '.join(value) if isinstance(value,list) else str(value)
                p=work/key;p.write_text(text);p.chmod(0o600)
            original=root/'original';original.write_text('original');target=root/'link';target.symlink_to(original)
            with self.assertRaises(FileExistsError):setup.save(work,target)
            self.assertEqual(original.read_text(),'original')
            shared=root/'shared';shared.mkdir(mode=0o777);shared.chmod(0o777)
            with self.assertRaises(m.MailError):setup.save(work,shared/'site.json')
            self.assertFalse((shared/'site.json').exists())
    @unittest.skipUnless(os.geteuid()==0,'Root-only default installation dispatch; exercised in disposable CI')
    def test_bare_install_prompts_then_dispatches_only_saved_valid_configuration(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'lib').mkdir();(root/'config').mkdir()
            shutil.copyfile(ROOT/'install.sh',root/'install.sh')
            shutil.copyfile(ROOT/'lib/setup_config.py',root/'lib/setup_config.py')
            shutil.copyfile(ROOT/'lib/mailctl.py',root/'lib/validation_core.py')
            shutil.copyfile(ROOT/'config/site.example.json',root/'config/site.example.json')
            # Keep the real validator, but replace all privileged backend execution.
            (root/'lib/mailctl.py').write_text("from validation_core import *\nif __name__=='__main__':\n import sys,json\n (Path(__file__).resolve().parents[1]/'invoked').write_text(json.dumps(sys.argv[1:]))\n")
            target=root/'generated.json';answers=self.answers(root/'must-not-exist')+[('Save configuration to',str(target))]
            rc,text=self.terminal(root/'install.sh',[],answers,root)
            self.assertEqual(rc,0,text);m.configuration(target)
            self.assertEqual(json.loads((root/'invoked').read_text()),['deploy','--config',str(target)])
            (root/'invoked').unlink()
            rc,text=self.terminal(root/'install.sh',[],[('Mail hostname',None)],root)
            self.assertNotEqual(rc,0);self.assertFalse((root/'invoked').exists())
            self.assertFalse(list(root.glob('eric-mail-setup.*')))
