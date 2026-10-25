import importlib.util,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import mail_snapshot as s
class SnapshotTests(unittest.TestCase):
    def test_freeze_is_thawed_if_lv_creation_fails(self):
        with tempfile.TemporaryDirectory() as td:
            events=[]
            def run(args,**kw):
                events.append(args)
                if args[0]=='findmnt':return '/dev/vg/mail xfs /var/vmail'
                if args[0]=='lvs':return '-wi-a-----'
                if args[0]=='lvcreate':raise s.m.MailError('simulated snapshot failure')
                return ''
            with mock.patch.object(s.m,'STATE',Path(td)),mock.patch.object(s.m,'run',side_effect=run):
                with self.assertRaises(s.m.MailError):
                    with s.mailbox_snapshot({'source_lv':'/dev/vg/mail','filesystem':'xfs','cow_gib':1}):pass
            self.assertIn(['fsfreeze','--unfreeze','/var/vmail'],events)
            self.assertFalse(any(x[0]=='lvremove' for x in events))
    def test_failed_unmount_never_removes_lv_or_mount_directory(self):
        with tempfile.TemporaryDirectory() as td:
            events=[];mounts=[]
            def run(args,**kw):
                events.append(args)
                if args[0]=='findmnt':return '/dev/vg/mail xfs /var/vmail'
                if args[0]=='lvs':return '1' if 'data_percent' in args else '-wi-a-----'
                if args[0]=='mount':mounts.append(Path(args[-1]))
                if args[0]=='umount':raise s.m.MailError('simulated unmount failure')
                return ''
            with mock.patch.object(s.m,'STATE',Path(td)),mock.patch.object(s.m,'run',side_effect=run):
                with self.assertRaises(s.m.MailError):
                    with s.mailbox_snapshot({'source_lv':'/dev/vg/mail','filesystem':'xfs','cow_gib':1}):pass
            self.assertTrue(mounts[0].is_dir())
            self.assertFalse(any(x[0]=='lvremove' for x in events))
