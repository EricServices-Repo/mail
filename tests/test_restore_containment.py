import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
S=importlib.util.spec_from_file_location('restore_mailctl',Path(__file__).resolve().parents[1]/'lib/mailctl.py')
m=importlib.util.module_from_spec(S);S.loader.exec_module(m)
class RestoreContainmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)/'state';self.base.mkdir(mode=0o700)
    def test_only_new_direct_children_allowed(self):
        self.assertEqual(m.restore_destination(self.base/'restore-safe_1',self.base),self.base/'restore-safe_1')
        for value in ['restore-one/../../outside','restore-one/child','../restore-outside','restore-','other','restore-a.b']:
            with self.subTest(value=value):
                with self.assertRaises(m.MailError):m.restore_destination(self.base/value,self.base)
    def test_existing_directories_dangling_links_and_linked_bases_rejected(self):
        p=self.base/'restore-link';p.symlink_to(self.base/'missing')
        with self.assertRaises(m.MailError):m.restore_destination(p,self.base)
        p.unlink();p.mkdir()
        with self.assertRaises(m.MailError):m.restore_destination(p,self.base)
        linked=self.base.parent/'linked';linked.symlink_to(self.base)
        with self.assertRaises(m.MailError):m.restore_destination(linked/'restore-a',linked)
    def test_shared_state_directory_rejected(self):
        os.chmod(self.base,0o755)
        with self.assertRaises(m.MailError):m.restore_destination(self.base/'restore-a',self.base)
