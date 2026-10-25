import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('recover_host',ROOT/'tests/recover_host.py');recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery)
class RecoveryLabTests(unittest.TestCase):
    def test_restored_mapping_cannot_escape_or_follow_external_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'mail').mkdir();self.assertEqual(recovery.recovered_path(root,'/mail'),root/'mail')
            (root/'link').symlink_to('/etc')
            for value in ('relative','/../etc','/link/passwd','/link'):
                with self.assertRaises(recovery.m.MailError):recovery.recovered_path(root,value)
    def test_unapproved_target_rejected_before_any_service_mutation(self):
        with tempfile.TemporaryDirectory() as td,mock.patch.object(recovery.m,'STATE',Path(td)/'state'),mock.patch.object(recovery.m,'run') as run:
            with self.assertRaises(recovery.m.MailError):recovery.preflight({},Path(td)/'live-host')
            run.assert_not_called()
