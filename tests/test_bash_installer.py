"""Exercise the public Bash installer without provisioning the test machine."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

class BashInstallerTests(unittest.TestCase):
    def test_help_and_feature_help_work_without_host_configuration(self):
        result=subprocess.run(['bash',str(ROOT/'install.sh'),'--help'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('sudo bash install.sh',result.stdout)
        self.assertIn('Docker is not required',result.stdout)
        for command in ('mailbox-mfa','content-security','web-egress','domain-security','security-ops','remote-audit','canary','replication'):
            with self.subTest(command=command):
                result=subprocess.run(['bash',str(ROOT/'install.sh'),command,'--help'],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('usage:',result.stdout)

    def test_native_deploy_argument_boundaries_and_exit_status(self):
        # Stub only the privileged backend: the real Bash entry point runs from a
        # path containing spaces, with no actual services/configuration touched.
        with tempfile.TemporaryDirectory(prefix='installer with spaces ') as td:
            root=Path(td);(root/'lib').mkdir();shutil.copyfile(ROOT/'install.sh',root/'install.sh')
            (root/'lib/mailctl.py').write_text('import json,sys;print(json.dumps(sys.argv[1:]));sys.exit(7)\n')
            for args,expected in (([],['deploy']),(['--config','/private/site with spaces.json'],['deploy','--config','/private/site with spaces.json']),(['render','--output','output with spaces'],['render','--output','output with spaces'])):
                with self.subTest(args=args):
                    result=subprocess.run(['bash',str(root/'install.sh'),*args],capture_output=True,text=True)
                    self.assertEqual(result.returncode,7,result.stderr)
                    self.assertEqual(json.loads(result.stdout),expected)

    def test_incomplete_release_fails_with_actionable_error(self):
        with tempfile.TemporaryDirectory() as td:
            script=Path(td)/'install.sh';shutil.copyfile(ROOT/'install.sh',script)
            result=subprocess.run(['bash',str(script),'deploy'],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('complete reviewed checkout/release',result.stderr)
