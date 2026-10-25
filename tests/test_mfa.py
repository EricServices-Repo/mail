import json,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class MFATests(unittest.TestCase):
    def php(self,code):
        p=subprocess.run(['php','-r','require '+json.dumps(str(ROOT/'templates/mfa-core.php'))+';'+code],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr);return p.stdout
    def test_rfc6238_vectors_and_replay(self):
        # RFC vector seed is ASCII 12345678901234567890, encoded as base32.
        result=self.php('$s="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; echo json_encode([mail_totp($s,1),mail_totp_counter($s,"287082",59,-1),mail_totp_counter($s,"287082",59,1),mail_totp_counter($s,"000000",59,-1)]);')
        self.assertEqual(json.loads(result),['287082',1,None,None])
    def test_authenticated_seed_encryption_and_tampering(self):
        result=self.php('$k=random_bytes(32);$v=mail_seed_encrypt("SEED",$k);echo mail_seed_decrypt($v,$k);try{mail_seed_decrypt($v,random_bytes(32));echo "bad";}catch(Throwable $e){echo " rejected";}')
        self.assertEqual(result,'SEED rejected')
    def test_fail_closed_hooks_and_remote_credentials(self):
        p=(ROOT/'templates/webmail-mfa.php').read_text();self.assertIn("empty($args['valid'])",p);self.assertIn("$args['abort']=true",p)
        sql=(ROOT/'templates/dovecot-sql.conf').read_text();self.assertIn('t.revoked=0 AND t.expires_at>NOW()',sql);self.assertIn("'%r' IN ('127.0.0.1','::1')",sql)
