import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import content_security as av
import domain_security as dns
import security_ops as ops
import web_egress as web

class SecurityOperationsTests(unittest.TestCase):
    def test_egress_blocks_web_workers_including_loopback_relay(self):
        text=web.rules({'mail_addresses':['127.0.0.1','::1'],'dns_addresses':['192.0.2.53']},{'roundcube':101,'postfixadmin':102})
        self.assertIn('tcp dport { 587, 993 } accept',text)
        self.assertNotIn('dport 25 ',text)
        self.assertIn('meta skuid { 101, 102 } counter reject',text)
        self.assertIn('policy accept',text)
        self.assertNotIn('meta skuid 102 ip',text)
        with self.assertRaises(web.m.MailError):web.rules({'mail_addresses':[],'dns_addresses':[]},{'roundcube':0,'postfixadmin':102})
        with self.assertRaises(ValueError):web.rules({'mail_addresses':['127.0.0.1; accept'],'dns_addresses':[]},{'roundcube':101,'postfixadmin':102})

    def test_invalid_policy_does_not_touch_firewall(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'p';p.write_text(json.dumps({'mail_addresses':['bad'],'dns_addresses':['127.0.0.1']}));p.chmod(0o600)
            with mock.patch.object(web.m,'run') as run:
                with self.assertRaises(ValueError):web.apply(p)
                run.assert_not_called()

    def test_firewall_check_failure_does_not_apply(self):
        c={'mail_addresses':['127.0.0.1'],'dns_addresses':['127.0.0.1']}
        with mock.patch.object(web,'policy',return_value=c),mock.patch.object(web.pwd,'getpwnam',side_effect=[mock.Mock(pw_uid=101),mock.Mock(pw_uid=102)]),mock.patch.object(web.m.subprocess,'run',return_value=mock.Mock(returncode=1)),mock.patch.object(web.m,'run',side_effect=web.m.MailError('bad rules')) as run:
            with self.assertRaises(web.m.MailError):web.apply('unused',False)
            self.assertEqual(run.call_count,1);self.assertEqual(run.call_args.args[0][:2],['nft','--check'])

    def test_quarantine_cannot_release_infected_or_unscanned_message(self):
        import contextlib
        for failure in ('clamdscan','rspamc'):
            events=[]
            def run(argv,**kwargs):
                events.append(argv)
                if argv[0]==failure:raise av.m.MailError('scanner failed')
                if argv[0]=='postcat':return 'private mail content'
                return '{}'
            with mock.patch.object(av.m,'lock',side_effect=contextlib.nullcontext),mock.patch.object(av,'health'),mock.patch.object(av,'held',return_value={'ABC123':{}}),mock.patch.object(av.m,'run',side_effect=run):
                with self.assertRaises(av.m.MailError):av.release('ABC123',True)
            self.assertFalse(any(e[0]=='postsuper' for e in events))
        with mock.patch.object(av.m,'run') as run:
            with self.assertRaises(av.m.MailError):av.release('ALL',False)
            with self.assertRaises(av.m.MailError):av.release('ABC123;id',True)
            run.assert_not_called()

    def test_quarantine_release_rechecks_hold_and_requires_safe_action(self):
        import contextlib
        with mock.patch.object(av.m,'lock',side_effect=contextlib.nullcontext),mock.patch.object(av,'health'),mock.patch.object(av,'audit'),mock.patch.object(av,'held',side_effect=[{'ABC123':{}},{}]),mock.patch.object(av.m,'run',side_effect=['message','',json.dumps({'action':'no action'})]) as run:
            with self.assertRaises(av.m.MailError):av.release('ABC123',True)
            self.assertEqual(run.call_count,3)
        self.assertIn('soft reject',av.FORCE)
        self.assertIn('CLAM_VIRUS_FAIL',av.FORCE)
        self.assertIn('AlertExceedsMax yes',av.CLAMD)

    def test_sts_rejects_downgrade_duplicate_or_wrong_mx(self):
        good=dns.sts_policy('mail.example.com','enforce');dns.check_sts(good,'mail.example.com')
        for bad in (good.replace('enforce','testing'),good+'mode: none\n',good.replace('mail.example.com','evil.example.net'),good.replace('86400','-1')):
            with self.assertRaises(dns.m.MailError):dns.check_sts(bad,'mail.example.com')
        with self.assertRaises(dns.m.MailError):dns.tags('v=DMARC1;p=reject;p=none')

    def test_dns_mismatch_prevents_selector_promotion(self):
        with mock.patch.object(dns,'dns',return_value=['0 wrong.example.net.']),mock.patch.object(dns.m,'atomic') as atomic:
            with self.assertRaises(dns.m.MailError):dns.promote({'domains':['example.com'],'hostname':'mail.example.com'},'example.com','mail2027',['192.0.2.25'])
            atomic.assert_not_called()

    def test_dane_requires_bogus_dnssec_failure(self):
        with mock.patch.object(dns,'local_resolver'),mock.patch.object(dns.m,'run',side_effect=['flags: qr rd ra ad;','status: NOERROR']) as run:
            with self.assertRaises(dns.m.MailError):dns.dane()
            self.assertEqual(run.call_count,2)

    def test_drift_detects_content_mode_symlink_and_missing(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'managed';p.write_text('approved');p.chmod(0o600)
            e={'path':str(p),'mode':0o600,'owner':ops.pwd.getpwuid(os.getuid()).pw_name,'group':ops.grp.getgrgid(os.getgid()).gr_name,'sha256':ops.m.digest(p)}
            ops.drift([e]);p.write_text('tampered')
            with self.assertRaises(ops.m.MailError):ops.drift([e])
            p.write_text('approved');p.chmod(0o644)
            with self.assertRaises(ops.m.MailError):ops.drift([e])
            p.unlink();p.symlink_to('/etc/passwd')
            with self.assertRaises(ops.m.MailError):ops.drift([e])
            p.unlink()
            with self.assertRaises(ops.m.MailError):ops.drift([e])

    def test_wrong_signing_pin_never_verifies(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'key';p.write_text('public key');p.chmod(0o600)
            with mock.patch.object(ops.m,'run') as run:
                with self.assertRaises(ops.m.MailError):ops.verify(p,p,p,'0'*64)
                run.assert_not_called()

    def test_missing_signature_proofs_fail_closed(self):
        with tempfile.TemporaryDirectory() as td,mock.patch.object(ops.m,'STATE',Path(td)):
            with self.assertRaises(ops.m.MailError):ops.require_verified({'roundcube_sha256':'a','postfixadmin_sha256':'b'})

    def test_canary_rejects_header_injection_before_network(self):
        import mail_canary
        with mock.patch.object(mail_canary.smtplib,'SMTP') as smtp:
            with self.assertRaises(ops.m.MailError):mail_canary.check({'hostname':'mail.example.com','username':'user','password':'p','sender':'user@example.com\r\nBcc: attacker','recipient':'user@example.com'})
            smtp.assert_not_called()
    def test_profiles_cannot_switch_to_uninstalled_source(self):
        with mock.patch.object(ops.m,'read_json',return_value={'release':'old'}),mock.patch.object(ops.m,'source_digest',return_value='new'),mock.patch.object(ops.m,'runtime_install') as install:
            with self.assertRaises(ops.m.MailError):ops.profile_runtime()
            install.assert_not_called()

    def test_old_acceptance_evidence_cannot_skip_new_security_gates(self):
        import contextlib,time
        names={'mailbox_mfa_enrollment_revocation','malware_quarantine_outage','web_worker_egress','independent_delivery_audit','advisories_integrity_rotation','durable_queue_recovery','domain_transport_readiness'}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);c={'operator':'test'};fingerprint=ops.m.fingerprint(c)
            ops.m.atomic(root/'installed.json',json.dumps({'fingerprint':fingerprint,'release':'reviewed'}))
            proof=root/'evidence';ops.m.atomic(proof,json.dumps({'fingerprint':fingerprint,'release':'reviewed','operator':'test','completed_at':time.time(),'checks':{k:True for k in ops.m.EVIDENCE-names}}))
            with mock.patch.object(ops.m,'STATE',root),mock.patch.object(ops.m,'lock',side_effect=contextlib.nullcontext),mock.patch.object(ops.m,'firewall') as firewall:
                with self.assertRaises(ops.m.MailError):ops.m.activate(c,proof)
                firewall.assert_not_called()
