import contextlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
S=importlib.util.spec_from_file_location('domain_mailctl',Path(__file__).resolve().parents[1]/'lib/mailctl.py')
m=importlib.util.module_from_spec(S);S.loader.exec_module(m)
class DomainLifecycleTests(unittest.TestCase):
    def test_provisioning_does_not_override_existing_state(self):
        text=(m.ROOT/'templates/add-domain.php').read_text().split('ON DUPLICATE KEY UPDATE')[1]
        self.assertNotIn('active=',text)
        self.assertNotIn('modified=',text)
    def test_disable_uses_prepared_values_then_kicks_live_sessions(self):
        with mock.patch.object(m,'lock',contextlib.nullcontext),mock.patch.object(m,'run',return_value='') as run:
            m.domain_state({'domains':['example.test']},'example.test',False)
        calls=run.call_args_list
        self.assertEqual(json.loads(calls[0].kwargs['data']),{'domain':'example.test','enabled':False})
        self.assertEqual(calls[1].args[0],['doveadm','kick','*@example.test'])
    def test_unconfigured_enable_and_injected_domain_fail_before_mutation(self):
        with mock.patch.object(m,'run') as run:
            for name in ('other.test','example.test;id'):
                with self.assertRaises(m.MailError):m.domain_state({'domains':['example.test']},name,True)
            run.assert_not_called()
