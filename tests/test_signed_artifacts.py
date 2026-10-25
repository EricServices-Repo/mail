import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import security_ops as ops

class SignatureTests(unittest.TestCase):
    def test_real_signature_accepts_exact_bytes_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);key=root/'private.pem';pub=root/'public.pem';payload=root/'payload';sig=root/'sig'
            subprocess.run(['openssl','genrsa','-out',str(key),'2048'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['openssl','rsa','-in',str(key),'-pubout','-out',str(pub)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            payload.write_bytes(b'reviewed release');payload.chmod(0o600);pub.chmod(0o600)
            subprocess.run(['openssl','dgst','-sha256','-sign',str(key),'-out',str(sig),str(payload)],check=True);sig.chmod(0o600)
            pin=ops.m.digest(pub);report=ops.verify(payload,sig,pub,pin)
            self.assertEqual(report['archive_sha256'],ops.m.digest(payload))
            payload.write_bytes(b'tampered release')
            with self.assertRaises(ops.m.MailError):ops.verify(payload,sig,pub,pin)

    def test_signed_toolkit_must_match_executed_source(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=root/'source';source.mkdir();script=source/'install.sh';script.write_bytes(b'reviewed installer')
            archive=root/'release.tar.gz'
            with tarfile.open(archive,'w:gz') as tf:
                info=tarfile.TarInfo('release/install.sh');data=b'different installer';info.size=len(data);tf.addfile(info,io.BytesIO(data))
            report={'archive_sha256':ops.m.digest(archive),'signing_key_sha256':'a'*64}
            with mock.patch.object(ops,'verify',return_value=report),mock.patch.object(ops.m,'ROOT',source),mock.patch.object(ops.m,'STATE',root/'state'),mock.patch.object(ops.m,'source_paths',return_value=[script]):
                with self.assertRaises(ops.m.MailError):ops.record_verification(archive,'sig','key','pin',toolkit=True)
                self.assertFalse((root/'state/verified-artifacts').exists())
