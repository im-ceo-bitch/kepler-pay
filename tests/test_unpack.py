import importlib.util
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/'scripts'/'secure_unpack.py'
spec=importlib.util.spec_from_file_location('secure_unpack',SCRIPT)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestUnpack(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.repo=Path(self.tmp.name)
        (self.repo/'spyderpay_core').mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def archive(self,names):
        path=self.repo/'spyderpay-core-update-v001.zip'
        with zipfile.ZipFile(path,'w') as z:
            for name,data in names:
                z.writestr(name,data)
        return path

    def test_normal_overlay_removes_only_archive(self):
        keep=self.repo/'spyderpay_core'/'old.py'
        keep.write_text('old')
        archive=self.archive([('spyderpay_core/new.py','new')])
        self.assertEqual(mod.install(self.repo,archive,('spyderpay_core',)),1)
        self.assertFalse(archive.exists())
        self.assertEqual(keep.read_text(),'old')
        self.assertEqual((self.repo/'spyderpay_core'/'new.py').read_text(),'new')

    def test_reject_traversal_without_modification(self):
        archive=self.archive([('spyderpay_core/good.py','good'),('../escape.py','bad')])
        with self.assertRaises(ValueError):
            mod.install(self.repo,archive,('spyderpay_core',))
        self.assertFalse((self.repo/'spyderpay_core'/'good.py').exists())
        self.assertTrue(archive.exists())

    def test_reject_workflow_overlay(self):
        archive=self.archive([('.github/workflows/ci.yml','malicious')])
        with self.assertRaises(ValueError):
            mod.install(self.repo,archive,('spyderpay_core',))

    def test_reject_private_key(self):
        archive=self.archive([('spyderpay_core/my-private.key','not safe')])
        with self.assertRaises(ValueError):
            mod.install(self.repo,archive,('spyderpay_core',))

    def test_reject_symlinks(self):
        archive=self.repo/'spyderpay-core-update-v001.zip'
        link=zipfile.ZipInfo('spyderpay_core/escape.py')
        link.create_system=3
        link.external_attr=(stat.S_IFLNK|0o777)<<16
        with zipfile.ZipFile(archive,'w') as z:
            z.writestr(link,'../../escape')
        with self.assertRaises(ValueError):
            mod.install(self.repo,archive,('spyderpay_core',))

    def test_reject_destination_symlink(self):
        outside=self.repo.parent/'do-not-write.py'
        target=self.repo/'spyderpay_core'/'target.py'
        target.symlink_to(outside)
        archive=self.archive([('spyderpay_core/target.py','bad')])
        with self.assertRaises(ValueError):
            mod.install(self.repo,archive,('spyderpay_core',))

    def test_reject_duplicate_entries(self):
        archive=self.archive([('spyderpay_core/test.py','a'),('spyderpay_core/test.py','b')])
        with self.assertRaises(ValueError):
            mod.install(self.repo,archive,('spyderpay_core',))

if __name__=='__main__':
    unittest.main()
