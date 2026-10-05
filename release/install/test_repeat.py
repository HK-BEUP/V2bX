import contextlib,fcntl,hashlib,io,json,subprocess,tempfile,types,unittest,zipfile,builtins
from pathlib import Path
from unittest.mock import patch
TEXT=(Path(__file__).parent/'install.sh').read_text().split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
M=types.ModuleType('repeat_bootstrap');exec(compile(TEXT,'install.sh','exec'),M.__dict__)
VERSION='v25.12.2-beup-legacy.1'
SAME=b'synthetic-reviewed-binary'
META={'version':VERSION,'binary_sha256':hashlib.sha256(SAME).hexdigest()}

class RepeatTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.binary=self.root/'usr/local/V2bX/V2bX';self.binary.parent.mkdir(parents=True)
  self.real_open=builtins.open
 def guard(self,answer='n',no_tty=False,meta=META):
  def opened(name,*a,**kw):
   if str(name)=='/dev/tty':
    if no_tty:raise OSError('no tty')
    return io.StringIO(answer+'\n')
   return self.real_open(name,*a,**kw)
  self.out=io.StringIO()
  with contextlib.redirect_stdout(self.out),patch('builtins.open',side_effect=opened),patch('subprocess.run',side_effect=AssertionError('guard must not invoke services')):
   return M.should_install(meta,VERSION,self.root)
 def test_same_binary_skips_without_process_or_config_writes(self):
  self.binary.write_bytes(SAME);before=self.binary.stat()
  self.assertFalse(self.guard());self.assertEqual(self.binary.stat().st_mtime_ns,before.st_mtime_ns)
  self.assertEqual(self.binary.read_bytes(),SAME);self.assertIn('已跳过重复安装',self.out.getvalue())
  (Path(__file__).parent/'same-version-output.txt').write_text(self.out.getvalue())
 def test_different_binary_decline_keeps_current(self):
  self.binary.write_bytes(b'old');self.assertFalse(self.guard());self.assertEqual(self.binary.read_bytes(),b'old')
  self.assertIn('暂时中断',self.out.getvalue());self.assertIn('已取消升级',self.out.getvalue())
 def test_different_binary_yes_allows_installer(self):
  self.binary.write_bytes(b'old');self.assertTrue(self.guard(answer='Y'))
 def test_different_binary_no_terminal_cancels(self):
  self.binary.write_bytes(b'old');self.assertFalse(self.guard(no_tty=True))
 def test_fresh_install_continues(self):self.assertTrue(self.guard())
 def test_bad_metadata_never_treated_as_current(self):
  self.binary.write_bytes(SAME)
  with self.assertRaises(SystemExit):self.guard(meta={'version':'wrong','binary_sha256':META['binary_sha256']})
 def test_symlink_is_not_followed_for_repeat_install(self):
  (self.root/'target').write_bytes(SAME);self.binary.symlink_to(self.root/'target')
  with self.assertRaises(SystemExit):self.guard()
 def test_active_upgrade_lock_rejects_repeat(self):
  self.binary.write_bytes(SAME);lock=self.root/'run/lock/beup-v2bx-upgrade.lock';lock.parent.mkdir(parents=True)
  with open(lock,'w') as held:
   fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaises(SystemExit):self.guard()
 def test_published_binary_exact_match_skips(self):
  pkg=Path('/Users/minxiangcai/Developer/BEUP/deployments/2026-09-18-subaccounts-admin-v1/legacy-queue-improvement-20261001/one-click-install-20261004/final-artifacts/V2bX-linux-64.zip')
  if not pkg.is_file(): self.skipTest('Published package fixture is verified separately')
  with zipfile.ZipFile(pkg) as z:
   self.binary.write_bytes(z.read('V2bX'));meta=json.loads(z.read('RELEASE.json'))
  self.assertFalse(self.guard(meta=meta));self.assertIn('已跳过重复安装',self.out.getvalue())
 def test_main_same_version_never_executes_packaged_upgrader(self):
  self.binary.write_bytes(SAME);archive=io.BytesIO()
  with zipfile.ZipFile(archive,'w') as z:
   z.writestr('upgrade.py','raise SystemExit("MUST NOT EXECUTE")')
   z.writestr('RELEASE.json',json.dumps(dict(META,legacy_accounting_v1=True)))
  payload=archive.getvalue();sha=hashlib.sha256(payload).hexdigest()
  def fetch(url,limit):
   if url.endswith('/latest'):return json.dumps({'tag_name':VERSION}).encode()
   if url.endswith('/SHA256SUMS'):return (sha+'  V2bX-linux-64.zip\n').encode()
   return payload
  original=M.should_install
  with patch.object(M,'fetch',side_effect=fetch),patch.object(M,'should_install',side_effect=lambda meta,v:original(meta,v,self.root)),patch('sys.argv',['install.sh','latest']),patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'),patch('os.path.isdir',return_value=True),patch('subprocess.run',side_effect=AssertionError('repeat must not execute any child')),contextlib.redirect_stdout(io.StringIO()) as out:
   M.main()
  self.assertIn('已跳过重复安装',out.getvalue());self.assertNotIn('重启成功',out.getvalue())
  (Path(__file__).parent/'repeat-e2e-output.txt').write_text(out.getvalue())

if __name__=='__main__':unittest.main(verbosity=2)
