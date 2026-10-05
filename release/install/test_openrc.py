import contextlib,hashlib,io,json,subprocess,tempfile,types,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
import upgrade as u
import test_upgrade

CODE=Path(__file__).with_name('install.sh').read_text().split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
M=types.ModuleType('alpine_bootstrap');exec(compile(CODE,'install.sh','exec'),M.__dict__)

class OpenRCTests(unittest.TestCase):
 def test_detect_openrc_and_systemd_priority(self):
  with patch('platform.system',return_value='Linux'),patch('upgrade.shutil.which',return_value='/sbin/tool'),patch.object(Path,'is_dir',lambda p:str(p)=='/run/openrc'):
   self.assertIsInstance(u.service_manager(),u.OpenRC)
  with patch('platform.system',return_value='Linux'),patch.object(Path,'is_dir',return_value=True):
   self.assertIsInstance(u.service_manager(),u.Systemd)
 def test_unsupported_init_refused_without_commands(self):
  with patch('platform.system',return_value='Linux'),patch.object(Path,'is_dir',return_value=False),patch('upgrade.subprocess.run') as run:
   with self.assertRaises(ValueError):u.service_manager()
   run.assert_not_called()
 def test_stop_has_no_kill_and_requires_exit_before_zap(self):
  s=u.OpenRC();s.stop_budget=630
  with patch.object(s,'identity',side_effect=[(12,'100'),None]),patch.object(s,'call',return_value=types.SimpleNamespace(returncode=0)) as call:
   s.stop();self.assertIn('TERM/630',call.call_args_list[0].args)
   self.assertEqual(call.call_args_list[-1].args,('rc-service','V2bX','zap'))
   self.assertNotIn('KILL',str(call.call_args_list))
 def test_stop_timeout_does_not_zap_or_start(self):
  s=u.OpenRC()
  with patch.object(s,'identity',return_value=(12,'100')),patch.object(s,'call',return_value=types.SimpleNamespace(returncode=2)) as call:
   with self.assertRaises(RuntimeError):s.stop()
   self.assertEqual(call.call_count,1)
 def test_process_changes_are_not_healthy(self):
  s=u.OpenRC();s.required_ports={'tcp:expected'}
  with patch.object(s,'identity',side_effect=[(12,'100'),(12,'200')]),patch.object(s,'active',return_value=True),patch('upgrade.time.sleep'):
   self.assertFalse(s.healthy())
 def test_stable_process_with_original_ports_is_healthy(self):
  s=u.OpenRC();s.required_ports={'tcp:expected'}
  with patch.object(s,'identity',return_value=(12,'100')),patch.object(s,'active',return_value=True),patch.object(s,'listening',return_value={'tcp:expected'}),patch('upgrade.time.sleep'):
   self.assertTrue(s.healthy())
 def test_overrides_refused_before_commands(self):
  s=u.OpenRC()
  with patch.object(Path,'exists',return_value=True),patch.object(s,'call') as call:
   with self.assertRaisesRegex(ValueError,'conf.d'):s.validate()
   call.assert_not_called()
 def test_custom_unit_refused_before_stop(self):
  s=u.OpenRC()
  with patch.object(Path,'exists',lambda p:str(p)=='/etc/init.d/V2bX'),patch.object(Path,'is_symlink',return_value=False),patch.object(Path,'read_text',return_value='#!/bin/sh\nunknown_start'),patch.object(s,'call') as call:
   with self.assertRaisesRegex(ValueError,'自定义'):s.validate()
   call.assert_not_called()
 def test_openrc_status_does_not_invoke_systemctl(self):
  with patch('os.path.isdir',side_effect=lambda p:p=='/run/openrc'),patch('subprocess.run',return_value=types.SimpleNamespace(returncode=0)) as run:
   self.assertTrue(M.service_flag('is-active'))
   self.assertEqual(run.call_args.args[0],['rc-service','V2bX','status'])
 def test_old_package_rejected_before_install_on_alpine(self):
  payload=io.BytesIO()
  with zipfile.ZipFile(payload,'w') as z:
   z.writestr('upgrade.py','raise RuntimeError("must not run")')
   z.writestr('RELEASE.json',json.dumps({'legacy_accounting_v1':True}))
  raw=payload.getvalue()
  def fetch(url,limit):
   return (hashlib.sha256(raw).hexdigest()+'  V2bX-linux-64.zip\n').encode() if url.endswith('SHA256SUMS') else raw
  with patch('sys.argv',['install','v25.12.2-test']),patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'),patch('os.path.isdir',side_effect=lambda p:p=='/run/openrc'),patch('shutil.which',return_value='/sbin/tool'),patch.object(M,'fetch',side_effect=fetch),patch('subprocess.run') as run,contextlib.redirect_stdout(io.StringIO()):
   with self.assertRaisesRegex(SystemExit,'尚不支持 Alpine'):M.main()
   run.assert_not_called()

class OpenRCTransactionTests(test_upgrade.UpgradeTests):
 # Reuse the complete fault matrix with a distinct OpenRC unit path and mode.
 def setUp(self):
  super().setUp()
  self.unit.unlink();self.unit=self.root/'etc/init.d/V2bX';self.unit.parent.mkdir(parents=True)
  self.unit.write_text('operator-unit');self.unit.chmod(0o755)
  self.service.unit_path='etc/init.d/V2bX';self.service.unit_mode=0o755
  self.service.unit_text=u.OPENRC_UNIT;self.service.upgrade_unit=True
 def test_success_preserves_config_and_operator_files(self):
  result=self.run_upgrade();self.assertEqual(u.tree_hash(self.config),self.before)
  self.assertEqual((self.program/'operator.txt').read_text(),'keep')
  self.assertEqual(self.unit.read_text(),u.OPENRC_UNIT)
  self.assertTrue(self.unit.stat().st_mode & 0o111)
  self.assertEqual((Path(result['backup'])/'V2bX.service').read_text(),'operator-unit')
 def test_stopped_remains_stopped(self):
  self.service.running=False;self.run_upgrade();self.assertFalse(self.service.running)
  self.assertEqual(self.service.calls,['reload'])
 def test_start_failure_rolls_back(self):
  self.service.health=[False,True]
  with self.assertRaisesRegex(RuntimeError,'稳定启动'):self.run_upgrade()
  self.unchanged();self.assertTrue(self.service.active())
  self.assertEqual(self.service.calls,['stop','reload','start','healthy','stop','reload','start','healthy'])
 def test_service_drift_during_stop_is_not_overwritten(self):
  self.service.on_stop=lambda:self.unit.write_text('operator-new')
  with self.assertRaisesRegex(RuntimeError,'服务文件已变化'):self.run_upgrade()
  self.assertEqual(self.unit.read_text(),'operator-new')
  self.assertEqual((self.program/'V2bX').read_bytes(),b'old-executable')
  self.assertTrue(self.service.active())

if __name__=='__main__':unittest.main()
