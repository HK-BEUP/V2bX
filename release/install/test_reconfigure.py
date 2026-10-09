"""Synthetic inputs only. Never contacts panels or controls a host service."""
import contextlib
import fcntl
import io
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import initconfig as wizard
import upgrade


class Service:
    unit_path = 'etc/systemd/system/V2bX.service'
    def __init__(self, path, running=True):
        self.path = path
        self.running = running
        self.calls = []
        self.required_ports = {'old-port'}
        self.accept = [True]
        self.on_stop = self.on_start = None
    def active(self): return self.running
    def validate(self): self.calls.append('validate')
    def stop(self):
        self.calls.append('stop')
        if self.on_stop: self.on_stop()
        self.running = False
    def start(self):
        self.calls.append('start')
        self.running = True
        if self.on_start: self.on_start()
    def healthy(self):
        self.calls.append(('healthy', self.required_ports.copy()))
        return self.accept.pop(0) if len(self.accept) > 1 else self.accept[0]


class ReconfigureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root/'etc/V2bX/config.json'; self.path.parent.mkdir(parents=True)
        self.current = wizard.make_config('https://panel.example', 'synthetic-secret', '42,43')
        self.current['Cores'][0]['DnsConfigPath'] = '/etc/V2bX/dns.json'
        self.current['Nodes'][0]['SendIP'] = '192.0.2.5'
        self.current['Nodes'][0]['LegacyAccounting']['Directory'] = '/var/lib/custom-journal/42'
        self.path.write_text('// keep this comment on rollback\n' + json.dumps(self.current))
        self.path.chmod(0o640)
        (self.path.parent/'dns.json').write_text('{"servers":["tcp://192.0.2.53"]}')
        (self.path.parent/'route.json').write_text('{"rules":[]}')
        self.journal = self.root/'var/lib/custom-journal/42/pending.json'
        self.journal.parent.mkdir(parents=True); self.journal.write_bytes(b'synthetic-pending-traffic')
        self.binary = self.root/'usr/local/V2bX/V2bX'
        self.binary.parent.mkdir(parents=True); self.binary.write_bytes(b'synthetic-core')
        self.service = Service(self.path)
        self.unit = self.root/self.service.unit_path
        self.unit.parent.mkdir(parents=True); self.unit.write_text(upgrade.UNIT)
        self.before = upgrade.tree_hash(self.path.parent)
        self.output = io.StringIO()

    def run_wizard(self, answers=('', '42,44', 'YES'), key='', on_confirm=None):
        answers = iter(answers)
        def read(prompt):
            self.output.write(prompt + '\n')
            if '确认输入 YES' in prompt and on_confirm: on_confirm()
            return next(answers)
        with contextlib.redirect_stdout(self.output):
            return wizard.reconfigure(self.root, self.service, read, lambda _: key)

    def receipts(self):
        return [json.loads(p.read_text()) for p in (self.root/'etc/.backups/V2bX').glob('*/transaction.json')]

    def assert_preserved(self):
        self.assertEqual(self.journal.read_bytes(), b'synthetic-pending-traffic')
        self.assertEqual(self.binary.read_bytes(), b'synthetic-core')
        self.assertEqual(self.unit.read_text(), upgrade.UNIT)
        self.assertNotIn('synthetic-secret', self.output.getvalue())
        for name in ('dns.json', 'route.json'):
            self.assertEqual(upgrade.tree_hash(self.path.parent)[name], self.before[name])

    def test_running_reconfigure_backs_up_and_retains_custom_settings(self):
        original = self.path.read_bytes()
        self.service.on_stop = lambda: self.assertEqual(self.path.read_bytes(), original)
        result = self.run_wizard()
        new = upgrade.load_config(self.path)
        self.assertEqual([n['NodeID'] for n in new['Nodes']], [42,44])
        self.assertEqual(new['Cores'], self.current['Cores'])
        self.assertEqual(new['Nodes'][0], self.current['Nodes'][0])
        self.assertNotEqual(new['Nodes'][1]['LegacyAccounting']['Directory'], '/var/lib/custom-journal/42')
        self.assertEqual(self.service.calls, ['validate','stop','start',('healthy',set())])
        backup = Path(result['backup'])
        self.assertEqual((backup/'etc/V2bX/config.json').read_bytes(), original)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertEqual((backup/'etc/V2bX/config.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.service.running)
        self.assert_preserved()

    def test_stopped_save_does_not_start_enable_or_reload(self):
        self.service.running = False
        self.assertFalse(self.run_wizard()['restarted'])
        self.assertEqual(self.service.calls, ['validate'])
        self.assertFalse(self.service.running)
        self.assert_preserved()

    def test_cancel_keeps_exact_config_and_process(self):
        self.assertEqual(self.run_wizard(('', '42,44', 'no'))['status'], 'cancelled')
        self.assertEqual(upgrade.tree_hash(self.path.parent), self.before)
        self.assertEqual(self.service.calls, ['validate'])
        self.assertEqual(self.receipts(), [])

    def test_unchanged_skips_backup_and_service_validation(self):
        self.assertEqual(self.run_wizard(('', ''))['status'], 'unchanged')
        self.assertEqual(upgrade.tree_hash(self.path.parent), self.before)
        self.assertEqual(self.service.calls, [])
        self.assertEqual(self.receipts(), [])

    def test_bad_input_cannot_stop_or_write(self):
        for answers in [('http://panel.example',), ('', '0'), ('', '42,42')]:
            with self.subTest(answers=answers), self.assertRaises(ValueError): self.run_wizard(answers)
        self.assertEqual(self.service.calls, [])
        self.assertEqual(upgrade.tree_hash(self.path.parent), self.before)

    def test_eof_and_interrupt_before_confirmation_keep_running(self):
        for error in (EOFError, KeyboardInterrupt):
            with self.subTest(error=error), self.assertRaises(error):
                self.run_wizard(on_confirm=lambda: (_ for _ in ()).throw(error()))
        self.assertNotIn('stop', self.service.calls)
        self.assertEqual(upgrade.tree_hash(self.path.parent), self.before)

    def test_start_failure_restores_original_bytes_mode_and_ports(self):
        self.service.accept = [False, True]
        self.service.on_stop = None
        with self.assertRaisesRegex(RuntimeError, '原运行状态已恢复'): self.run_wizard()
        self.assertEqual(upgrade.tree_hash(self.path.parent), self.before)
        self.assertTrue(self.service.running)
        self.assertEqual(self.service.calls[-1], ('healthy', {'old-port'}))
        self.assertEqual(self.receipts()[0]['status'], 'rolled-back')
        self.assert_preserved()

    def test_interrupt_after_candidate_start_also_restores_original(self):
        def once():
            self.service.on_start = None
            raise KeyboardInterrupt()
        self.service.on_start = once
        with self.assertRaisesRegex(RuntimeError, '原运行状态已恢复'): self.run_wizard()
        self.assertEqual(upgrade.tree_hash(self.path.parent), self.before)
        self.assertTrue(self.service.running)

    def test_graceful_stop_failure_does_not_write_or_force_start(self):
        self.service.on_stop = lambda: (_ for _ in ()).throw(RuntimeError('tail not settled'))
        with self.assertRaisesRegex(RuntimeError, '自动回退未完成'): self.run_wizard()
        self.assertEqual(upgrade.tree_hash(self.path.parent), self.before)
        self.assertNotIn('start', self.service.calls)
        self.assertEqual(self.receipts()[0]['status'], 'manual-recovery-required')

    def test_operator_config_change_while_prompting_is_not_overwritten(self):
        def change(): self.path.write_text('operator change')
        with self.assertRaisesRegex(RuntimeError, '已变化'): self.run_wizard(on_confirm=change)
        self.assertEqual(self.path.read_text(), 'operator change')
        self.assertNotIn('stop', self.service.calls)

    def test_service_status_change_while_prompting_aborts(self):
        with self.assertRaisesRegex(RuntimeError, '服务状态已变化'):
            self.run_wizard(on_confirm=lambda: setattr(self.service,'running',False))
        self.assertNotIn('stop', self.service.calls)
        self.assertEqual(upgrade.tree_hash(self.path.parent), self.before)

    def test_program_change_while_prompting_aborts(self):
        with self.assertRaisesRegex(RuntimeError, '已变化'):
            self.run_wizard(on_confirm=lambda: self.binary.write_bytes(b'operator upgrade'))
        self.assertNotIn('stop', self.service.calls)

    def test_operator_change_during_stop_is_not_overwritten_or_started(self):
        self.service.on_stop = lambda: self.path.write_text('operator change')
        with self.assertRaisesRegex(RuntimeError, '自动回退未完成'): self.run_wizard()
        self.assertEqual(self.path.read_text(), 'operator change')
        self.assertNotIn('start', self.service.calls)

    def test_operator_change_during_failed_start_is_not_rolled_over(self):
        self.service.on_start = lambda: self.path.write_text('operator change')
        self.service.accept = [False]
        with self.assertRaisesRegex(RuntimeError, '自动回退未完成'): self.run_wizard()
        self.assertEqual(self.path.read_text(), 'operator change')
        self.assertEqual(self.service.calls.count('stop'), 1)

    def test_rollback_failure_is_explicit(self):
        self.service.accept = [False,False]
        with self.assertRaisesRegex(RuntimeError, '自动回退未完成'): self.run_wizard()
        self.assertEqual(upgrade.tree_hash(self.path.parent), self.before)
        self.assertEqual(self.receipts()[0]['status'], 'manual-recovery-required')

    def test_new_origin_never_reuses_other_panel_key(self):
        with self.assertRaises(ValueError): self.run_wizard(('https://other.example','42'))
        self.assertNotIn('stop', self.service.calls)

    def test_new_origin_uses_new_accounting_scope_with_explicit_key(self):
        self.run_wizard(('https://other.example','42','YES'), key='other-synthetic')
        node = upgrade.load_config(self.path)['Nodes'][0]
        self.assertEqual(node['ApiHost'], 'https://other.example')
        self.assertNotEqual(node['LegacyAccounting']['Directory'], '/var/lib/custom-journal/42')
        self.assert_preserved()

    def test_nested_node_format_retains_options(self):
        node = self.current['Nodes'][0]
        nested = {'ApiConfig':{k:node[k] for k in ('ApiHost','ApiKey','NodeID','NodeType')},
                  'Options':{k:v for k,v in node.items() if k not in ('ApiHost','ApiKey','NodeID','NodeType')}}
        old = dict(self.current, Nodes=[nested])
        result = wizard.replacement_config(old, 'https://panel.example','changed-synthetic','42')
        self.assertEqual(result['Nodes'][0]['Options'],nested['Options'])
        self.assertEqual(result['Nodes'][0]['ApiConfig']['ApiKey'],'changed-synthetic')
        self.assertEqual(old['Nodes'][0]['ApiConfig']['ApiKey'],'synthetic-secret')

    def test_transfer_mode_is_not_silently_converted(self):
        self.current['Nodes'][0]['TransferAccounting'] = {'Enabled':True}
        self.path.write_text(json.dumps(self.current))
        with self.assertRaises(ValueError): self.run_wizard()
        same = wizard.replacement_config(self.current,'https://panel.example','new-synthetic','42,43')
        self.assertEqual(same['Nodes'][0]['TransferAccounting'],{'Enabled':True})
        self.assertNotIn('stop',self.service.calls)

    def test_symlink_target_is_refused_without_mutating_service(self):
        dest = self.root/'secret-config'; self.path.rename(dest); self.path.symlink_to(dest)
        with self.assertRaises(ValueError): self.run_wizard()
        self.assertEqual(self.service.calls,[])

    def test_fresh_manual_configuration_stays_stopped_with_logs_off(self):
        self.path.unlink(); self.service.running = False
        self.run_wizard(('https://panel.example','9','YES'),key='synthetic-only')
        saved = upgrade.load_config(self.path)
        self.assertEqual(saved['Log']['Output'],'/dev/null')
        self.assertFalse(self.service.running)

    def test_automatic_init_guards_still_reject_running_or_existing_nodes(self):
        # Redirect only fixed filesystem paths and manager; exercise the actual CLI main.
        def path(value): return self.root/str(value).lstrip('/')
        real_open = open
        def opened(name,*args,**kwargs):
            return real_open(path(name) if str(name).startswith('/run/lock/') else name,*args,**kwargs)
        for running in (True,False):
            self.service.running = running
            with patch.object(wizard,'Path',side_effect=path),patch.object(wizard,'service_manager',return_value=self.service),patch.object(wizard.os,'geteuid',return_value=0),patch.object(wizard.os,'umask'),patch('builtins.open',side_effect=opened),patch('builtins.input',side_effect=AssertionError('automatic init must refuse')):
                with self.assertRaises(SystemExit): wizard.main()
        self.assertEqual(upgrade.tree_hash(self.path.parent),self.before)
        self.assertNotIn('stop',self.service.calls)

    def test_shell_menu_dispatches_explicit_manual_mode(self):
        shell = Path(__file__).with_name('V2bX.sh').read_text()
        function = shell.split('generate_config_file() {',1)[1].split('return $?',1)[0]
        code = 'python3() { printf "%s\\n" "$@"; }; generate_config_file() {' + function + '\n}; generate_config_file'
        run = subprocess.run(['bash','-c',code],check=True,capture_output=True,text=True)
        self.assertEqual(run.stdout.splitlines(),['/usr/local/V2bX/initconfig.py','--reconfigure'])
        self.assertIn('15) generate_config_file',shell)
        self.assertIn('"generate"|"init") generate_config_file',shell)

    def test_manual_cli_without_terminal_never_reconfigures(self):
        real_open = open
        def path(value): return self.root/str(value).lstrip('/')
        def opened(name,*args,**kwargs):
            return real_open(path(name) if str(name).startswith('/run/lock/') else name,*args,**kwargs)
        with patch.object(wizard,'Path',side_effect=path),patch.object(wizard,'service_manager',return_value=self.service),patch.object(wizard.os,'geteuid',return_value=0),patch.object(wizard.os,'umask'),patch('builtins.open',side_effect=opened),patch.object(wizard.sys.stdin,'isatty',return_value=False),patch.object(wizard,'reconfigure') as manual:
            with self.assertRaisesRegex(SystemExit,'交互终端'): wizard.main(manual=True)
            manual.assert_not_called()
        self.assertEqual(upgrade.tree_hash(self.path.parent),self.before)
        self.assertEqual(self.service.calls,[])

    def test_active_installer_lock_blocks_manual_cli(self):
        real_open = open
        def path(value): return self.root/str(value).lstrip('/')
        def opened(name,*args,**kwargs):
            return real_open(path(name) if str(name).startswith('/run/lock/') else name,*args,**kwargs)
        lock = self.root/'run/lock/beup-v2bx-upgrade.lock'; lock.parent.mkdir(parents=True)
        with real_open(lock,'w') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(wizard,'Path',side_effect=path),patch.object(wizard,'service_manager',return_value=self.service),patch.object(wizard.os,'geteuid',return_value=0),patch.object(wizard.os,'umask'),patch('builtins.open',side_effect=opened),patch.object(wizard.sys.stdin,'isatty',return_value=True),patch.object(wizard,'reconfigure') as manual:
                with self.assertRaises(BlockingIOError): wizard.main(manual=True)
                manual.assert_not_called()
        self.assertEqual(upgrade.tree_hash(self.path.parent),self.before)
        self.assertEqual(self.service.calls,[])


if __name__ == '__main__': unittest.main(verbosity=2)
