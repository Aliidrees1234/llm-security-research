"""Tests for shield/jsbridge.py - the Python <-> shield-js bridge."""

import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from shield import jsbridge
from shield.jsbridge import JsBridgeError
from shield.reporter import Finding, ScanResult


def fake_run(returncode=0, stdout='', stderr=''):
    def _run(cmd, **kwargs):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr, cmd=cmd)
    return _run


@pytest.fixture
def has_cli(monkeypatch):
    monkeypatch.setattr(jsbridge, 'find_shield_js', lambda: ['shield-js'])


class TestFind:
    def test_env_var_pointing_at_repo_folder(self, tmp_path, monkeypatch):
        (tmp_path / 'src').mkdir()
        (tmp_path / 'src' / 'cli.js').write_text('')
        monkeypatch.setenv('SHIELD_JS_PATH', str(tmp_path))
        monkeypatch.setattr(shutil, 'which', lambda name: '/usr/bin/node' if name == 'node' else None)
        assert jsbridge.find_shield_js() == ['/usr/bin/node', str(tmp_path / 'src' / 'cli.js')]

    def test_env_var_pointing_at_cli_file(self, tmp_path, monkeypatch):
        cli = tmp_path / 'cli.js'
        cli.write_text('')
        monkeypatch.setenv('SHIELD_JS_PATH', str(cli))
        monkeypatch.setattr(shutil, 'which', lambda name: '/usr/bin/node' if name == 'node' else None)
        assert jsbridge.find_shield_js() == ['/usr/bin/node', str(cli)]

    def test_falls_back_to_path_lookup(self, monkeypatch):
        monkeypatch.delenv('SHIELD_JS_PATH', raising=False)
        monkeypatch.setattr(shutil, 'which', lambda name: '/usr/bin/shield-js' if name == 'shield-js' else None)
        assert jsbridge.find_shield_js() == ['/usr/bin/shield-js']

    def test_returns_none_when_missing(self, monkeypatch):
        monkeypatch.delenv('SHIELD_JS_PATH', raising=False)
        monkeypatch.setattr(shutil, 'which', lambda name: None)
        assert jsbridge.find_shield_js() is None

    def test_bad_env_path_is_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setenv('SHIELD_JS_PATH', str(tmp_path / 'nope'))
        monkeypatch.setattr(shutil, 'which', lambda name: None)
        assert jsbridge.find_shield_js() is None


class TestWantsJs:
    def test_detects_js_and_ts(self):
        assert jsbridge.wants_js(['python', 'javascript'])
        assert jsbridge.wants_js(['typescript'])

    def test_ignores_other_languages(self):
        assert not jsbridge.wants_js(['python', 'csharp', 'java'])
        assert not jsbridge.wants_js([])


class TestRun:
    def test_missing_cli_raises(self, monkeypatch):
        monkeypatch.setattr(jsbridge, 'find_shield_js', lambda: None)
        with pytest.raises(JsBridgeError, match='not found'):
            jsbridge.run_shield_js(['scan', '.'])

    def test_exit_code_1_means_findings_not_failure(self, has_cli, monkeypatch):
        monkeypatch.setattr(subprocess, 'run', fake_run(1, json.dumps({'findings': []})))
        assert jsbridge.run_shield_js(['scan', '.']) == {'findings': []}

    def test_exit_code_2_is_a_failure(self, has_cli, monkeypatch):
        monkeypatch.setattr(subprocess, 'run', fake_run(2, '', 'Path not found: x'))
        with pytest.raises(JsBridgeError, match='Path not found'):
            jsbridge.run_shield_js(['scan', 'x'])

    def test_invalid_json_raises(self, has_cli, monkeypatch):
        monkeypatch.setattr(subprocess, 'run', fake_run(0, 'not json'))
        with pytest.raises(JsBridgeError, match='invalid JSON'):
            jsbridge.run_shield_js(['scan', '.'])

    def test_timeout_raises(self, has_cli, monkeypatch):
        def boom(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 1)
        monkeypatch.setattr(subprocess, 'run', boom)
        with pytest.raises(JsBridgeError, match='timed out'):
            jsbridge.run_shield_js(['scan', '.'])


class TestScanAndFix:
    PAYLOAD = {
        'files': 2, 'loc': 10, 'errors': [{'file': 'bad.js', 'message': 'oops'}],
        'findings': [{'ruleId': 'SJS-003', 'severity': 'HIGH', 'cwe': 'CWE-95',
                      'message': 'eval', 'line': 3, 'file': 'src/a.js'}],
    }

    def test_scan_js_converts_findings(self, has_cli, monkeypatch):
        monkeypatch.setattr(subprocess, 'run', fake_run(1, json.dumps(self.PAYLOAD)))
        out = jsbridge.scan_js('src')
        f = out['findings'][0]
        assert isinstance(f, Finding)
        assert (f.rule_id, f.severity, f.cwe, f.line, f.source) == ('SJS-003', 'HIGH', '95', 3, 'shield-js')
        assert out['errors'][0]['file'] == 'bad.js'
        assert out['files'] == 2

    def test_scan_js_passes_json_flag(self, has_cli, monkeypatch):
        seen = {}
        def capture(cmd, **kwargs):
            seen['cmd'] = cmd
            return SimpleNamespace(returncode=0, stdout=json.dumps({'findings': []}), stderr='')
        monkeypatch.setattr(subprocess, 'run', capture)
        jsbridge.scan_js('src')
        assert seen['cmd'] == ['shield-js', 'scan', 'src', '--json']

    def test_fix_js_safe_mode_uses_output(self, has_cli, monkeypatch):
        seen = {}
        def capture(cmd, **kwargs):
            seen['cmd'] = cmd
            return SimpleNamespace(returncode=0, stdout=json.dumps({'fixed': 1}), stderr='')
        monkeypatch.setattr(subprocess, 'run', capture)
        assert jsbridge.fix_js('src', 'out') == {'fixed': 1}
        assert seen['cmd'] == ['shield-js', 'fix', 'src', '--json', '--output', 'out']

    def test_fix_js_inplace_omits_output(self, has_cli, monkeypatch):
        seen = {}
        def capture(cmd, **kwargs):
            seen['cmd'] = cmd
            return SimpleNamespace(returncode=0, stdout=json.dumps({'fixed': 0}), stderr='')
        monkeypatch.setattr(subprocess, 'run', capture)
        jsbridge.fix_js('src', 'out', inplace=True)
        assert '--inplace' in seen['cmd'] and '--output' not in seen['cmd']


    def test_fix_js_passes_excludes(self, has_cli, monkeypatch):
        seen = {}
        def capture(cmd, **kwargs):
            seen['cmd'] = cmd
            return SimpleNamespace(returncode=0, stdout=json.dumps({'fixed': 0}), stderr='')
        monkeypatch.setattr(subprocess, 'run', capture)
        jsbridge.fix_js('src', 'out', exclude=['a', 'b'])
        assert seen['cmd'][-4:] == ['--exclude', 'a', '--exclude', 'b']


class TestMerge:
    def test_adds_new_findings(self):
        result = ScanResult('.', loc=10)
        js = [Finding('SJS-001', 'HIGH', '94', 'debug', 'a.js', 1, source='shield-js')]
        added = jsbridge.merge_findings(result, js)
        assert len(added) == 1 and len(result.findings) == 1

    def test_skips_duplicates_on_same_file_and_line(self):
        result = ScanResult('.', loc=10)
        result.add_finding(Finding('eval-detected', 'HIGH', 'N/A', 'semgrep', 'a.js', 3, source='semgrep'))
        js = [Finding('SJS-003', 'HIGH', '95', 'eval', 'a.js', 3, source='shield-js'),
              Finding('SJS-001', 'HIGH', '94', 'debug', 'a.js', 4, source='shield-js')]
        added = jsbridge.merge_findings(result, js)
        assert [f.rule_id for f in added] == ['SJS-001']
        assert len(result.findings) == 2

    def test_does_not_add_the_same_finding_twice(self):
        result = ScanResult('.', loc=10)
        f = Finding('SJS-001', 'HIGH', '94', 'debug', 'a.js', 1, source='shield-js')
        jsbridge.merge_findings(result, [f, f])
        assert len(result.findings) == 1


@pytest.mark.skipif(jsbridge.find_shield_js() is None, reason='shield-js is not installed')
class TestIntegration:
    def test_real_scan_and_fix(self, tmp_path):
        (tmp_path / 'a.js').write_text("const DEBUG = true;\neval(x);\n")
        scan = jsbridge.scan_js(str(tmp_path))
        assert sorted(f.rule_id for f in scan['findings']) == ['SJS-001', 'SJS-003']

        fixed = jsbridge.fix_js(str(tmp_path), str(tmp_path / 'out'))
        assert fixed['fixed'] == 1
        assert fixed['after']['high'] == 1
        assert 'false' in (tmp_path / 'out' / 'a.js').read_text()
