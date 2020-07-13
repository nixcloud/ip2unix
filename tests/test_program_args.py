import json
import sys
import subprocess

from helper import IP2UNIX, LIBIP2UNIX


def check_error(cmd):
    env = {'LANG': 'C'}
    with subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                          env=env) as proc:
        stdout, stderr = proc.communicate()
        assert len(stdout) == 0
        assert proc.poll() != 0
        return stderr


def test_show_usage():
    usage = subprocess.check_output([IP2UNIX, '-h'])
    assert usage.startswith(b'Usage:')


def test_unknown_arg():
    assert b'invalid option' in check_error([IP2UNIX, '-X'])


def test_rules_and_rulefile():
    stderr = check_error([IP2UNIX, '-r', 'path=/foo', '-f', '/nonexistent'])
    assert b"Can't specify both" in stderr


def test_rulefile_and_ruledata():
    stderr = check_error([IP2UNIX, '-f', '/nonexistent', '-F', '{}'])
    assert b"rule file path and inline rules at the same time" in stderr


def test_rule_longopts(tmpdir):
    rulesfile = str(tmpdir.join('rules.yml'))
    rulesdata = json.dumps([{'socketPath': '/test'}])
    open(rulesfile, 'w').write(rulesdata)
    for deprecated_cmd in [
        [IP2UNIX, '-cp', '--rules-file', rulesfile],
        [IP2UNIX, '-cp', '--rules-data', rulesdata],
    ]:
        stdout = subprocess.check_output(deprecated_cmd,
                                         stderr=subprocess.STDOUT)
        assert b"is deprecated" in stdout
        assert b"path: /test (will" in stdout

    stdout = subprocess.check_output([IP2UNIX, '-cp', '--rule', 'path=/test'])
    assert b"path: /test (will" in stdout


def test_no_program():
    stderr = check_error([IP2UNIX, '-r', 'path=/foo'])
    assert b"No program to execute" in stderr


def test_no_rules():
    stderr = check_error([IP2UNIX, '/nonexistent'])
    assert b"either specify a rule" in stderr


def test_exec_fail():
    stderr = check_error([IP2UNIX, '-r', 'path=/foo', '/nonexistent'])
    assert b"No such file or directory" in stderr


def test_version_longopt():
    stdout = subprocess.check_output([IP2UNIX, '--version'])
    assert b"This program is free software" in stdout


def test_version_shortopt_fail():
    stderr = check_error([IP2UNIX, '-V'])
    assert b"invalid option" in stderr


def test_existing_ld_preload():
    testprog = "import os; print(os.environ['LD_PRELOAD'])"
    cmd = [IP2UNIX, '-r', 'path=/foo', sys.executable, '-c', testprog]
    output = subprocess.check_output(cmd, env={'LD_PRELOAD': '/nonexistent'})
    expect = LIBIP2UNIX + ":/nonexistent"
    assert output.decode().strip() == expect
