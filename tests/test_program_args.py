import sys
import subprocess

from helper import IP2UNIX


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


def test_no_program():
    stderr = check_error([IP2UNIX, '-r', 'path=/foo'])
    assert b"No program to execute" in stderr


def test_no_rules():
    stderr = check_error([IP2UNIX, '/nonexistent'])
    assert b"either specify a rule" in stderr


def test_exec_fail():
    stderr = check_error([IP2UNIX, '-r', 'path=/foo', '/nonexistent'])
    assert b"No such file or directory" in stderr


def test_existing_ld_preload():
    testprog = "import os; print(os.environ['LD_PRELOAD'])"
    cmd = [IP2UNIX, '-r', 'path=/foo', sys.executable, '-c', testprog]
    output = subprocess.check_output(cmd, env={'LD_PRELOAD': '/nonexistent'})
    expect = IP2UNIX + ":/nonexistent"
    assert output.decode().strip() == expect
