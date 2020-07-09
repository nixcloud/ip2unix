import sys
import subprocess

from tempfile import NamedTemporaryFile

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


def test_rule_args_and_file():
    with NamedTemporaryFile('w') as rf:
        rf.write('in,port=1234,path=/foo\nout,path=/bar\n')
        rf.flush()
        cmd = [IP2UNIX, '-c', '-p', '-r', 'in,udp,addr=127.0.0.1,ignore',
               '-f', rf.name, '-r', 'out,addr=0.0.0.0,reject']
        result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)

    expected = b'Rule #1:\n' \
               b'  Direction: incoming\n' \
               b'  IP Type: UDP\n' \
               b'  Address: 127.0.0.1\n' \
               b'  Port: <any>\n' \
               b'  Don\'t handle this socket.\n' \
               b'Rule #2:\n' \
               b'  Direction: incoming\n' \
               b'  IP Type: TCP and UDP\n' \
               b'  Address: <any>\n' \
               b'  Port: 1234\n' \
               b'  Socket path: /foo\n' \
               b'Rule #3:\n' \
               b'  Direction: outgoing\n' \
               b'  IP Type: TCP and UDP\n' \
               b'  Address: <any>\n' \
               b'  Port: <any>\n' \
               b'  Socket path: /bar\n' \
               b'Rule #4:\n' \
               b'  Direction: outgoing\n' \
               b'  IP Type: TCP and UDP\n' \
               b'  Address: 0.0.0.0\n' \
               b'  Port: <any>\n' \
               b'  Reject connect() and bind() calls.\n'

    assert result.stdout == expected


def test_rule_longopts(tmpdir):
    stdout = subprocess.check_output([IP2UNIX, '-cp', '--rule', 'path=/test'])
    assert b"path: /test\n" in stdout


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
