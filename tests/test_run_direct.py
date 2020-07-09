import subprocess
import sys

import helper


TESTPROG = r'''
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect(('127.0.0.1', 9999))
    sock.sendall(b'foobar')
    assert sock.recv(6) == b'barfoo'
'''


def test_run_direct_fail():
    cmd = [sys.executable, '-c', TESTPROG]
    env = {'LD_PRELOAD': helper.LIBIP2UNIX}

    with subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as proc:
        stdout, stderr = proc.communicate()
        assert stderr.startswith(b'ip2unix FATAL:')
        assert proc.poll() != 0


def test_run_direct_invalid_rules():
    cmd = [sys.executable, '-c', TESTPROG]
    env = {'LD_PRELOAD': helper.LIBIP2UNIX, '__IP2UNIX_RULES': '{'}

    with subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as proc:
        stdout, stderr = proc.communicate()
        assert b'Invalid character' in stderr
        assert proc.poll() != 0
