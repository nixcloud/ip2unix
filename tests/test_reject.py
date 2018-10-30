import subprocess
import sys

from helper import IP2UNIX

TESTPROG = '''
import socket
import errno

from contextlib import contextmanager

@contextmanager
def assert_reject(errno):
    try:
        yield
    except OSError as e:
        assert e.errno == errno, '{} != {}'.format(e.errno, errno)
        return
    raise AssertionError("not risen")

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    with assert_reject(errno.EPERM):
        server.bind(('127.0.0.1', 1234))

    with assert_reject(errno.EPERM):
        server.connect(('127.0.0.1', 1234))

with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server:
    with assert_reject(errno.EACCES):
        server.bind(('1234::1', 1234))

    with assert_reject(errno.EACCES):
        server.connect(('1234::1', 1234))
'''


def test_reject():
    rules = ['-r', 'addr=1234::1,reject', '-r', 'reject=eperm']
    cmd = [IP2UNIX] + rules + [sys.executable, '-c', TESTPROG]
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    assert result.returncode == 0
