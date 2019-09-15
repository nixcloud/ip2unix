import os
import sys
import subprocess

import pytest

import helper


TESTPROG = r'''
import os
import socket
import sys

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    for i in range(20):
        sock.connect_ex(('127.0.0.1', 666))
    open_fds = set(os.listdir('/proc/self/fd/'))
    sys.stdout.write(str(len(open_fds)))
'''


@pytest.mark.skipif(not os.path.exists('/proc/self/fd'),
                    reason='requires procfs')
def test_fdleak():
    rules = [{'path': '/dev/null/not/existing', 'direction': 'outgoing'}]
    cmd = [sys.executable, '-c', TESTPROG]
    with helper.ip2unix(rules, cmd, stdout=subprocess.PIPE) as proc:
        stdout = proc.communicate()[0]
        num_fds = int(stdout.strip())
        assert num_fds <= 10
