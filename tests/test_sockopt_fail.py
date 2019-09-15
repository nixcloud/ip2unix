import sys

import helper


TESTPROG = r'''
import os
import socket
import sys

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN, 1)
    except:
        pass
    sock.bind(('1.2.3.4', 666))
    sock.listen(1)
'''


def test_setsockopt_fail(tmpdir):
    rules = [{'socketPath': str(tmpdir.join('foo.sock'))}]
    cmd = [sys.executable, '-c', TESTPROG]
    with helper.ip2unix(rules, cmd) as proc:
        assert proc.wait() == 0
