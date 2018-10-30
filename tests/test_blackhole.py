import subprocess
import sys

from helper import IP2UNIX

TESTPROG = r'''
import socket
import os

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server1, \
     socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server2:
    server1.bind(('127.0.0.1', 6789))
    server1.listen()
    server2.bind(('127.0.0.1', 5678))
    server2.listen()

    childpid = os.fork()
    if childpid == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(('127.0.0.1', 6789))
            client.sendall(b'hello not blackhole')
        raise SystemExit

    with server2.accept()[0] as conn:
        assert conn.recv(19) == b'hello not blackhole'

status = os.WEXITSTATUS(os.waitpid(childpid, 0)[1])
'''


def test_blackhole(tmpdir):
    sockfile = str(tmpdir.join('test.sock'))
    rules = ['-r', 'in,port=6789,blackhole', '-r', 'path=' + sockfile]
    cmd = [IP2UNIX] + rules + [sys.executable, '-c', TESTPROG]
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    assert result.returncode == 0
