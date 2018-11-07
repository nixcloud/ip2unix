import os
import socket
import subprocess
import sys

from helper import IP2UNIX

TESTPROG = r'''
import socket
import os

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(('4.3.2.1', 4321))
    sock.connect(('1.2.3.4', 1234))
    sock.sendall(b'hello')

# Deliberately keep the file descriptor open.
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('1.2.3.4', 1234))
assert sock.recv(5) == b'world'
'''


def test_wrong_unlink(tmpdir):
    sockfile_unlink = str(tmpdir.join('test_unlink.sock'))
    sockfile_nounlink = str(tmpdir.join('test_nounlink.sock'))

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(sockfile_nounlink)
        sock.listen(10)

        cmd = [IP2UNIX]
        cmd += ['-r', 'addr=4.3.2.1,path=' + sockfile_unlink]
        cmd += ['-r', 'addr=1.2.3.4,path=' + sockfile_nounlink]
        cmd += [sys.executable, '-c', TESTPROG]

        with subprocess.Popen(cmd, stdout=subprocess.PIPE) as client:
            with sock.accept()[0] as conn:
                assert conn.recv(5) == b'hello'
            with sock.accept()[0] as conn:
                conn.sendall(b'world')
            assert client.wait() == 0

        assert not os.path.exists(sockfile_unlink)
        assert os.path.exists(sockfile_nounlink)
