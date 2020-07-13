import sys
import subprocess
import socket

from helper import IP2UNIX

TESTPROG = r'''
import os
import sys
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('1.2.3.4', 1234))
sock.listen(10)

childpid = os.fork()
if childpid == 0:
    os.closerange(3, 65536)
    raise SystemExit

assert os.WEXITSTATUS(os.waitpid(childpid, 0)[1]) == 0

sys.stdout.write('ready\n')
sys.stdout.flush()

with sock.accept()[0] as conn:
    assert conn.recv(3) == b'foo'
'''


def test_preliminary_unlink(tmpdir):
    """
    Regression test for https://github.com/nixcloud/ip2unix/issues/16
    """
    sockfile = str(tmpdir.join('test.sock'))

    cmd = [
        IP2UNIX, '-r', 'port=1234,addr=1.2.3.4,noremove,path=' + sockfile,
        sys.executable, '-c', TESTPROG,
    ]

    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as client:
        assert client.stdout.readline() == b'ready\n'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(sockfile)
            sock.sendall(b'foo')
        assert client.wait() == 0
