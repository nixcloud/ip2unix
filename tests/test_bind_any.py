import subprocess
import sys

from helper import IP2UNIX

TESTPROG = '''
import socket
import os

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind(('1.2.3.4', 0))
    server.listen(10)
    srvport = server.getsockname()[1]
    assert srvport != 0, srvport

    childpid = os.fork()
    if childpid == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(('1.2.3.4', srvport))
            sock.sendall(b'foobar\\n')
        raise SystemExit
    else:
        with server.accept()[0] as conn:
            assert conn.recv(7) == b'foobar\\n'

status = os.WEXITSTATUS(os.waitpid(childpid, 0)[1])
print('all fine')
raise SystemExit(status)
'''


def test_sockserver(tmpdir):
    sockfile = str(tmpdir.join('foo-%p.sock'))
    rules = ['-r', 'addr=1.2.3.4,path=' + sockfile]
    cmd = [IP2UNIX] + rules + [sys.executable, '-c', TESTPROG]
    try:
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        print(e.output)
        raise
    assert b'all fine\n' == output
