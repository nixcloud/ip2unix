import subprocess
import sys

from helper import IP2UNIX

TESTPROG = '''
import array
import fcntl
import socket
import termios
import time
import signal
import os

rsync, wsync = os.pipe()

# We fork here so that we can directly establish a connection to the master
# signalled by SIGIO, which is the *same* signal used by FIOASYNC. The reason
# is that we want to make sure that F_SETOWN works correctly.
childpid = os.fork()
if childpid == 0:
    def connector(signum, frame):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.connect(('dead::beef', 6666))
            assert sock.recv(7) == b'foobar\\n'
            sock.sendall(b'got it\\n')
            raise SystemExit

    signal.signal(signal.SIGIO, connector)
    os.write(wsync, b'X')
    for i in range(1000):
        time.sleep(0.1)

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
    try:
        def acceptor(signum, frame):
            with sock.accept()[0] as conn:
                conn.sendall(b'foobar\\n')
                assert conn.recv(7) == b'got it\\n'

        signal.signal(signal.SIGIO, acceptor)

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        fcntl.fcntl(sock.fileno(), fcntl.F_SETOWN, os.getpid())

        flag = array.array('h', [1])
        fcntl.ioctl(sock.fileno(), termios.FIOASYNC, flag)

        sock.bind(('dead::beef', 6666))
        sock.listen(10)

        os.read(rsync, 1)
        os.kill(childpid, signal.SIGIO)

        status = os.WEXITSTATUS(os.waitpid(childpid, 0)[1])
        print("all fine")
        raise SystemExit(status)
    finally:
        try:
            os.kill(childpid, signal.SIGKILL)
        except:
            pass
'''


def test_sockserver(tmpdir):
    sockfile = str(tmpdir.join('foo.sock'))
    rules = ['-r', 'out,addr=dead::beef,path=' + sockfile,
             '-r', 'in,tcp,path=' + sockfile]
    cmd = [IP2UNIX] + rules + [sys.executable, '-c', TESTPROG]
    try:
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        print(e.output)
        raise
    assert b'all fine\n' == output
