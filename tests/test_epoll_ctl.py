import subprocess
import sys

from helper import IP2UNIX

TESTPROG = '''
import socket
import select
import os

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    epoll = select.epoll()
    epoll.register(server.fileno(), select.EPOLLIN)

    # NOTE: Specifically bind/listen *after* adding the fds to epoll.
    server.bind(('1.2.3.4', 9191))
    server.listen(10)

    childpid = os.fork()
    if childpid == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(('1.2.3.4', 9191))
            sock.sendall(b'foobar\\n')
        raise SystemExit
    else:
        events = epoll.poll()
        assert len(events) == 1
        assert events[0][0] == server.fileno()
        with server.accept()[0] as conn:
            assert conn.recv(7) == b'foobar\\n'

status = os.WEXITSTATUS(os.waitpid(childpid, 0)[1])
print('all fine')
raise SystemExit(status)
'''


def test_epoll_ctl(tmpdir):
    sockfile = str(tmpdir.join('foo-%p.sock'))
    rules = ['-r', 'addr=1.2.3.4,port=9191,path=' + sockfile]
    cmd = [IP2UNIX] + rules + [sys.executable, '-c', TESTPROG]
    try:
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        print(e.output)
        raise
    assert b'all fine\n' == output
