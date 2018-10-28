import pickle
import socket
import struct
import subprocess
import sys

from helper import IP2UNIX

TESTPROG = '''
import os
import pickle
import socket
import sys

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
    server.bind(('a123::321a', 1234))
    server.listen(10)

    childpid = os.fork()
    if childpid == 0:
        # Yes, using IPv4 is intentional here!
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(('9.8.7.6', 9616))
            client.sendall(pickle.dumps({
                'peername': client.getpeername(),
                'sockname': client.getsockname(),
            }))
        raise SystemExit

    conn, addrinfo = server.accept()
    with conn:
        server_info = {
            'addrinfo': addrinfo,
            'peername': conn.getpeername(),
            'sockname': conn.getsockname(),
        }
        data = b''
        while True:
            buf = conn.recv(1024)
            if len(buf) == 0:
                break
            data += buf
        client_info = pickle.loads(data)

    status = os.WEXITSTATUS(os.waitpid(childpid, 0)[1])

    server_info['pid'] = os.getpid()
    client_info['pid'] = childpid

    sys.stdout.buffer.write(pickle.dumps({
        'uid': os.getuid(),
        'gid': os.getgid(),
        'client': client_info,
        'server': server_info,
    }))

    raise SystemExit(status)
'''


def test_addrinfo(tmpdir):
    sockfile = str(tmpdir.join('test.sock'))
    cmd = [IP2UNIX, '-r', 'path=' + sockfile, sys.executable, '-c', TESTPROG]
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    assert result.returncode == 0
    info = pickle.loads(result.stdout)

    # The more obvious cases, where we should get back what we threw in.
    assert info['client']['peername'] == ('9.8.7.6', 9616)
    assert info['server']['sockname'] == ('a123::321a', 1234, 0, 0)
    assert info['server']['addrinfo'] == info['server']['peername']

    # Ephemeral ports have to be 1024 or higher.
    assert info['client']['sockname'][1] >= 1024
    assert info['server']['peername'][1] >= 1024
    assert info['server']['addrinfo'][1] >= 1024

    # On the client side, our own address is the pid of the client.
    addr = info['client']['sockname'][0]
    intaddr = struct.unpack('!I', socket.inet_aton(addr))[0]
    assert intaddr == info['client']['pid']

    # The server's peer address always starts with "fe80::" but we're only
    # testing for "fe80:" to make sure it's not expanded.
    addr = info['server']['peername'][0]
    assert addr.startswith('fe80:')

    # User ID is the second 32 bit word.
    binaddr = socket.inet_pton(socket.AF_INET6, addr)
    addr_uid = struct.unpack('!I', binaddr[4:8])[0]
    assert addr_uid == info['uid']

    # Group ID is the third 32 bit word.
    binaddr = socket.inet_pton(socket.AF_INET6, addr)
    addr_gid = struct.unpack('!I', binaddr[8:12])[0]
    assert addr_gid == info['gid']

    # PID is the last 32 bit word.
    binaddr = socket.inet_pton(socket.AF_INET6, addr)
    addr_pid = struct.unpack('!I', binaddr[12:16])[0]
    assert addr_pid == info['client']['pid']
