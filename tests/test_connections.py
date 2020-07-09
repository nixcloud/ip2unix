import helper
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from contextlib import contextmanager

CURDIR = os.path.dirname(os.path.abspath(__file__))
CONNECTOR = os.path.join(CURDIR, 'connector.py')


class TcpConnectionTest(unittest.TestCase):
    SOTYPE = 'tcp'

    def assert_client(self, rules, *args):
        cmd = [sys.executable, CONNECTOR] + list(map(str, args))
        cmd += ['-t', self.SOTYPE]
        with helper.ip2unix(rules, cmd, stderr=subprocess.STDOUT,
                            stdout=subprocess.PIPE) as process:
            stdout = process.communicate()[0]
            msg = 'Client did not return successful:\n' + stdout.decode()
            self.assertEqual(process.poll(), 0, msg)

    @contextmanager
    def run_server(self, rules, *args, **kwargs):
        pre_cmd = kwargs.pop('pre_cmd', None)
        sync = kwargs.pop('sync', False)
        cmd = [sys.executable, CONNECTOR, '-l'] + list(map(str, args))
        cmd += ['-t', self.SOTYPE]
        with helper.ip2unix(rules, cmd, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            pre_cmd=pre_cmd) as proc:
            if sync:
                sync_event = proc.stdout.read(6)
                if sync_event == b'READY:':
                    portstr = proc.stdout.read(6)
                    assert portstr.endswith(b'\n'), \
                        "Sync event must end with newline."
                    port = int(portstr)
                    yield port
                else:
                    expected = b'READY\n'
                    if sync_event != expected:
                        stderr = proc.communicate()[1]
                        msg = 'Wrong sync event from server, expected '
                        msg += '{} but got {}:\n'.format(expected, sync_event)
                        msg += stderr.decode()
                        raise AssertionError(msg)
                    yield proc
            else:
                yield proc
            proc.stdin.write(b'\n')

    def assert_connection(self, crule, srule, cargs, sargs, pre_cmd_srv=None):
        client_rule = {'dir': 'out', 'path': self.sockpath}
        client_rule.update(crule)
        if 'systemd' in srule:
            sync = False
            server_rule = dict(srule)
        else:
            sync = True
            server_rule = {'path': self.sockpath}
            server_rule.update(srule)
        with self.run_server([server_rule], *sargs, pre_cmd=pre_cmd_srv,
                             sync=sync):
            self.assert_client([client_rule], *cargs)

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sockpath = os.path.join(self.tmpdir, 'test.sock')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_simple(self):
        args = ['1.2.3.4', 123]
        self.assert_connection({}, {}, args, args)

    def test_simple_threaded(self):
        args = ['-m', 'threading', '1.2.3.4', 123]
        self.assert_connection({}, {}, args, args)

    def test_several(self):
        args = ['-p', 10, '-c', 20, '1.2.3.4', 123]
        self.assert_connection({}, {}, args, args)

    def test_several_threaded(self):
        args = ['-m', 'threading', '-p', 10, '-c', 20, '1.2.3.4', 123]
        self.assert_connection({}, {}, args, args)

    def test_path_placeholders(self):
        args = ['127.0.0.1', 111]
        srule = {'path': os.path.join(self.tmpdir, '%a-%t-%p.sock')}
        clipath = '127.0.0.1-' + self.SOTYPE + '-111.sock'
        crule = {'path': os.path.join(self.tmpdir, clipath)}
        self.assert_connection(crule, srule, args, args)

    def test_nomatch(self):
        rules = [{'ignore': True}]
        with self.run_server(rules, '127.0.0.1', 0, sync=True) as port:
            self.assert_client(rules, '127.0.0.1', port)

    @helper.systemd_sa_helper_only
    def test_socket_activation(self):
        srule = {'systemd': True}
        args = ['-c', 10, '4.3.2.1', 321]
        pre_cmd = [helper.SYSTEMD_SA_PATH, '-l', self.sockpath]
        if self.SOTYPE == 'udp':
            pre_cmd.append('-d')
        self.assert_connection({}, srule, args, args, pre_cmd_srv=pre_cmd)

    @helper.systemd_sa_helper_only
    def test_socket_activation_threaded(self):
        srule = {'systemd': True}
        args = ['-m', 'threading', '-p', 10, '-c', 20, '4.3.2.1', 321]
        pre_cmd = [helper.SYSTEMD_SA_PATH, '-l', self.sockpath]
        if self.SOTYPE == 'udp':
            pre_cmd.append('-d')
        self.assert_connection({}, srule, args, args, pre_cmd_srv=pre_cmd)

    @helper.systemd_sa_helper_only
    def test_socket_activation_with_fdname(self):
        srule = {'systemd': 'foo', 'port': 333}
        args = ['-c', 10, '4.3.2.1', 333]
        extrasock = os.path.join(self.tmpdir, 'extra.sock')
        pre_cmd = [helper.SYSTEMD_SA_PATH, '-l', extrasock]
        if self.SOTYPE == 'udp':
            pre_cmd.append('-d')
        pre_cmd += ['-l', self.sockpath, '--fdname=:foo']
        try:
            self.assert_connection({}, srule, args, args, pre_cmd_srv=pre_cmd)
        finally:
            os.unlink(extrasock)


class UdpConnectionTest(TcpConnectionTest):
    SOTYPE = 'udp'
