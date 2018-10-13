import helper
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from contextlib import contextmanager

CURDIR = os.path.dirname(os.path.abspath(__file__))
CONNECTOR = os.path.join(CURDIR, 'connector.py')


class ConnectionTest(unittest.TestCase):
    def assert_client(self, rules, *args):
        cmd = [sys.executable, CONNECTOR] + list(map(str, args))
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
        with helper.ip2unix(rules, cmd, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            pre_cmd=pre_cmd) as proc:
            if sync:
                sync_event = proc.stdout.read(6)
                expected = b'READY\n'
                if sync_event != expected:
                    stderr = proc.communicate()[1]
                    msg = 'Wrong sync event from server, expected '
                    msg += '{} but got {}:\n'.format(expected, sync_event)
                    msg += stderr.decode()
                    raise AssertionError(msg)
            else:
                while not os.path.exists(self.sockpath):
                    time.sleep(0.1)
            yield proc
            proc.stdin.write(b'\n')

    def assert_connection(self, crule, srule, cargs, sargs, pre_cmd_srv=None):
        client_rule = {'direction': 'outgoing', 'socketPath': self.sockpath}
        client_rule.update(crule)
        if 'socketActivation' in srule:
            sync = False
            server_rule = dict(srule)
        else:
            sync = True
            server_rule = {'socketPath': self.sockpath}
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

    @helper.systemd_sa_helper_only
    def test_socket_activation(self):
        srule = {'socketActivation': True}
        args = ['-c', 10, '4.3.2.1', 321]
        pre_cmd = [helper.SYSTEMD_SA_PATH, '-l', self.sockpath]
        self.assert_connection({}, srule, args, args, pre_cmd_srv=pre_cmd)

    @helper.systemd_sa_helper_only
    def test_socket_activation_with_fdname(self):
        srule = {'socketActivation': True, 'fdName': 'foo', 'port': 333}
        args = ['-c', 10, '4.3.2.1', 333]
        extrasock = os.path.join(self.tmpdir, 'extra.sock')
        pre_cmd = [helper.SYSTEMD_SA_PATH, '-l', extrasock,
                   '-l', self.sockpath, '--fdname=:foo']
        try:
            self.assert_connection({}, srule, args, args, pre_cmd_srv=pre_cmd)
        finally:
            os.unlink(extrasock)
