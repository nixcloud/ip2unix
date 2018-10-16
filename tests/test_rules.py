import subprocess
import sys
import unittest

from helper import ip2unix, ip2unix_check, systemd_only, non_systemd_only


class RulesTest(unittest.TestCase):
    def assert_good_rules(self, rules):
        code, output = ip2unix_check(rules)
        msg = 'Rules {!r} do not validate: {}'.format(rules, output.rstrip())
        self.assertTrue(code, msg)

    def assert_bad_rules(self, rules):
        code, output = ip2unix_check(rules)
        msg = 'Rules {!r} should not be valid.'.format(rules)
        self.assertFalse(code, msg)

    def test_no_array(self):
        self.assert_bad_rules({'rule1': {'socketPath': '/foo'}})
        self.assert_bad_rules({'rule2': {}})
        self.assert_bad_rules({})

    def test_empty(self):
        self.assert_good_rules([])

    def test_complete_rules(self):
        self.assert_good_rules([
            {'direction': 'outgoing',
             'type': 'udp',
             'socketPath': '/tmp/foo'},
            {'direction': 'incoming',
             'address': '::',
             'socketPath': '/tmp/bar'}
        ])

    def test_unknown_rule_attrs(self):
        self.assert_bad_rules([{'foo': 1}])
        self.assert_bad_rules([{'socketpath': 'xxx'}])

    def test_wrong_rule_types(self):
        self.assert_bad_rules([{'type': 'nope', 'socketPath': '/tmp/foo'}])
        self.assert_bad_rules([{'direction': 'out', 'socketPath': '/tmp/foo'}])
        self.assert_bad_rules([{'socketPath': 1234}])

    def test_no_socket_path(self):
        self.assert_bad_rules([{'address': '1.2.3.4'}])

    def test_relative_socket_path(self):
        self.assert_bad_rules([{'socketPath': 'aaa/bbb'}])
        self.assert_bad_rules([{'socketPath': 'bbb'}])

    def test_absolute_socket_path(self):
        self.assert_good_rules([{'socketPath': '/xxx'}])

    def test_invalid_enums(self):
        self.assert_bad_rules([{'socketPath': '/bbb', 'direction': 111}])
        self.assert_bad_rules([{'socketPath': '/bbb', 'direction': False}])
        self.assert_bad_rules([{'socketPath': '/bbb', 'type': 234}])
        self.assert_bad_rules([{'socketPath': '/bbb', 'type': True}])

    def test_invalid_port_type(self):
        self.assert_bad_rules([{'socketPath': '/aaa', 'port': 'foo'}])
        self.assert_bad_rules([{'socketPath': '/aaa', 'port': True}])
        self.assert_bad_rules([{'socketPath': '/aaa', 'port': -1}])
        self.assert_bad_rules([{'socketPath': '/aaa', 'port': 65536}])

    @systemd_only
    def test_contradicting_socket_options(self):
        self.assert_bad_rules([
            {'socketPath': '/foo', 'socketActivation': True}
        ])

    @systemd_only
    def test_socket_fdname(self):
        self.assert_good_rules([{'socketActivation': True, 'fdName': 'foo'}])

    @non_systemd_only
    def test_no_systemd_options(self):
        self.assert_bad_rules([{'socketActivation': True}])
        self.assert_bad_rules([{'socketActivation': True, 'fdName': 'foo'}])

    def test_print_rules_check_stdout(self):
        rules = [
            {'direction': 'outgoing',
             'type': 'tcp',
             'socketPath': '/foo'},
            {'address': '0.0.0.0',
             'socketPath': '/bar'}
        ]
        with ip2unix(rules, [], stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                     ip2unix_args=['-cp']) as process:
            stdout, stderr = process.communicate()
            self.assertEqual(process.poll(), 0)
            self.assertEqual(stderr, b'')
            self.assertNotEqual(stdout, b'')
            self.assertGreater(len(stdout), 0)
            self.assertIn(b'IP Type', stdout)

    def test_print_rules_stderr(self):
        rules = [{'socketPath': '/xxx'}]
        dummy = [sys.executable, '-c', '']
        with ip2unix(rules, dummy, stderr=subprocess.PIPE,
                     stdout=subprocess.PIPE, ip2unix_args=['-p']) as process:
            stdout, stderr = process.communicate()
            self.assertEqual(process.poll(), 0)
            self.assertEqual(stdout, b'')
            self.assertNotEqual(stderr, b'')
            self.assertGreater(len(stderr), 0)
            self.assertIn(b'IP Type', stderr)
