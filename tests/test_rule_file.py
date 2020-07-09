import subprocess
import sys
import unittest

from tempfile import NamedTemporaryFile

from helper import IP2UNIX, dict_to_rule, systemd_only, non_systemd_only


class RuleFileTest(unittest.TestCase):
    def assert_good_rules(self, rules):
        with NamedTemporaryFile('w') as rf:
            for rule in rules:
                rf.write(dict_to_rule(rule) + '\n')
            rf.flush()

            cmd = [IP2UNIX, '-c', '-f', rf.name]
            result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
        msg = 'Rules {!r} do not validate: {}'.format(rules, result.stdout)
        self.assertEqual(result.returncode, 0, msg)

    def assert_bad_rules(self, rules):
        with NamedTemporaryFile('w') as rf:
            for rule in rules:
                rf.write(dict_to_rule(rule) + '\n')
            rf.flush()

            cmd = [IP2UNIX, '-c', '-f', rf.name]
            result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
        msg = 'Rules {!r} should not be valid.'.format(rules)
        self.assertNotEqual(result.returncode, 0, msg)

    def test_empty(self):
        self.assert_bad_rules([])

    def test_complete_rules(self):
        self.assert_good_rules([
            {'dir': 'out', 'type': 'udp', 'path': '/tmp/foo'},
            {'dir': 'in', 'addr': '::', 'path': '/tmp/bar'}
        ])

    def test_unknown_rule_attrs(self):
        self.assert_bad_rules([{'foo': 1}])
        self.assert_bad_rules([{'sockpath': 'xxx'}])

    def test_wrong_rule_types(self):
        self.assert_bad_rules([{'type': 'nope', 'path': '/tmp/foo'}])
        self.assert_bad_rules([{'dir': 'outgoing', 'path': '/tmp/foo'}])
        self.assert_bad_rules([{'path': True}])

    def test_no_socket_path(self):
        self.assert_bad_rules([{'addr': '1.2.3.4'}])

    def test_invalid_enums(self):
        self.assert_bad_rules([{'path': '/bbb', 'dir': '111'}])
        self.assert_bad_rules([{'path': '/bbb', 'dir': ''}])
        self.assert_bad_rules([{'path': '/bbb', 'type': '234'}])
        self.assert_bad_rules([{'path': '/bbb', 'type': 'true'}])

    def test_invalid_port_type(self):
        self.assert_bad_rules([{'path': '/aaa', 'port': 'foo'}])
        self.assert_bad_rules([{'path': '/aaa', 'port': 'True'}])
        self.assert_bad_rules([{'path': '/aaa', 'port': '-1'}])
        self.assert_bad_rules([{'path': '/aaa', 'port': '65536'}])

    def test_port_range(self):
        self.assert_good_rules([{'path': '/aaa', 'port': '123-124'}])
        self.assert_good_rules([{'path': '/aaa', 'port': '1000-65535'}])

    def test_invalid_port_range(self):
        self.assert_bad_rules([{'path': '/aaa', 'port': '123-10'}])
        self.assert_bad_rules([{'path': '/aaa', 'port': '123-123'}])
        self.assert_bad_rules([{'path': '/aaa', 'port': '123-65536'}])

    def test_missing_start_port_in_range(self):
        self.assert_bad_rules([{'path': '/aaa', 'port': '-123'}])

    def test_valid_address(self):
        valid_addrs = [
            '127.0.0.1', '0.0.0.0', '9.8.7.6', '255.255.255.255', '::',
            '::ffff:127.0.0.1', '7:6:5:4:3:2:1::', '::7:6:5:4:3:2:1',
            '7::', '::2:1', '::17', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        ]
        for addr in valid_addrs:
            self.assert_good_rules([{'path': '/foo', 'addr': addr}])

    def test_invalid_addrss(self):
        invalid_addrs = [
            '.0.0.1', '123', '123.', '..', '-1.2.3.4', '256.255.255.255', ':::'
            '0.00.0.0', '1.-2.3.4', 'abcde', '::-1', '01000::', 'abcd::efgh'
            '8:7:6:5:4:3:2:1::', '::8:7:6:5:4:3:2:1', 'f:f11::01100:2'
        ]
        for addr in invalid_addrs:
            self.assert_bad_rules([{'path': '/foo', 'addr': addr}])

    def test_valid_reject(self):
        for val in ["EBADF", "EINTR", "enomem", "EnOMeM", 13, 12]:
            self.assert_good_rules([{'reject': val}])

    def test_invalid_reject(self):
        for val in ["EBAAAADF", "", "XXX", "vvv", -10]:
            self.assert_bad_rules([{'reject': val}])

    def test_reject_with_sockpath(self):
        self.assert_bad_rules([{'path': '/foo', 'reject': True}])

    def test_blackhole_with_reject(self):
        self.assert_bad_rules([{'dir': 'in', 'reject': True,
                                'blackhole': True}])

    def test_blackhole_outgoing(self):
        self.assert_bad_rules([{'blackhole': True}])
        self.assert_bad_rules([{'dir': 'out', 'blackhole': True}])

    def test_blackhole_with_sockpath(self):
        self.assert_bad_rules([{'dir': 'in', 'path': '/foo',
                                'blackhole': True}])

    def test_blackhole_all(self):
        self.assert_good_rules([{'dir': 'in', 'blackhole': True}])

    def test_ignore_with_sockpath(self):
        self.assert_bad_rules([{'path': '/foo', 'ignore': True}])

    def test_ignore_with_reject(self):
        self.assert_bad_rules([{'reject': True, 'ignore': True}])

    def test_ignore_with_blackhole(self):
        self.assert_bad_rules([{'blackhole': True, 'ignore': True}])

    @systemd_only
    def test_ignore_with_systemd(self):
        self.assert_bad_rules([{'socketActivation': True, 'ignore': True}])

    @systemd_only
    def test_contradicting_systemd(self):
        self.assert_bad_rules([{'path': '/foo',
                                'socketActivation': True}])

    @systemd_only
    def test_socket_fdname(self):
        self.assert_good_rules([{'systemd': 'foo'}])

    @non_systemd_only
    def test_no_systemd_options(self):
        self.assert_bad_rules([{'systemd': True}])
        self.assert_bad_rules([{'systemd': 'foo'}])

    def test_print_rules_check_stdout(self):
        rules = [
            {'dir': 'out', 'type': 'tcp', 'path': '/foo'},
            {'addr': '0.0.0.0', 'path': '/bar'}
        ]
        with NamedTemporaryFile('w') as rf:
            for rule in rules:
                rf.write(dict_to_rule(rule) + '\n')
            rf.flush()

            cmd = [IP2UNIX, '-cp', '-f', rf.name]
            result = subprocess.run(cmd, stderr=subprocess.PIPE,
                                    stdout=subprocess.PIPE)
        self.assertEqual(result.returncode, 0)
        self.assertNotEqual(result.stdout, b'')
        self.assertGreater(len(result.stdout), 0)
        self.assertIn(b'IP Type', result.stdout)

    def test_print_rules_stderr(self):
        with NamedTemporaryFile('w') as rf:
            rf.write('path=/xxx\n')
            rf.flush()
            cmd = [IP2UNIX, '-p', '-f', rf.name, sys.executable, '-c', '']
            result = subprocess.run(cmd, stderr=subprocess.PIPE,
                                    stdout=subprocess.PIPE)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertRegex(result.stderr, b'^Rule #1.*')
        self.assertGreater(len(result.stderr), 0)
        self.assertIn(b'IP Type', result.stderr)

    def test_weirdly_formatted(self):
        with NamedTemporaryFile('w') as rf1, NamedTemporaryFile('w') as rf2:
            rf1.write('in,port=1234,path=/foo\n')
            rf1.flush()
            rf2.write('  \t in,addr=9.8.7.6,path=/bar\n'
                      # Note the second \n here is to make sure that we skip
                      # empty lines.
                      '# some comment\n\n'
                      # Only whitespace should be skipped as well.
                      '   \t  '
                      # Note: Missing \n is intentional here!
                      'out,port=4321,path=/foobar')
            rf2.flush()
            cmd = [IP2UNIX, '-c', '-p', '-f', rf1.name, '-f', rf2.name]
            result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)

        self.assertEqual(
            result.stdout,
            b'Rule #1:\n'
            b'  Direction: incoming\n'
            b'  IP Type: TCP and UDP\n'
            b'  Address: <any>\n'
            b'  Port: 1234\n'
            b'  Socket path: /foo\n'
            b'Rule #2:\n'
            b'  Direction: incoming\n'
            b'  IP Type: TCP and UDP\n'
            b'  Address: 9.8.7.6\n'
            b'  Port: <any>\n'
            b'  Socket path: /bar\n'
            b'Rule #3:\n'
            b'  Direction: outgoing\n'
            b'  IP Type: TCP and UDP\n'
            b'  Address: <any>\n'
            b'  Port: 4321\n'
            b'  Socket path: /foobar\n'
        )
