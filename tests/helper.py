import subprocess

from contextlib import contextmanager

import pytest
from conftest import IP2UNIX, LIBIP2UNIX, SYSTEMD_SUPPORT, SYSTEMD_SA_PATH

__all__ = ['IP2UNIX', 'LIBIP2UNIX', 'SYSTEMD_SUPPORT', 'SYSTEMD_SA_PATH',
           'dict_to_rule', 'dict_to_rule_args', 'ip2unix', 'systemd_only',
           'non_systemd_only', 'systemd_sa_helper_only']


def dict_to_rule(rule):
    items = []
    for key, value in rule.items():
        if key in ['dir', 'type']:
            items.append(value)
        elif value is True:
            items.append(key)
        else:
            items.append(f'{key}={value}')
    return ','.join(items)


def dict_to_rule_args(rules):
    return [arg for rule in rules for arg in ['-r', dict_to_rule(rule)]]


@contextmanager
def ip2unix(rules, childargs, *args, **kwargs):
    ip2unix_args = kwargs.pop('ip2unix_args', None)
    cmdargs = [] if ip2unix_args is None else ip2unix_args
    pre_cmd = kwargs.pop('pre_cmd', None)
    pre = [] if pre_cmd is None else pre_cmd
    rule_args = dict_to_rule_args(rules)
    full_args = pre + [IP2UNIX] + rule_args + cmdargs + childargs
    yield subprocess.Popen(full_args, *args, **kwargs)


systemd_only = pytest.mark.skipif(
    not SYSTEMD_SUPPORT, reason='no support for systemd compiled in'
)
non_systemd_only = pytest.mark.skipif(
    SYSTEMD_SUPPORT, reason='support for systemd compiled in'
)
systemd_sa_helper_only = pytest.mark.skipif(
    SYSTEMD_SA_PATH is None, reason="no 'systemd-socket-activate' helper"
)
