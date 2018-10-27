import os
import json
import tempfile
import subprocess

from contextlib import contextmanager

import pytest
from conftest import IP2UNIX, SYSTEMD_SUPPORT, SYSTEMD_SA_PATH

__all__ = ['IP2UNIX', 'SYSTEMD_SUPPORT', 'SYSTEMD_SA_PATH', 'ip2unix',
           'systemd_only', 'non_systemd_only', 'systemd_sa_helper_only']


@contextmanager
def ip2unix(rules, childargs, *args, **kwargs):
    ip2unix_args = kwargs.pop('ip2unix_args', None)
    cmdargs = [] if ip2unix_args is None else ip2unix_args
    pre_cmd = kwargs.pop('pre_cmd', None)
    pre = [] if pre_cmd is None else pre_cmd
    rulefile = tempfile.NamedTemporaryFile('w', delete=False)
    json.dump(rules, rulefile)
    rulefile.close()
    full_args = pre + [IP2UNIX, '-f', rulefile.name] + cmdargs + childargs
    try:
        yield subprocess.Popen(full_args, *args, **kwargs)
    finally:
        os.unlink(rulefile.name)


systemd_only = pytest.mark.skipif(
    not SYSTEMD_SUPPORT, reason='no support for systemd compiled in'
)
non_systemd_only = pytest.mark.skipif(
    SYSTEMD_SUPPORT, reason='support for systemd compiled in'
)
systemd_sa_helper_only = pytest.mark.skipif(
    SYSTEMD_SA_PATH is None, reason="no 'systemd-socket-activate' helper"
)
