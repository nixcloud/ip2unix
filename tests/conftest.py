IP2UNIX = None
SYSTEMD_SUPPORT = False
SYSTEMD_SA_PATH = None


def pytest_addoption(parser):
    parser.addoption('--ip2unix-path', action='store',
                     help='The path to the ip2unix command')
    parser.addoption('--systemd-support', action='store_true',
                     help='Whether systemd support is compiled in')
    parser.addoption('--systemd-sa-path', action='store',
                     help='The path to the \'systemd-socket-activate\' helper')


def pytest_configure(config):
    global IP2UNIX
    global SYSTEMD_SUPPORT
    global SYSTEMD_SA_PATH
    IP2UNIX = config.option.ip2unix_path
    SYSTEMD_SUPPORT = config.option.systemd_support
    SYSTEMD_SA_PATH = config.option.systemd_sa_path
