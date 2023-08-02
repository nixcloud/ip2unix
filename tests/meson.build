pytest_canidates = ['pytest-3', 'py.test-3', 'pytest', 'py.test']
pytest = find_program(pytest_canidates, required: false)
if pytest.found()
  subdir('helpers')

  pytest_args = [
    '-p', 'no:cacheprovider',
    '--ip2unix-path=@0@'.format(ip2unix.full_path()),
    '--libip2unix-path=@0@'.format(libip2unix.full_path()),
    '--helper-accept-no-peer-addr=@0@'.format(
      helper_accept_no_peer_addr.full_path()
    )
  ]

  has_timeout_plugin = run_command(pytest, '--timeout=20', '--version',
                                   check: false)
  if has_timeout_plugin.returncode() == 0
    pytest_args += ['--timeout=@0@'.format(get_option('test-timeout'))]
    timeout = get_option('test-timeout') + 30
  else
    timeout = get_option('test-timeout')
  endif

  if systemd_enabled
    pytest_args += ['--systemd-support']
    systemd_sa = find_program('systemd-socket-activate', required: false)
    if systemd_sa.found()
      # XXX: Use of .path() is deprecated but we need a minimum version of
      # 0.55.0 to use .full_path() here and we're not yet going to require that
      # just yet.
      pytest_args += ['--systemd-sa-path=@0@'.format(systemd_sa.path())]
    else
      message('No \'systemd-socket-activate\' program found, can\'t run' +
              ' tests for socket activation.')
    endif
  endif
  test('integration', pytest, args: pytest_args, timeout: timeout,
       workdir: meson.current_source_dir(),
       depends: [ip2unix, libip2unix, helper_accept_no_peer_addr],
       env: ['PYTHONDONTWRITEBYTECODE=1'])
else
  warning('Unable to find pytest, tests will not be run.')
endif

subdir('unit')
