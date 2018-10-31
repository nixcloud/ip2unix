pytest = find_program('pytest', required: false)
if pytest.found()
  pytest_args = [
    '-p', 'no:cacheprovider',
    '--ip2unix-path=@0@'.format(ip2unix.full_path())
  ]

  has_timeout_plugin = run_command(pytest, '--timeout=20', '--version')
  if has_timeout_plugin.returncode() == 0
    pytest_args += ['--timeout=30']
    timeout = 60
  else
    timeout = 30
  endif

  if libsystemd.found()
    pytest_args += ['--systemd-support']
    systemd_sa = find_program('systemd-socket-activate', required: false)
    if systemd_sa.found()
      pytest_args += ['--systemd-sa-path=@0@'.format(systemd_sa.path())]
    else
      message('No \'systemd-socket-activate\' program found, can\'t run' +
              ' tests for socket activation.')
    endif
    if systemd_no_fdnames
      pytest_args += ['--systemd-no-fdnames']
    endif
  endif
  test('integration', pytest, args: pytest_args, timeout: timeout,
       workdir: meson.current_source_dir(),
       env: ['PYTHONDONTWRITEBYTECODE=1'])
else
  warning('Unable to find pytest, tests will not be run.')
endif

subdir('unit')
