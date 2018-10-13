pytest = find_program('pytest', required: false)
if pytest.found()
  pytest_args = [
    '-p', 'no:cacheprovider',
    '--ip2unix-path=@0@'.format(ip2unix.full_path())
  ]
  if libsystemd.found()
    pytest_args += ['--systemd-support']
    systemd_sa = find_program('systemd-socket-activate', required: false)
    if systemd_sa.found()
      pytest_args += ['--systemd-sa-path=@0@'.format(systemd_sa.path())]
    else
      message('No \'systemd-socket-activate\' program found, can\'t run' +
              ' tests for socket activation.')
    endif
  endif
  test('tests', pytest, args: pytest_args,
       workdir: meson.current_source_dir(),
       env: ['PYTHONDONTWRITEBYTECODE=1'])
else
  warning('Unable to find pytest, tests will not be run.')
endif
