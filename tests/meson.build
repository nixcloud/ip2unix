pytest = find_program('pytest', required: false)
if pytest.found()
  pytest_args = [
    '-p', 'no:cacheprovider',
    '--ip2unix-path=@0@'.format(ip2unix.full_path())
  ]
  if libsystemd.found()
    pytest_args += ['--systemd-support']
  endif
  test('tests', pytest, args: pytest_args,
       workdir: meson.current_source_dir(),
       env: ['PYTHONDONTWRITEBYTECODE=1'])
else
  warning('Unable to find pytest, tests will not be run.')
endif
