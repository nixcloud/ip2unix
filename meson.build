project('ip2unix', 'cpp', default_options: ['cpp_std=c++17'],
        meson_version: '>=0.46.0', version: '1.1.0')

cc = meson.get_compiler('cpp')

warning_flags = [
  '-Wcast-qual',
  '-Weffc++',
  '-Wextra',
  '-Wold-style-cast',
  '-Wshadow',
  '-Wsign-conversion',
  '-Wswitch-enum',
  '-Wuseless-cast',
  '-Wzero-as-null-pointer-constant',
]

add_project_arguments(cc.get_supported_arguments(warning_flags),
                      language: 'cpp')

python = import('python').find_installation()

cflags = ['-fPIC']

ldflags = [
  '-pie',
  '-Wl,-E',
]

deps = [
  dependency('yaml-cpp', version: '>=0.5.0'),
  cc.find_library('dl')
]

libcpath = run_command(python, 'meson/findlibc.py', cc.cmd_array())
if libcpath.returncode() == 0
  fullpath = libcpath.stdout()
  message('Found C library at ' + fullpath)
  cflags += ['-DLIBC_PATH="' + fullpath + '"']
endif

systemd_no_fdnames = false

libsystemd = dependency('libsystemd', required: false)
if libsystemd.found()
  cflags += ['-DSOCKET_ACTIVATION']
  deps += [libsystemd]
  if not cc.has_function('sd_listen_fds_with_names', dependencies: libsystemd)
    systemd_no_fdnames = true
    cflags += ['-DNO_FDNAMES']
  endif
endif

sources = []
includes = []
subdir('src')

generate_sym_map = [python, files('meson/gensyms.py'), '@INPUT@']
sym_map = custom_target('symmap', input: sources, output: 'symbols.map',
                        command: generate_sym_map, capture: true)
cflags += ['-Wl,--version-script,@0@'.format(sym_map.full_path())]

ip2unix = executable('ip2unix', sources, install: true, dependencies: deps,
                     link_args: ldflags, link_depends: sym_map,
                     include_directories: includes, cpp_args: cflags)

man_input = files('README.adoc')

adoc_attrs = [
  '-a', 'manmanual=IP2Unix Manual',
  '-a', 'mansource=IP2Unix',
  '-a', 'revnumber=@0@'.format(meson.project_version()),
]

if not libsystemd.found()
  adoc_attrs += ['-a', 'without-systemd']
endif
if systemd_no_fdnames
  adoc_attrs += ['-a', 'systemd-no-fdnames']
endif

# For generating the manpage
subdir('meson')

subdir('tests')
