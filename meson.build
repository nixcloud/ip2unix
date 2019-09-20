project('ip2unix', 'cpp', default_options: ['cpp_std=c++17'],
        meson_version: '>=0.46.0', version: '2.0.2')

script_findlibc = files('scripts/findlibc.py')
script_generrno = files('scripts/generrno.py')
script_genoffsets = files('scripts/genoffsets.py')
script_gensyms = files('scripts/gensyms.py')

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

python = import('python').find_installation('python3')

cflags = ['-fPIC', '-DVERSION="' + meson.project_version() + '"']

ldflags = [
  '-pie',
  '-Wl,-E',
]

deps = [
  dependency('yaml-cpp', version: '>=0.5.0'),
  cc.find_library('dl')
]

libcpath = run_command(python, script_findlibc, cc.cmd_array())
if libcpath.returncode() == 0
  fullpath = libcpath.stdout()
  message('Found C library at ' + fullpath)
  cflags += ['-DLIBC_PATH="' + fullpath + '"']
endif

systemd_enabled = get_option('systemd-support')

if systemd_enabled
  cflags += ['-DSYSTEMD_SUPPORT']
endif

sources = []
includes = []
subdir('src')

generate_sym_map = [python, script_gensyms, '@INPUT@']
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

if not systemd_enabled
  adoc_attrs += ['-a', 'without-systemd']
endif

# For generating the manpage
subdir('doc')

subdir('tests')
