project('ip2unix', 'cpp', default_options: ['cpp_std=c++17'],
        meson_version: '>=0.46.0', version: '0.1.0')
add_project_arguments('-Wextra', language: 'cpp')

python = import('python').find_installation()

sources = []
includes = []
subdir('src')

generate_sym_map = [python, files('meson/gensyms.py'), '@INPUT@']
sym_map = custom_target('symmap', input: sources, output: 'symbols.map',
                        command: generate_sym_map, capture: true)

cc = meson.get_compiler('cpp')

ldflags = [
  '-fPIC',
  '-pie',
  '-Wl,-E',
  '-Wl,--version-script,@0@'.format(sym_map.full_path()),
]
cflags = []

deps = [
  dependency('yaml-cpp', version: '>=0.5.0'),
  cc.find_library('dl')
]

libsystemd = dependency('libsystemd', required: false)
if libsystemd.found()
  cflags += ['-DSOCKET_ACTIVATION']
  deps += [libsystemd]
endif

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

# For generating the manpage
subdir('meson')

subdir('tests')
