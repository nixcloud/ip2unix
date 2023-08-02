project('ip2unix', 'cpp',
        default_options: ['cpp_std=c++17', 'warning_level=3'],
        meson_version: '>=0.47.0', version: '2.1.4')

script_findlibc = files('scripts/findlibc.py')
script_generrno = files('scripts/generrno.py')
script_genoffsets = files('scripts/genoffsets.py')
script_gensyms = files('scripts/gensyms.py')

cc = meson.get_compiler('cpp')

warning_flags = [
  '-Wcast-qual',
  '-Wcovered-switch-default',
  '-Weffc++',
  '-Wextra-semi',
  '-Wimplicit-fallthrough',
  '-Wno-trigraphs',
  '-Wold-style-cast',
  '-Wrange-loop-analysis',
  '-Wreserved-id-macro',
  '-Wshadow',
  '-Wsign-conversion',
  '-Wswitch-enum',
  '-Wunused-exception-parameter',
  '-Wuseless-cast',
  '-Wzero-as-null-pointer-constant',
]

add_project_arguments(cc.get_supported_arguments(warning_flags),
                      language: 'cpp')

python = import('python').find_installation('python3')

cflags = ['-DVERSION="' + meson.project_version() + '"']
cflags += ['-fPIC']
main_cflags = []
lib_cflags = []
lib_ldflags = []

deps = [
  dependency('yaml-cpp', version: '>=0.5.0'),
  cc.find_library('dl')
]

libcpath = run_command(python, script_findlibc, cc.cmd_array(), check: false)
if libcpath.returncode() == 0
  fullpath = libcpath.stdout()
  message('Found C library at ' + fullpath)
  lib_cflags += ['-DLIBC_PATH="' + fullpath + '"']
endif

systemd_enabled = get_option('systemd-support')

if systemd_enabled
  cflags += ['-DSYSTEMD_SUPPORT']
endif

if cc.has_header_symbol('sys/epoll.h', 'epoll_ctl')
  cflags += ['-DHAS_EPOLL']
endif

lib_sources = []
main_sources = []
includes = []
subdir('src')

gen_extra_args = cc.cmd_array() + lib_cflags + cflags + ['--', '@INPUT@']

gen_sym_map = [python, script_gensyms, '--map']
sym_map = custom_target('symmap', input: lib_sources, output: 'symbols.map',
                        command: gen_sym_map + gen_extra_args, capture: true)

gen_ldscript = [python, script_gensyms, '--ldscript']
ldscript = custom_target('ldscript', input: lib_sources, output: 'ldscript',
                         command: gen_ldscript + gen_extra_args, capture: true)

lib_ldflags += [
  '-Wl,--version-script,@0@'.format(sym_map.full_path()),
  ldscript.full_path()
]

man_input = files('README.adoc')

adoc_attrs = [
  '-a', 'manmanual=IP2Unix Manual',
  '-a', 'mansource=IP2Unix',
  '-a', 'revnumber=@0@'.format(meson.project_version()),
]

if not systemd_enabled
  adoc_attrs += ['-a', 'without-systemd']
endif

################################## MANPAGE ##################################

mandest = join_paths(get_option('prefix'), get_option('mandir'), 'man1')

build_manpage = false

a2x = find_program(['a2x', 'a2x.py'], required: false)
if a2x.found()
  build_manpage = true

  a2xcmd = [a2x, '-d', 'manpage', '-f', 'manpage', '-D', '@OUTDIR@']

  docbook_xsl = 'http://docbook.sourceforge.net/release/xsl/current/'
  docbook_xsl += 'manpages/docbook.xsl'
  docbook_dtd = 'http://www.oasis-open.org/docbook/xml/4.5/docbookx.dtd'

  xsltproc = find_program('xsltproc', required: false)
  if xsltproc.found()
    xslt_test = run_command([xsltproc, docbook_xsl], check: false)
    if xslt_test.returncode() != 0
      warning('No Docbook XSL stylesheet found, not generating manpage.')
      build_manpage = false
    endif
  else
    build_manpage = false
    warning('No \'xsltproc\' found, not generating manpage.')
  endif

  xmllint = find_program('xmllint', required: false)

  if xmllint.found()
    lintcmd = [xmllint, '--nonet', '--dtdvalid', docbook_dtd, '--auto']
    if run_command(lintcmd, check: false).returncode() != 3
      a2xcmd += ['-L']
      warning('No Docbook 4.5 DTD found, disabling validation.')
    endif
  else
    a2xcmd += ['-L']
    warning('No \'xmllint\' found, disabling validation of AsciiDoc output.')
  endif

  if build_manpage
    custom_target('ip2unix-man',
                  command: a2xcmd + adoc_attrs + ['@INPUT@'],
                  input: man_input,
                  output: 'ip2unix.1',
                  install: true,
                  install_dir: mandest)
  endif
endif

if not build_manpage
  asciidoctor = find_program('asciidoctor', required: false)

  if asciidoctor.found()
    adcmd = [asciidoctor, '-b', 'manpage', '-d', 'manpage']
    adoc_attrs += ['-a', 'reproducible']
    custom_target('ip2unix-man',
                  command: adcmd + adoc_attrs + ['-o', '@OUTPUT0@', '@INPUT@'],
                  input: man_input,
                  output: 'ip2unix.1',
                  install: true,
                  install_dir: mandest)
    build_manpage = true
  endif
endif

if build_manpage
  cflags += ['-DWITH_MANPAGE']
else
  warning('Neither AsciiDoc nor Asciidoctor found, not generating manpage.')
endif

############################### BUILD TARGETS ###############################

libip2unix = shared_library('ip2unix', lib_sources, install: true,
                            dependencies: deps,
                            link_depends: [sym_map, ldscript],
                            cpp_args: lib_cflags + cflags,
                            link_args: lib_ldflags,
                            include_directories: includes)

ip2unix = executable('ip2unix', main_sources, install: true,
                     link_with: libip2unix,
                     dependencies: deps, include_directories: includes,
                     cpp_args: main_cflags + cflags)

subdir('tests')
