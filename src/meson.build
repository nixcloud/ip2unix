dynports = custom_target('dynports',
                         input: [script_genoffsets,
                                 'dynports/dynports.cc'],
                         output: 'dynports.cc',
                         command: [python, '@INPUT@', '@OUTPUT@'])

errnos = custom_target('errno_list',
                       input: script_generrno,
                       output: 'errno_list.cc',
                       command: [python, '@INPUT@'] + cc.cmd_array(),
                       capture: true)

dynports_sources = [dynports, files('rng.cc')]
serial_sources = files('serial.cc')
globpath_sources = files('globpath.cc')

common_sources = files('rules/parse.cc')
common_sources += serial_sources
common_sources += errnos

main_sources += files('ip2unix.cc')
main_sources += common_sources

lib_sources += files('blackhole.cc',
                     'logging.cc',
                     'preload.cc',
                     'realcalls.cc',
                     'socket.cc',
                     'sockaddr.cc',
                     'sockopts.cc')
lib_sources += common_sources

if systemd_enabled
  lib_sources += files('systemd.cc')
endif
lib_sources += dynports_sources
lib_sources += globpath_sources
includes += include_directories('.')
