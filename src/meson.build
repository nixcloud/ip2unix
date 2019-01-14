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

sources += files('ip2unix.cc',
                 'blackhole.cc',
                 'logging.cc',
                 'preload.cc',
                 'realcalls.cc',
                 'rules/parse.cc',
                 'socket.cc',
                 'sockaddr.cc',
                 'sockopts.cc')
if systemd_enabled
  sources += files('systemd.cc')
endif
sources += dynports_sources
sources += serial_sources
sources += globpath_sources
sources += errnos
includes += include_directories('.')
