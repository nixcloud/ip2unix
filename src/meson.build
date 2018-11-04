dynports = custom_target('dynports',
                         input: ['dynports/genoffsets.py',
                                 'dynports/dynports.cc'],
                         output: 'dynports.cc',
                         command: [python, '@INPUT@', '@OUTPUT@'])

errnos = custom_target('errno_list',
                       input: 'rules/generrno.py',
                       output: 'errno_list.cc',
                       command: [python, '@INPUT@'] + cc.cmd_array(),
                       capture: true)

dynports_sources = [dynports, files('rng.cc')]

sources += files('ip2unix.cc',
                 'blackhole.cc',
                 'preload.cc',
                 'realcalls.cc',
                 'rules/match.cc',
                 'rules/parse.cc',
                 'socket.cc',
                 'sockaddr.cc',
                 'sockopts.cc')
sources += dynports_sources
sources += errnos
includes += include_directories('.')
