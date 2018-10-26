dynports = custom_target('dynports',
                         input: ['dynports/genoffsets.py',
                                 'dynports/dynports.cc'],
                         output: 'dynports.cc',
                         command: [python, '@INPUT@', '@OUTPUT@'])

sources += files('ip2unix.cc',
                 'preload.cc',
                 'realcalls.cc',
                 'rules/match.cc',
                 'rules/parse.cc',
                 'socket.cc',
                 'sockaddr.cc',
                 'sockopts.cc')
sources += dynports
includes += include_directories('.')
