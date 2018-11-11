test_dynports = executable('test_dynports',
                           ['dynports.cc', dynports_sources],
                           include_directories: includes)
test('unit-dynports', test_dynports, timeout: get_option('test-timeout'))
