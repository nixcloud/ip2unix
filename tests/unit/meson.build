test_dynports = executable('test_dynports',
                           ['dynports.cc', dynports_sources],
                           include_directories: includes)
test('unit-dynports', test_dynports, timeout: get_option('test-timeout'))

test_serial = executable('test_serial',
                         ['serial.cc', serial_sources],
                         include_directories: includes)
test('unit-serial', test_serial, timeout: get_option('test-timeout'))
