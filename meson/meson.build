asciidoctor = find_program('asciidoctor', required: false)

mandest = join_paths(get_option('prefix'), get_option('mandir'), 'man1')

if asciidoctor.found()
  adcmd = [asciidoctor, '-b', 'manpage', '-d', 'manpage']
  adoc_attrs += ['-a', 'reproducible']
  custom_target('ip2unix-man',
                command: adcmd + adoc_attrs + ['-o', '@OUTPUT0@', '@INPUT@'],
                input: man_input,
                output: 'ip2unix.1',
                install: true,
                install_dir: mandest)
else
  a2x = find_program(['a2x', 'a2x.py'], required: false)
  if a2x.found()
    build_manpage = true

    a2xcmd = [a2x, '-d', 'manpage', '-f', 'manpage', '-D', '@OUTDIR@']

    docbook_xsl = 'http://docbook.sourceforge.net/release/xsl/current/'
    docbook_xsl += 'manpages/docbook.xsl'
    docbook_dtd = 'http://www.oasis-open.org/docbook/xml/4.5/docbookx.dtd'

    xsltproc = find_program('xsltproc', required: false)
    if xsltproc.found()
      xslt_test = run_command([xsltproc, docbook_xsl])
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
      if run_command(lintcmd).returncode() != 3
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
  else
    warning('Neither AsciiDoc nor Asciidoctor found, not generating manpage.')
  endif
endif
