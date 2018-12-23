# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning].

## [Unreleased]

### Fixed
- Use right endian conversion functions in port matching.
- Pass `is_unix` to child socket on `accept` to prevent accidentally replacing
  an already converted Unix socket by a new Unix socket. The latter would be a
  socket that's not accepted, which would eventually lead to an error.

### Added
- New `ignore` rule option, which prevents conversion to Unix socket.
- A way to increase the verbosity via the `-v` command line argument.
- Reams of log messages in addition to the FATAL errors we had so far.

### Changed
- Improve wording and add more descriptions in README and manpage.
- The implementation for fetching systemd sockets now no longer uses
  `libsystemd`, thus the build-time dependency is no longer required.

## [1.2.0] - 2018-11-12

### Fixed
- Don't fail when building the manual with AsciiDoc and xmllint.
- Some long options (`--rule`, `--rules-file` and `--rules-data`) were ignored.
- Manpage formatting is now more consistent.

### Added
- A new --version command line argument for showing version information.

## [1.1.1] - 2018-11-07

### Fixed
- Don't unlink target socket path if connect is used after bind.

## [1.1.0] - 2018-11-07

### Fixed
- Prevent closing file descriptors passed by systemd.

### Added
- Allow to specify port ranges.

## 1.0.0 - 2018-11-05

### Added
- The initial release, which evolved from an early prototype specific to a
  certain use case into a more generic command line tool.

[Unreleased]: https://github.com/nixcloud/ip2unix/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/nixcloud/ip2unix/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/nixcloud/ip2unix/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/nixcloud/ip2unix/compare/v1.0.0...v1.1.0

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
