# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning].

## [Unreleased]

### Fixed
- Missing header files for newer GCC versions, thanks to Varun Madiath.
- Use-after-free of blackhole working directory path.
- A few compiler warnings on unnecessary allocation of string literals.

### Added
- Deprecation warnings if rules are specified in YAML format.
- Unlink socket file before `bind` if `SO_REUSEADDR` is used.
- Support for Linux abstract sockets.
- Support for matching an existing Unix domain socket or abstract socket.
- Add `stream`/`datagram` aliases for `tcp`/`udp` socket types.

### Changed
- Rule files (`-f`) are now just a list of newline-separated rule (`-r`)
  arguments instead of YAML files.
- Improve and overhaul README and man page.
- Split build instructions into separate file.
- Include URL to README in usage if manpage is not being built.
- Turn into a Nix Flake.
- Improve serializer to be more robust in end-of-stream conditions.
- Bump requirements to require at least GCC version 9.

### Removed
- Badges (eg. LGTM and build status) in README and Hydra.
- No longer prefer C library path over `RTLD_NEXT`.

## [2.1.4] - 2021-07-10

### Fixed
- Ordering between systemd socket file descriptor names and rules.
- Usage of C library path as discovered by Meson.

## [2.1.3] - 2020-06-01

### Fixed
- Pass linker version script to the linker instead of the compiler.
- Compile with `-fPIC` again (regression from version 2.1.2).
- Out of bounds array access in `globpath`.
- Handling of `epoll_ctl` calls (they're now replayed after replacing socket).
- GCC 10 build errors and Clang warnings.

## [2.1.2] - 2020-05-27

### Fixed
- Support for glibc >= 2.30 by splitting preload library and main executable.

## [2.1.1] - 2019-09-20

### Fixed
- Segfault when using `accept()` or `accept4()` without a sockaddr buffer.

## [2.1.0] - 2019-06-21

### Added
- Support `AF_INET` and `AF_INET6` sockets for systemd socket activation.

## [2.0.1] - 2019-02-26

### Fixed
- Unregister socket as soon as we know that no rule matches.

### Removed
- The `encode_rules()` function is no longer needed because the serializer has
  been refactored in version 2.0.0.

## [2.0.0] - 2018-12-26

### Fixed
- Use right endian conversion functions in port matching.
- Pass `is_unix` to child socket on `accept` to prevent accidentally replacing
  an already converted Unix socket by a new Unix socket. The latter would be a
  socket that's not accepted, which would eventually lead to an error.
- Correctly handle `setsockopts` used with other levels than `SOL_SOCKET`.

### Added
- New `ignore` rule option, which prevents conversion to Unix socket.
- A way to increase the verbosity via the `-v` command line argument.
- Reams of log messages in addition to the FATAL errors we had so far.
- Use Syslog format for logging if `stderr` is a socket.
- Set `FD_CLOEXEC` on systemd socket file descriptors as soon as they're
  associated.

### Changed
- Improve wording and add more descriptions in README and manpage.
- The implementation for fetching systemd sockets now no longer uses
  `libsystemd`, thus the build-time dependency is no longer required.
- New serialiser for passing rules to the preloaded library in a more compact
  form instead of using YAML, so it's less likely that we'll hit the maximum
  stack size.
- Systemd sockets are now associated during rule initialisation and thus behave
  more predictable in complex setups.

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

[Unreleased]: https://github.com/nixcloud/ip2unix/compare/v2.1.4...HEAD
[2.1.4]: https://github.com/nixcloud/ip2unix/compare/v2.1.3...v2.1.4
[2.1.3]: https://github.com/nixcloud/ip2unix/compare/v2.1.2...v2.1.3
[2.1.2]: https://github.com/nixcloud/ip2unix/compare/v2.1.1...v2.1.2
[2.1.1]: https://github.com/nixcloud/ip2unix/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/nixcloud/ip2unix/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/nixcloud/ip2unix/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/nixcloud/ip2unix/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/nixcloud/ip2unix/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/nixcloud/ip2unix/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/nixcloud/ip2unix/compare/v1.0.0...v1.1.0

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
