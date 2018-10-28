{ pkgs ? import <nixpkgs> {}, lib ? pkgs.lib }:

pkgs.stdenv.mkDerivation rec {
  name = "ip2unix-${version}";

  version = let
    regex = " *project *\\([^)]*[ ,]+version *: *'([^']*)'.*";
    contents = builtins.readFile ./meson.build;
  in builtins.head (builtins.match regex contents);

  src = lib.cleanSource ./.;

  nativeBuildInputs = [
    pkgs.meson pkgs.ninja pkgs.pkgconfig pkgs.asciidoctor
    pkgs.python3Packages.pytest pkgs.python3Packages.pytest-timeout
  ];
  buildInputs = [ pkgs.libyamlcpp pkgs.systemd ];

  doCheck = true;
}
