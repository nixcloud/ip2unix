# Regression test for https://github.com/nixcloud/ip2unix/issues/6
{ pkgs ? import <nixpkgs> {}, ip2unix ? import ../.. { inherit pkgs; } }:

pkgs.runCommand "test-rsession" {
  nativeBuildInputs = [ ip2unix pkgs.R pkgs.rstudio pkgs.curl ];
  R_HOME = "${pkgs.R}/lib/R";
  R_SHARE_DIR = "${pkgs.R}/lib/R/share";
  R_INCLUDE_DIR = "${pkgs.R}/lib/R/include";
  R_DOC_DIR = "${pkgs.R}/lib/R/doc";
} ''
  export HOME="$PWD"
  export LANG=C

  ip2unix -r path=test.socket rsession \
    --standalone=1 --program-mode=server --log-stderr=1 \
    --www-address 127.0.0.1 --www-port 8080 &
  while [ ! -e test.socket ]; do sleep 1; done

  curl --unix-socket test.socket http://127.0.0.1/ \
    | grep -qF '<title>RStudio</title>'

  touch "$out"
''
