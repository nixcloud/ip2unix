let
  rev = "99f1c2157fba4bfe6211a321fd0ee43199025dbf";
  url = "https://github.com/edolstra/flake-compat/archive/${rev}.tar.gz";
  flake = import (fetchTarball url) { src = ./.; };
  inNixShell = builtins.getEnv "IN_NIX_SHELL" != "";
in if inNixShell then flake.shellNix else flake.defaultNix
