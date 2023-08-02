{
  description = "Turn IP sockets into Unix domain sockets";

  outputs = { self, nixpkgs }: let
    inherit (nixpkgs) lib;
    nixpkgsSystems = lib.attrNames nixpkgs.legacyPackages;

    systems = lib.filter (lib.hasSuffix "-linux") nixpkgsSystems;
    hydraSystems = [ "i686-linux" "x86_64-linux" "aarch64-linux" ];
    vmTestSystems = [ "x86_64-linux" "aarch64-linux" ];

    withPkgs = f: forAllSystems (sys: f sys nixpkgs.legacyPackages.${sys});
    forAllSystems = lib.genAttrs systems;
  in {
    packages = withPkgs (system: pkgs: {
      default = self.packages.${system}.ip2unix;

      ip2unix = pkgs.stdenv.mkDerivation {
        pname = "ip2unix";

        version = let
          regex = " *project *\\([^)]*[ ,]+version *: *'([^']*)'.*";
          contents = builtins.readFile ./meson.build;
        in builtins.head (builtins.match regex contents);

        src = lib.cleanSourceWith {
          src = lib.cleanSource ./.;
          filter = path: type: let
            relPath = lib.removePrefix (toString ./. + "/") path;
            toplevel = [
              { type = "directory"; name = "doc"; }
              { type = "directory"; name = "scripts"; }
              { type = "directory"; name = "src"; }
              { type = "directory"; name = "tests"; }
              { type = "regular"; name = "README.adoc"; }
              { type = "regular"; name = "meson.build"; }
              { type = "regular"; name = "meson_options.txt"; }
            ];
            isMatching = { type, name }: type == type && relPath == name;
            isToplevel = lib.any isMatching toplevel;
            excludedTestDirs = [ "tests/vm" "tests/programs" ];
          in if type == "directory" && lib.elem relPath excludedTestDirs
             then false
             else builtins.match "[^/]+" relPath != null -> isToplevel;
        };

        nativeBuildInputs = [
          pkgs.meson pkgs.ninja pkgs.pkg-config pkgs.asciidoc pkgs.libxslt.bin
          pkgs.docbook_xml_dtd_45 pkgs.docbook_xsl pkgs.libxml2.bin
          pkgs.docbook5 pkgs.python3Packages.pytest
          pkgs.python3Packages.pytest-timeout pkgs.systemd
        ];
        buildInputs = [ pkgs.libyamlcpp ];

        doCheck = true;

        doInstallCheck = true;
        installCheckPhase = ''
          found=0
          for man in "$out/share/man/man1"/ip2unix.1*; do
            test -s "$man" && found=1
          done
          if [ $found -ne 1 ]; then
            echo "ERROR: Manual page hasn't been generated." >&2
            exit 1
          fi

          diff -u <(
            find "$src/src" -iname '*.cc' -type f -exec sed -n \
              -e '/^ *#/!s/^.*\(WRAP\|EXPORT\)_SYM(\([^)]\+\)).*/\2/p' \
              {} + | sort
          ) <(
            nm --defined-only -g "$out/lib/libip2unix.so" \
              | cut -d' ' -f3- | sort
          )
        '';
      };
    });

    hydraJobs = let
      # This is with all the *required* dependencies only.
      withSystem = fun: system: let
        pkgs = nixpkgs.legacyPackages.${system};
        attrs = fun pkgs;
        stdenv = attrs.stdenv or pkgs.stdenv;

        libyamlcpp =
          if stdenv.cc.isClang then pkgs.libyamlcpp
          else pkgs.libyamlcpp.override { inherit stdenv; };

      in stdenv.mkDerivation (removeAttrs attrs [ "stdenv" ] // rec {
        inherit (self.packages.${system}.ip2unix) name version src;

        mesonFlags = [ "-Dtest-timeout=3600" ] ++ attrs.mesonFlags or [];

        nativeBuildInputs = [ pkgs.meson pkgs.ninja pkgs.pkgconfig ]
                         ++ attrs.nativeBuildInputs or [];
        buildInputs = [ libyamlcpp ] ++ attrs.buildInputs or [];

        doCheck = attrs.doCheck or true;

        doInstallCheck = attrs.doInstallCheck or true;
        installCheckPhase = attrs.installCheckPhase or ''
          found=0
          for man in "$out/share/man/man1"/ip2unix.1*; do
            test -s "$man" && found=1
          done
          expected=${if attrs.requireManpage or true then "1" else "0"}
          if [ $found -ne $expected ]; then
            echo "ASSERTION: Manpage found($found) != expected($expected)" >&2
            exit 1
          fi
        '';
      });

      # Bare minimum dependencies plus pytest for integration tests.
      withSystemAndTests = fun: system: let
        funWithTests = pkgs: let
          funAttrs = fun pkgs;
        in funAttrs // {
          nativeBuildInputs = [
            pkgs.python3Packages.pytest pkgs.python3Packages.pytest-timeout
          ] ++ funAttrs.nativeBuildInputs or [];
          postConfigure = ''
            grep -qF 'Program pytest found: YES' meson-logs/meson-log.txt
            ${funAttrs.postConfigure or ""}
          '';
        };
      in withSystem funWithTests system;

      # All the dependencies including optional ones.
      withSystemFull = fun: system: let
        funFull = pkgs: let
          funAttrs = fun pkgs;
        in funAttrs // {
          nativeBuildInputs = [
            pkgs.asciidoc pkgs.libxslt.bin pkgs.docbook_xml_dtd_45
            pkgs.docbook_xsl pkgs.libxml2.bin pkgs.docbook5 pkgs.systemd
          ] ++ funAttrs.nativeBuildInputs or [];
          postConfigure = ''
            grep -qF 'Program systemd-socket-activate found: YES' \
              meson-logs/meson-log.txt
            ${funAttrs.postConfigure or ""}
          '';
        };
      in withSystemAndTests funFull system;

      forEachSystem = f: lib.genAttrs hydraSystems (withSystem f);
      testForEachSystem = f: lib.genAttrs hydraSystems (withSystemAndTests f);
      fullForEachSystem = f: lib.genAttrs hydraSystems (withSystemFull f);

      mkManpageJobs = attrsFun: {
        no-manpage = testForEachSystem (pkgs: (attrsFun pkgs) // {
          requireManpage = false;
        });

        asciidoc = {
          with-validation = testForEachSystem (pkgs: (attrsFun pkgs) // {
            nativeBuildInputs = [
              pkgs.libxslt.bin pkgs.docbook_xml_dtd_45 pkgs.docbook_xsl
              pkgs.libxml2.bin pkgs.docbook5

              # We want to pass the -v argument to a2x so that if we get a
              # validation error it's actually shown in the build log. The
              # reason we don't do this by default is because it would cause
              # unnecessary build output when built on other systems.
              (pkgs.runCommand "a2x-wrapped" {
                nativeBuildInputs = [ pkgs.makeWrapper ];
                a2x = "${pkgs.asciidoc}/bin/a2x";
              } ''
                mkdir -p "$out/bin"
                makeWrapper "$a2x" "$out/bin/a2x" --add-flags -v
                ln -s ${lib.escapeShellArg pkgs.asciidoc}/bin/asciidoc \
                  "$out/bin"
              '')
            ] ++ (attrsFun pkgs).nativeBuildInputs or [];
            postConfigure = ''
              grep -qF 'Program xmllint found: YES' meson-logs/meson-log.txt
              ${(attrsFun pkgs).postConfigure or ""}
            '';
          });

          without-validation = testForEachSystem (pkgs: (attrsFun pkgs) // {
            nativeBuildInputs = [
              pkgs.asciidoc pkgs.libxslt.bin pkgs.docbook_xml_dtd_45
              pkgs.docbook_xsl
            ] ++ (attrsFun pkgs).nativeBuildInputs or [];
            postConfigure = ''
              grep -qF 'Program a2x found: YES' meson-logs/meson-log.txt
              ${(attrsFun pkgs).postConfigure or ""}
            '';
          });
        };

        asciidoctor = testForEachSystem (pkgs: (attrsFun pkgs) // {
          nativeBuildInputs = [ pkgs.asciidoctor ]
                           ++ (attrsFun pkgs).nativeBuildInputs or [];
          postConfigure = ''
            grep -qF 'Program asciidoctor found: YES' meson-logs/meson-log.txt
            ${(attrsFun pkgs).postConfigure or ""}
          '';
        });
      };

    in {
      tests.configurations = {
        minimal.no-tests = forEachSystem (pkgs: {
          requireManpage = false;
          nativeBuildInputs = [ pkgs.python3 ];
        });
        minimal.tested = testForEachSystem (lib.const {
          requireManpage = false;
        });

        systemd = mkManpageJobs (pkgs: {
          nativeBuildInputs = [ pkgs.systemd ];
          postConfigure = ''
            grep -qF 'Program systemd-socket-activate found: YES' \
              meson-logs/meson-log.txt
          '';
        });
        no-systemd = mkManpageJobs (lib.const {
          mesonFlags = [ "-Dsystemd-support=false" ];
        });

        # This is to make sure AsciiDoc is picked over Asciidoctor when
        # generating the manpage.
        default-asciidoc = forEachSystem (pkgs: {
          requireManpage = true;
          nativeBuildInputs = [
            pkgs.libxslt.bin pkgs.docbook_xml_dtd_45 pkgs.docbook_xsl
            pkgs.libxml2.bin pkgs.docbook5 pkgs.asciidoc pkgs.python3
            (pkgs.writeScriptBin "asciidoctor" ''
              #!${pkgs.stdenv.shell}
              exit 1
            '')
          ];
        });
      };

      tests.full = let
        mapAttrsToOneList = f: set: lib.concatLists (lib.mapAttrsToList f set);

        mkCompilerPackages = compiler: req: mapAttrsToOneList (name: pkg: let
          majorVersion = req.matchAttr name;
          isEligible = lib.versionAtLeast (req.getVersion pkg) req.minVersion;
          getPackageAttrs = pkgs: { stdenv = req.getStdenv pkgs.${name}; };
        in lib.optional (majorVersion != null && isEligible) {
          name = "${compiler}${lib.head majorVersion}";
          value = lib.genAttrs req.systems (withSystemFull getPackageAttrs);
        }) nixpkgs.legacyPackages.x86_64-linux;

      in lib.listToAttrs (mapAttrsToOneList mkCompilerPackages {
        clang = {
          minVersion = "7";
          matchAttr = builtins.match "llvmPackages_([0-9]+)";
          getVersion = attr: attr.llvm.version;
          getStdenv = attr: attr.stdenv;
          systems = lib.singleton "x86_64-linux";
        };

        gcc = {
          minVersion = "7";
          matchAttr = builtins.match "gcc([0-9]+)Stdenv";
          getVersion = attr: attr.cc.version;
          getStdenv = lib.id;
          systems = hydraSystems;
        };
      });

      tests.repeat100 = fullForEachSystem (pkgs: {
        checkPhase = ''
          meson test --print-errorlogs --repeat=100
        '';
      });

      tests.no-hardening = fullForEachSystem (pkgs: {
        hardeningDisable = [ "all" ];
      });

      tests.vm = let
        makeTest = path: lib.genAttrs vmTestSystems (system: let
          libPath = nixpkgs + "/nixos/lib/testing-python.nix";
          testLib = import libPath { inherit system; };
        in testLib.makeTest (import path self));
      in {
        systemd-single = makeTest tests/vm/systemd-single.nix;
        systemd-multi = makeTest tests/vm/systemd-multi.nix;
      };

      tests.programs = let
        mkProgramTest = system: path: import path {
          pkgs = nixpkgs.legacyPackages.${system};
          inherit (self.packages.${system}) ip2unix;
        };
      in lib.mapAttrs (lib.const (lib.mapAttrs mkProgramTest)) {
        rsession.x86_64-linux = tests/programs/rsession.nix;
      };

      tests.sanitizer = lib.mapAttrs (name: let
        genDrv = { fun ? forEachSystem, override ? x: {} }: fun (super: {
          mesonFlags = [ "-Db_sanitize=${name}" ];
          mesonBuildType = "debug";
          disableHardening = [ "all" ];
          doInstallCheck = false;
          nativeBuildInputs = [ super.python3 ];
        } // override super);
      in genDrv) {
        # FIXME: Currently those do not work with integration tests because
        #        lib[at]san runtimes need to be the initial library to be
        #        loaded.
        address = {};

        thread.fun = fun: let
          supportedSystems = lib.remove "i686-linux" hydraSystems;
        in lib.genAttrs supportedSystems (withSystem fun);

        undefined.fun = fullForEachSystem;
      };

      coverage = fullForEachSystem (pkgs: {
        nativeBuildInputs = [ pkgs.lcov ];

        mesonFlags = [ "-Db_coverage=true" ];

        installPhase = ''
          ninja coverage-html 2>&1 | tee metrics.log >&2

          mkdir -p "$out/nix-support"
          sed -n -e '/^Overall coverage rate:$/,/^[^ ]/ {
            s/^ \+lines\.*: \([0-9.]\+\)%.*/lineCoverage \1 %/p
            s/^ \+functions\.*: \([0-9.]\+\)%.*/functionCoverage \1 %/p
          }' metrics.log > "$out/nix-support/hydra-metrics"

          if $(wc -l < "$out/nix-support/hydra-metrics") -ne 2; then
            echo "Failed to get coverage statistics." >&2
            exit 1
          fi

          mv meson-logs/coveragereport "$out/coverage"
          echo "report coverage $out/coverage" \
            > "$out/nix-support/hydra-build-products"
        '';

        doInstallCheck = false;
      });
    };
  };
}
