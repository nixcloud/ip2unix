{ pkgs ? import <nixpkgs> {}
, lib ? pkgs.lib
, hydraUrl ? "https://headcounter.org/hydra"
, hydraJobset ? "ip2unix/master"
, constituents
}:

let
  # SHA1 hash collisions from https://shattered.io/static/shattered.pdf:
  collisions = pkgs.runCommand "sha1-collisions" {
    outputs = [ "out" "good" "bad" ];
    base64 = ''
      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
      y+VeTA==
    '';
  } ''
    echo "$base64" | base64 -d | tar xj
    mv good.pdf "$good"
    mv bad.pdf "$bad"
    touch "$out"
  '';

  closureHash = let
    inherit (builtins) unsafeDiscardStringContext;
    drvMap = map (x: unsafeDiscardStringContext x.drvPath) constituents;
  in builtins.hashString "sha256" (builtins.toJSON drvMap);

  drvName = "badge-${closureHash}";

  mkNode = nodeName: attrs: children: let
    mkAttr = name: value: "${name}=\"${toString value}\"";
    attrListStr = lib.concatStringsSep " " (lib.mapAttrsToList mkAttr attrs);
    start = "<${nodeName} ${attrListStr}";
    withChildren = "${start}>${lib.concatStrings children}</${nodeName}>";
  in if children == [] then "${start}/>" else withChildren;

  badgePassing = mkBadge {
    status = "passing";
    color = "#4c1";
    width = 94;
    height = 51;
    x = 675;
    textLength = 410;
  };

  badgeFailing = mkBadge {
    status = "failing";
    color = "#e05d44";
    width = 86;
    height = 43;
    x = 635;
    textLength = 330;
  };

  mkBadge = attrs: pkgs.writeText "builds-${attrs.status}.svg" (mkNode "svg" {
    xmlns = "http://www.w3.org/2000/svg";
    inherit (attrs) width;
    height = 20;
  } [
    (mkNode "linearGradient" {
      id = "b";
      x2 = "0";
      y2 = "100%";
    } [
      (mkNode "stop" {
        offset = "0";
        stop-color = "#bbb";
        stop-opacity = ".1";
      } [])
      (mkNode "stop" {
        offset = 1;
        stop-opacity = ".1";
      } [])
    ])
    (mkNode "clipPath" {
      id = "a";
    } [
      (mkNode "rect" {
        inherit (attrs) width;
        height = 20;
        rx = 3;
        fill = "#fff";
      } [])
    ])
    (mkNode "g" {
      clip-path = "url(#a)";
    } [
      (mkNode "path" {
        fill = "#555";
        d = "M0 0h43v20H0z";
      } [])
      (mkNode "path" {
        fill = attrs.color;
        d = "M43 0h${toString attrs.height}v20H43z";
      } [])
      (mkNode "path" {
        fill = "url(#b)";
        d = "M0 0h${toString attrs.width}v20H0z";
      } [])
    ])
    (mkNode "g" {
      fill = "#fff";
      text-anchor = "middle";
      font-family = "DejaVu Sans,Verdana,Geneva,sans-serif";
      font-size = 110;
    } [
      " "
      (mkNode "text" {
        x = 225;
        y = 150;
        fill = "#010101";
        fill-opacity = ".3";
        transform = "scale(.1)";
        textLength = 330;
      } [ "builds" ])
      (mkNode "text" {
        x = 225;
        y = 140;
        transform = "scale(.1)";
        textLength = 330;
      } [ "builds" ])
      (mkNode "text" {
        inherit (attrs) x textLength;
        y = 150;
        fill = "#010101";
        fill-opacity = ".3";
        transform = "scale(.1)";
      } [ attrs.status ])
      (mkNode "text" {
        inherit (attrs) x textLength;
        y = 140;
        transform = "scale(.1)";
      } [ attrs.status ])
    ])
  ]);

in pkgs.runCommand drvName {
  failureCheck = pkgs.runCommand drvName {
    inherit hydraUrl hydraJobset;
    nativeBuildInputs = [ pkgs.jq pkgs.curl ];
    SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    outputHashMode = "flat";
    outputHashAlgo = "sha1";
    outputHash = "d00bbe65d80f6d53d5c15da7c6b4f0a655c5a86a";
  } ''
    jcurl() {
      retval=22
      retries=0
      while [ $retval -ne 0 -a $retries -le 1000 ]; do
        set +e
        out="$(curl -f -s -H 'Accept: application/json' "$@")"
        retval=$?
        set -e
        if [ $retval -ne 0 ]; then sleep 0.1; fi
        retries=$(($retries + 1))
      done
      if [ $retval -ne 0 ]; then
        echo "Hydra API not available after 100 seconds, giving up." >&2
        exit 1
      fi
      echo "$out"
    }

    evalsBuilds="$(jcurl "$hydraUrl/jobset/$hydraJobset/evals" | jq -r '
      .evals | map(
        (.id | tostring) + ":" + (.builds | map(tostring) | join(","))
      ) | @tsv
    ')"

    found=0
    for evalBuilds in $evalsBuilds; do
      eval="''${evalBuilds%%:*}"
      builds="''${evalBuilds#*:}"
      for build in ''${builds//,/ }; do
        if nixname="$(jcurl "$hydraUrl/build/$build" | jq -r .nixname)"; then
          if [ "$nixname" = "$name" ]; then found=1; break; fi
        fi
      done
      if [ $found -eq 1 ]; then break; fi
    done

    if [ $found -eq 0 ]; then
      echo "Unable to find badge job in $hydraJobset." >&2
      exit 1
    fi

    for build in ''${builds//,/ }; do
      finished=0
      while [ "$finished" -ne 1 ]; do
        finStatusName="$(jcurl "$hydraUrl/build/$build" | jq -r '
          (.finished | tostring) + ":" +
          (.buildstatus | tostring) + "!" +
          .nixname
        ')"
        if [ "''${finStatusName#*!}" = "$name" ]; then
          finStatus="1:0"
        else
          finStatus="''${finStatusName%%!*}"
        fi
        finished="''${finStatus%%:*}"
        if [ "$finished" -ne 1 ]; then sleep 1; fi
      done
      if [ "''${finStatus##*:}" -ne 0 ]; then
        cp ${lib.escapeShellArg collisions.bad} "$out"
        exit 0
      fi
    done

    cp ${lib.escapeShellArg collisions.good} "$out"
    exit 0
  '';
} ''
  mkdir -p "$out/nix-support"

  if cmp "$failureCheck" ${pkgs.lib.escapeShellArg collisions.good}; then
    cp ${lib.escapeShellArg badgePassing} "$out/status.svg"
  else
    cp ${lib.escapeShellArg badgeFailing} "$out/status.svg"
  fi

  echo "report badge $out status.svg" > "$out/nix-support/hydra-build-products"
''
