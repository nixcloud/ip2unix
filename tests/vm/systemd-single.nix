{ packages, ... }:

{
  name = "ip2unix-systemd-single";

  nodes.server = { config, pkgs, lib, ... }: let
    inherit (packages.${config.nixpkgs.system}) ip2unix;

    testServer = pkgs.writeScript "test-server.py" ''
      #!${pkgs.python3.interpreter}
      import socket, sys
      from http.server import BaseHTTPRequestHandler, HTTPServer

      IS_UNIX = len(sys.argv) == 3

      class TestServer(HTTPServer):
        address_family = getattr(socket, sys.argv[1])

      class TestHandler(BaseHTTPRequestHandler):
        def address_string(self):
          if IS_UNIX:
            return self.client_address
          else:
            return self.client_address[0]

        def do_GET(self):
          self.send_response(200)
          self.send_header('Content-Type', 'text/plain')
          self.end_headers()
          self.wfile.write(self.address_string().encode())

      if IS_UNIX:
        laddr = sys.argv[2]
      else:
        laddr = (sys.argv[2], int(sys.argv[3]))

      TestServer(laddr, TestHandler).serve_forever()
    '';

    mkTestService = name: desc: socketConfig: serverArgs: {
      systemd.sockets."test-${name}" = {
        description = "Test Socket for ${desc}";
        wantedBy = [ "sockets.target" ];
        requiredBy = [ "test-${name}.service" ];

        inherit socketConfig;
      };

      systemd.services."test-${name}" = {
        description = "Test Service for ${desc}";

        serviceConfig.PrivateNetwork = true;
        serviceConfig.ExecStart = lib.escapeShellArgs ([
          "${ip2unix}/bin/ip2unix" "-r" "systemd" testServer
        ] ++ serverArgs);
        serviceConfig.User = "testuser";
        serviceConfig.Group = "testgroup";
      };
    };

  in {
    imports = [
      (mkTestService "unix" "Unix" {
        ListenStream = "/run/test-unix.sock";
      } [ "AF_INET" "5.6.7.8" 99 ])

      (mkTestService "inet4" "IPv4" {
        ListenStream = "0.0.0.0:4";
      } [ "AF_INET" "9.10.11.12" 99 ])

      (mkTestService "inet6" "IPv6" {
        ListenStream = "[::]:6";
      } [ "AF_INET6" "dead::beef" 99 ])
    ];

    users.users.testuser.isSystemUser = true;
    users.users.testuser.group = "testgroup";
    users.groups.testgroup = {};

    networking.interfaces.eth1.ipv6.addresses = lib.singleton {
      address = "2000:3000::1";
      prefixLength = 64;
    };

    networking.firewall.enable = false;
  };

  nodes.client = { lib, ... }: {
    networking.firewall.enable = false;
    networking.interfaces.eth1.ipv6.addresses = lib.singleton {
      address = "2000:3000::2";
      prefixLength = 64;
    };
  };

  testScript = { nodes, ... }: let
    inherit (nodes.client.networking) primaryIPAddress;
  in ''
    start_all()
    server.wait_for_unit('multi-user.target')

    server.succeed('curl -vvv --unix-socket /run/test-unix.sock http://t/')
    client.succeed(
      'test "$(curl -vvv http://server:4/)" = ${primaryIPAddress}',
      'test "$(curl -vvv "http://[2000:3000::1]:6/")" = 2000:3000::2',
    )
  '';
}
