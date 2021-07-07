{ packages, ... }:

{
  name = "ip2unix-systemd-multi";

  machine = { pkgs, lib, ... }: let
    inherit (packages.${pkgs.system}) ip2unix;

    testServer = pkgs.writeScript "test-server.py" ''
      #!${pkgs.python3.interpreter}
      from functools import partial
      from selectors import DefaultSelector, EVENT_READ
      from http.server import BaseHTTPRequestHandler, HTTPServer

      class TestHandler(BaseHTTPRequestHandler):
        def __init__(self, *args, reply, **kwargs):
          self.reply = reply
          super().__init__(*args, **kwargs)

        def do_GET(self):
          self.send_response(200)
          self.send_header('Content-Type', 'text/plain')
          self.send_header('X-Reply', self.reply)
          self.end_headers()
          self.wfile.write(self.reply.encode())

      selector = DefaultSelector()

      # Note that it's *intentional* here that the ports are in reverse order
      # than they are in the ip2unix invocation, because otherwise we'd get
      # rules matched in order.
      for port in [1113, 8090]:
        handler = partial(TestHandler, reply=f'port{port}')
        server = HTTPServer(('127.0.0.1', port), handler)
        selector.register(server, EVENT_READ, server.handle_request)

      while True:
        for event in selector.select():
          event[0].data()
    '';

  in {
    systemd.sockets.testsock1 = {
      description = "Test Socket 1 for Multiple Socket Test";
      wantedBy = [ "sockets.target" ];
      requiredBy = [ "socktest.service" ];
      socketConfig.ListenStream = "/run/test1.sock";
      socketConfig.FileDescriptorName = "socket1";
      socketConfig.Service = "socktest.service";
    };

    systemd.sockets.testsock2 = {
      description = "Test Socket 2 for Multiple Socket Test";
      wantedBy = [ "sockets.target" ];
      requiredBy = [ "socktest.service" ];
      socketConfig.ListenStream = "/run/test2.sock";
      socketConfig.FileDescriptorName = "socket2";
      socketConfig.Service = "socktest.service";
    };

    systemd.services.canary = {
      description = "Canary Service to verify implementation";
      after = [ "network.target" ];
      requiredBy = [ "multi-user.target" ];
      serviceConfig.User = "testuser";
      serviceConfig.Group = "testgroup";
      serviceConfig.ExecStart = testServer;
    };

    systemd.services.socktest = {
      description = "Test Service for Multiple Socket Test";
      serviceConfig.User = "testuser";
      serviceConfig.Group = "testgroup";
      serviceConfig.ExecStart = lib.escapeShellArgs [
        "${ip2unix}/bin/ip2unix"
        "-r" "in,tcp,port=8090,systemd=socket1"
        "-r" "in,tcp,port=1113,systemd=socket2"
        "-r" "out,ignore"
        testServer
      ];
    };

    users.users.testuser.isSystemUser = true;
    users.users.testuser.group = "testgroup";
    users.groups.testgroup = {};
  };

  testScript = ''
    # fmt: off
    machine.wait_for_unit('multi-user.target')

    for n, port in enumerate([8090, 1113], start=1):
      for args in [f'http://127.0.0.1:{port}/',
                   f'--unix-socket /run/test{n}.sock http://test/']:
        cmd = f'test "$(curl --no-progress-meter -v {args})" = port{port}'
        machine.succeed(cmd)
  '';
}
