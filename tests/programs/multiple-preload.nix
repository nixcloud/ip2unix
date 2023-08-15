{ pkgs, ip2unix, ... }:

pkgs.runCommand "multiple-preload" {
  TSOCKS_DEBUG = 10;
  TSOCKS_CONF_FILE = pkgs.writeText "tsocks.conf" ''
    server = 127.0.0.2
  '';

  nativeBuildInputs = [
    ip2unix
    pkgs.tsocks
    pkgs.netcat-openbsd

    (pkgs.writeScriptBin "socksd" ''
      #!${(pkgs.python3.withPackages (p: [ p.tiny-proxy ])).interpreter}
      import anyio
      from tiny_proxy import Socks4ProxyHandler

      async def main():
        handler = Socks4ProxyHandler()
        listener = await anyio.create_tcp_listener()
        await listener.serve(handler.handle)

      anyio.run(main)
    '')

    (pkgs.writeScriptBin "testprog" ''
      #!${pkgs.python3.interpreter}
      import socket
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(('1.2.3.4', 1234))
        assert sock.recv(3) == b'foo'
    '')
  ];
} ''
  echo foo | nc -N -lU foo.sock &
  while [ ! -e foo.sock ]; do sleep 1; done

  ip2unix -r in,path=bar.sock -r out,path=foo.sock socksd &
  while [ ! -e bar.sock ]; do sleep 1; done

  ip2unix -vvvvv -r out,addr=127.0.0.2,path=bar.sock tsocks testprog
  touch "$out"
''
