import argparse
import concurrent.futures
import socket
import socketserver
import sys
import threading


def make_handler(sotype):
    if sotype == 'tcp':
        def _handle(self):
            data = self.request.recv(20)
            self.request.sendall(data.upper())
    elif sotype == 'udp':
        def _handle(self):
            data = self.request[0]
            self.sendto(data.upper(), self.client_address)
    else:
        raise Exception('Unknown IP socket type')

    class _handler(socketserver.BaseRequestHandler):
        handle = _handle

    return _handler


def make_server(method, sotype, family):
    if method == 'threading':
        mixin = socketserver.ThreadingMixIn
    elif method == 'forking':
        mixin = socketserver.ForkingMixIn
    else:
        raise Exception('Unknown process method')

    if sotype == 'tcp':
        soserver = socketserver.TCPServer
    elif sotype == 'udp':
        soserver = socketserver.UDPServer
    else:
        raise Exception('Unknown IP socket type')

    class _server(mixin, soserver):
        address_family = family
        allow_reuse_address = True

    return _server


def client(ip, port, sotype, family):
    if sotype == 'tcp':
        socktype = socket.SOCK_STREAM
    elif sotype == 'udp':
        socktype = socket.SOCK_DGRAM
    else:
        raise Exception('Unknown IP socket type')

    with socket.socket(family, socktype) as sock:
        sock.connect((ip, port))
        sock.sendall(b'make this upper case')
        expected = b'MAKE THIS UPPER CASE'
        got = sock.recv(20)
        if got != expected:
            msg = 'Expected {!r} but got {!r}'.format(expected, got)
            raise AssertionError(msg)
        return True


if __name__ == '__main__':
    desc = 'Client/Server connection test helper'
    parser = argparse.ArgumentParser(description=desc)
    v4v6 = parser.add_mutually_exclusive_group()
    v4v6.add_argument('-4', '--inet4', action='store_false',
                      help='Use IPv4 for connection/listening')
    v4v6.add_argument('-6', '--inet6', action='store_true',
                      help='Use IPv6 for connection/listening')
    parser.add_argument('-t', '--sotype', choices=['tcp', 'udp'],
                        default='tcp', help='The socket type to use')
    parser.add_argument('-l', '--listen', action='store_true',
                        help='Listen instead of connect')
    parser.add_argument('-m', '--method', choices=['threading', 'forking'],
                        default='forking', help='The process method to use')
    parser.add_argument('-c', '--clients', type=int, default=1,
                        help='Amount of test clients to run')
    parser.add_argument('-p', '--parallel', type=int, default=None,
                        help='Amount of test clients to run in parallel')
    parser.add_argument('address', type=str,
                        help='The address to bind or connect to')
    parser.add_argument('port', type=int, help='The port to connect/listen on')
    args = parser.parse_args()

    if args.inet4:
        family = socket.AF_INET
    else:
        family = socket.AF_INET6

    if args.listen:
        srv = make_server(args.method, args.sotype, family)
        handler = make_handler(args.sotype)
        with srv((args.address, args.port), handler) as server:
            srvthread = threading.Thread(target=server.serve_forever)
            srvthread.daemon = True
            srvthread.start()
            sys.stdout.write('READY\n')
            sys.stdout.flush()
            sys.stdin.read(1)
            server.shutdown()
    else:
        if args.method == 'threading':
            pool = concurrent.futures.ThreadPoolExecutor
        elif args.method == 'forking':
            pool = concurrent.futures.ProcessPoolExecutor
        else:
            raise Exception('Unknown process method')
        with pool(max_workers=args.parallel) as executor:
            def cfun(iteration):
                return client(args.address, args.port, args.sotype, family)
            assert all(executor.map(cfun, range(args.clients)))
