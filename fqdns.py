import argparse
import socket
import logging
import sys
import os
import select
import contextlib
import time
import struct

import dpkt

import gevent.server
import gevent.monkey


LOGGER = logging.getLogger(__name__)


class DNSServer(gevent.server.DatagramServer):
    max_wait = 1
    max_retry = 2
    max_cache_size = 20000
    timeout = 6

    def handle(self, data, address):
        pass


def serve():
    pass


def resolve(domain, server_type, at, strategy, timeout):
    if ':' in at:
        server_ip, server_port = at.split(':')
        server_port = int(server_port)
    else:
        server_ip = at
        server_port = 53
    LOGGER.info('resolve %s at %s:%s' % (domain, server_ip, server_port))
    if 'udp' == server_type:
        return resolve_over_udp(domain, server_ip, server_port, strategy, timeout)
    elif 'tcp' == server_type:
        return resolve_over_tcp(domain, server_ip, server_port, timeout)
    else:
        raise Exception('unsupported server type: %s' % server_type)


def resolve_over_tcp(domain, server_ip, server_port, timeout):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    sock.settimeout(timeout)
    with contextlib.closing(sock):
        request = dpkt.dns.DNS(id=os.getpid(), qd=[dpkt.dns.DNS.Q(name=domain, type=dpkt.dns.DNS_A)])
        LOGGER.info('send request: %s' % repr(request))
        sock.connect((server_ip, server_port))
        data = str(request)
        sock.send(struct.pack('>h', len(data)) + data)
        rfile = sock.makefile('r', 512)
        data = rfile.read(2)
        data = rfile.read(struct.unpack('>h', data)[0])
        response = dpkt.dns.DNS(data)
        if response:
            return [socket.inet_ntoa(answer['rdata']) for answer in response.an]
        else:
            return []


def resolve_over_udp(domain, server_ip, server_port, strategy, timeout):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.settimeout(1)
    with contextlib.closing(sock):
        request = dpkt.dns.DNS(id=os.getpid(), qd=[dpkt.dns.DNS.Q(name=domain, type=dpkt.dns.DNS_A)])
        LOGGER.info('send request: %s' % repr(request))
        sock.sendto(str(request), (server_ip, server_port))
        response = read_response(sock, strategy, timeout)
        if response:
            return [socket.inet_ntoa(answer['rdata']) for answer in response.an]
        else:
            return []


def read_response(sock, strategy, timeout):
    response = None
    started_at = time.time()
    this_timeout = started_at + timeout - time.time()
    while this_timeout > 0:
        LOGGER.info('wait for %s seconds' % this_timeout)
        ins, outs, errors = select.select([sock], [], [sock], this_timeout)
        if sock in errors:
            raise Exception('failed to read dns response')
        if not ins:
            return response
        response = dpkt.dns.DNS(sock.recv(512))
        LOGGER.info('received response: %s' % repr(response))
        if 'pick-first' == strategy:
            return response
        this_timeout = started_at + timeout - time.time()
    return response

# TODO multiple --at
# TODO --recursive
# TODO multiple domain
# TODO concurrent query
# TODO pick-right pick-right-later with multiple --wrong-answer
# TODO --auto-discover-wrong-answers
# TODO --record-type

if '__main__' == __name__:
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    argument_parser = argparse.ArgumentParser()
    sub_parsers = argument_parser.add_subparsers()
    resolve_parser = sub_parsers.add_parser('resolve', help='start as dns client')
    resolve_parser.add_argument('domain')
    resolve_parser.add_argument('--at', help='dns server', default='8.8.8.8:53')
    resolve_parser.add_argument(
        '--strategy', help='anti-gfw strategy', default='pick-first',
        choices=['pick-first', 'pick-later'])
    resolve_parser.add_argument('--timeout', help='in seconds', default=1, type=float)
    resolve_parser.add_argument('--server-type', default='udp', choices=['udp', 'tcp'])
    resolve_parser.set_defaults(handler=resolve)
    serve_parser = sub_parsers.add_parser('serve', help='start as dns server')
    serve_parser.set_defaults(handler=serve)
    args = argument_parser.parse_args()
    sys.stderr.write(repr(args.handler(**{k: getattr(args, k) for k in vars(args) if k != 'handler'})))
    sys.stderr.write('\n')