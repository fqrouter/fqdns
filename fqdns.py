import argparse
import socket
import logging
import sys
import os
import select
import contextlib
import time

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


def resolve(domain, at, port, strategy, timeout):
    LOGGER.info('resolve %s at %s:%s' % (domain, at, port))
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    with contextlib.closing(sock):
        request = dpkt.dns.DNS(id=os.getpid(), qd=[dpkt.dns.DNS.Q(name=domain, type=dpkt.dns.DNS_A)])
        LOGGER.info('send request: %s' % repr(request))
        sock.sendto(str(request), (at, port))
        response = None
        started_at = time.time()
        this_timeout = started_at + timeout - time.time()
        while this_timeout > 0:
            LOGGER.info('wait for %s seconds' % this_timeout)
            ins, outs, errors = select.select([sock], [], [sock], this_timeout)
            if sock in errors:
                raise Exception('failed to read dns response')
            if not ins:
                break
            response = dpkt.dns.DNS(sock.recv(512))
            LOGGER.info('received response: %s' % repr(response))
            if 'pick-first' == strategy:
                break
            this_timeout = started_at + timeout - time.time()
        if response:
            return [socket.inet_ntoa(answer['rdata']) for answer in response.an]
        else:
            return []


if '__main__' == __name__:
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    argument_parser = argparse.ArgumentParser()
    sub_parsers = argument_parser.add_subparsers()
    resolve_parser = sub_parsers.add_parser('resolve', help='start as dns client')
    resolve_parser.add_argument('domain')
    resolve_parser.add_argument('--at', help='dns server ip', default='8.8.8.8')
    resolve_parser.add_argument('--port', help='dns server port', type=int, default=53)
    resolve_parser.add_argument(
        '--strategy', help='anti-gfw strategy', default='pick-first',
        choices=['pick-first', 'pick-later'])
    resolve_parser.add_argument('--timeout', help='in seconds', default=1, type=float)
    resolve_parser.set_defaults(handler=resolve)
    serve_parser = sub_parsers.add_parser('serve', help='start as dns server')
    serve_parser.set_defaults(handler=serve)
    args = argument_parser.parse_args()
    sys.stderr.write(repr(args.handler(**{k: getattr(args, k) for k in vars(args) if k != 'handler'})))
    sys.stderr.write('\n')