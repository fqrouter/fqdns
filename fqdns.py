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


def main():
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1, thread=False)
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    argument_parser = argparse.ArgumentParser()
    sub_parsers = argument_parser.add_subparsers()
    resolve_parser = sub_parsers.add_parser('resolve', help='start as dns client')
    resolve_parser.add_argument('domain')
    resolve_parser.add_argument('--at', help='dns server', default='8.8.8.8:53')
    resolve_parser.add_argument(
        '--strategy', help='anti-GFW strategy', default='pick-right',
        choices=['pick-first', 'pick-later', 'pick-right', 'pick-right-later', 'pick-all'])
    resolve_parser.add_argument('--wrong-answer', help='wrong answer forged by GFW', nargs='*')
    resolve_parser.add_argument('--timeout', help='in seconds', default=1, type=float)
    resolve_parser.add_argument('--server-type', default='udp', choices=['udp', 'tcp'])
    resolve_parser.add_argument('--record-type', default='A', choices=['A', 'TXT'])
    resolve_parser.set_defaults(handler=resolve)
    discover_parser = sub_parsers.add_parser('discover', help='resolve black listed domain to discover wrong answers')
    discover_parser.add_argument('--at', help='dns server', default='8.8.8.8:53')
    discover_parser.add_argument('--timeout', help='in seconds', default=1, type=float)
    discover_parser.add_argument('--repeat', help='repeat query for each domain many times', default=30, type=int)
    discover_parser.add_argument('--only-new', help='only show the new wrong answers', action='store_true')
    discover_parser.add_argument('domain', nargs='*', help='black listed domain such as twitter.com')
    discover_parser.set_defaults(handler=discover)
    serve_parser = sub_parsers.add_parser('serve', help='start as dns server')
    serve_parser.set_defaults(handler=serve)
    args = argument_parser.parse_args()
    sys.stderr.write(repr(args.handler(**{k: getattr(args, k) for k in vars(args) if k != 'handler'})))
    sys.stderr.write('\n')


class DNSServer(gevent.server.DatagramServer):
    max_wait = 1
    max_retry = 2
    max_cache_size = 20000
    timeout = 6

    def handle(self, data, address):
        pass


def serve():
    pass


def resolve(record_type, domain, server_type, at, timeout, strategy, wrong_answer):
    server_ip, server_port = parse_at(at)
    LOGGER.info('resolve %s [%s] at %s:%s' % (domain, record_type, server_ip, server_port))
    record_type = getattr(dpkt.dns, 'DNS_%s' % record_type)
    if 'udp' == server_type:
        wrong_answers = set(wrong_answer) if wrong_answer else set()
        wrong_answers |= BUILTIN_WRONG_ANSWERS()
        return resolve_over_udp(
            record_type, domain, server_ip, server_port, timeout, strategy, wrong_answers)
    elif 'tcp' == server_type:
        return resolve_over_tcp(record_type, domain, server_ip, server_port, timeout)
    else:
        raise Exception('unsupported server type: %s' % server_type)


def parse_at(at):
    if ':' in at:
        server_ip, server_port = at.split(':')
        server_port = int(server_port)
    else:
        server_ip = at
        server_port = 53
    return server_ip, server_port


def resolve_over_tcp(record_type, domain, server_ip, server_port, timeout):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    sock.setblocking(0)
    with contextlib.closing(sock):
        request = dpkt.dns.DNS(id=os.getpid(), qd=[dpkt.dns.DNS.Q(name=domain, type=record_type)])
        LOGGER.info('send request: %s' % repr(request))
        sock.settimeout(1)
        try:
            sock.connect((server_ip, server_port))
        except:
            LOGGER.exception('failed to connect to %s:%s' % (server_ip, server_port))
            return []
        sock.settimeout(None)
        data = str(request)
        sock.send(struct.pack('>h', len(data)) + data)
        ins, outs, errors = select.select([sock], [], [sock], timeout)
        if errors:
            LOGGER.error('failed to read dns response')
            return []
        if not ins:
            return []
        rfile = sock.makefile('r', 512)
        data = rfile.read(2)
        data = rfile.read(struct.unpack('>h', data)[0])
        response = dpkt.dns.DNS(data)
        if response:
            if dpkt.dns.DNS_A == record_type:
                return list_ipv4_addresses(response)
            else:
                return [answer.rdata for answer in response.an]
        else:
            return []


def resolve_over_udp(record_type, domain, server_ip, server_port, timeout, strategy, wrong_answers):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.setblocking(0)
    with contextlib.closing(sock):
        request = dpkt.dns.DNS(id=os.getpid(), qd=[dpkt.dns.DNS.Q(name=domain, type=record_type)])
        LOGGER.info('send request: %s' % repr(request))
        sock.sendto(str(request), (server_ip, server_port))
        if dpkt.dns.DNS_A == record_type:
            responses = pick_responses(sock, timeout, strategy, wrong_answers)
            if len(responses) == 1:
                return list_ipv4_addresses(responses[0])
            elif len(responses) > 1:
                return [list_ipv4_addresses(response) for response in responses]
            else:
                return []
        else:
            ins, outs, errors = select.select([sock], [], [sock], timeout)
            if errors:
                LOGGER.error('failed to read dns response')
                return []
            if not ins:
                return []
            response = dpkt.dns.DNS(sock.recv(512))
            return [answer.rdata for answer in response.an]


def pick_responses(sock, timeout, strategy, wrong_answers):
    picked_responses = []
    started_at = time.time()
    remaining_timeout = started_at + timeout - time.time()
    while remaining_timeout > 0:
        LOGGER.info('wait for max %s seconds' % remaining_timeout)
        ins, outs, errors = select.select([sock], [], [sock], remaining_timeout)
        if errors:
            LOGGER.error('failed to read dns response')
            return []
        if not ins:
            return picked_responses
        response = dpkt.dns.DNS(sock.recv(512))
        LOGGER.info('received response: %s' % repr(response))
        if 'pick-first' == strategy:
            return [response]
        elif 'pick-later' == strategy:
            picked_responses = [response]
        elif 'pick-right' == strategy:
            if is_right_response(response, wrong_answers):
                return [response]
        elif 'pick-right-later' == strategy:
            if is_right_response(response, wrong_answers):
                picked_responses = [response]
        elif 'pick-all' == strategy:
            picked_responses.append(response)
        else:
            raise Exception('unsupported strategy: %s' % strategy)
        remaining_timeout = started_at + timeout - time.time()
    return picked_responses


def is_right_response(response, wrong_answers):
    answers = list_ipv4_addresses(response)
    if not answers: # GFW can forge empty response
        return False
    if len(answers) > 1: # GFW does not forge response with more than one answer
        return True
    return not any(answer in wrong_answers for answer in answers)


def list_ipv4_addresses(response):
    return [socket.inet_ntoa(answer.rdata) for answer in response.an if dpkt.dns.DNS_A == answer.type]


def discover(domain, at, timeout, repeat, only_new):
    server_ip, server_port = parse_at(at)
    domains = domain or [
        'facebook.com', 'youtube.com', 'twitter.com', 'plus.google.com', 'drive.google.com']
    wrong_answers = set()
    greenlets = []
    for domain in domains:
        right_answers = resolve_over_tcp(domain, server_ip, server_port, timeout * 2)
        right_answer = right_answers[0] if right_answers else None
        for i in range(repeat):
            greenlets.append(gevent.spawn(discover_once, domain, server_ip, server_port, timeout, right_answer))
    for greenlet in greenlets:
        wrong_answers |= greenlet.get()
    if only_new:
        return wrong_answers - BUILTIN_WRONG_ANSWERS()
    else:
        return wrong_answers


def discover_once(domain, server_ip, server_port, timeout, right_answer):
    wrong_answers = set()
    responses_answers = resolve_over_udp(domain, server_ip, server_port, timeout, 'pick-all', set())
    contains_right_answer = any(len(answers) > 1 for answers in responses_answers)
    if right_answer or contains_right_answer:
        for answers in responses_answers:
            if len(answers) == 1 and answers[0] != right_answer:
                wrong_answers |= set(answers)
    return wrong_answers


def BUILTIN_WRONG_ANSWERS():
    return {
        '4.36.66.178',
        '8.7.198.45',
        '37.61.54.158',
        '46.82.174.68',
        '59.24.3.173',
        '64.33.88.161',
        '64.33.99.47',
        '64.66.163.251',
        '65.104.202.252',
        '65.160.219.113',
        '66.45.252.237',
        '72.14.205.99',
        '72.14.205.104',
        '78.16.49.15',
        '93.46.8.89',
        '128.121.126.139',
        '159.106.121.75',
        '169.132.13.103',
        '192.67.198.6',
        '202.106.1.2',
        '202.181.7.85',
        '203.161.230.171',
        '203.98.7.65',
        '207.12.88.98',
        '208.56.31.43',
        '209.36.73.33',
        '209.145.54.50',
        '209.220.30.174',
        '211.94.66.147',
        '213.169.251.35',
        '216.221.188.182',
        '216.234.179.13',
        '243.185.187.39',
        # plus.google.com
        '74.125.127.102',
        '74.125.155.102',
        '74.125.39.113',
        '74.125.39.102',
        '209.85.229.138'
    }

# TODO multiple --at
# TODO --recursive
# TODO multiple domain
# TODO concurrent query
# TODO pick-right pick-right-later with multiple --wrong-answer
# TODO --auto-discover-wrong-answers
# TODO --record-type

if '__main__' == __name__:
    main()