import argparse
import socket
import logging
import sys
import os
import select
import contextlib
import time
import struct
import json
import dpkt

import gevent.server
import gevent.queue
import gevent.monkey


LOGGER = logging.getLogger(__name__)

ERROR_NO_DATA = 11


def main():
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1, thread=False)
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    argument_parser = argparse.ArgumentParser()
    sub_parsers = argument_parser.add_subparsers()
    resolve_parser = sub_parsers.add_parser('resolve', help='start as dns client')
    resolve_parser.add_argument('domain', help='one or more domain names to query', nargs='+')
    resolve_parser.add_argument(
        '--at', help='one or more dns servers', default=[], action='append')
    resolve_parser.add_argument(
        '--strategy', help='anti-GFW strategy, for UDP only', default='pick-right',
        choices=['pick-first', 'pick-later', 'pick-right', 'pick-right-later', 'pick-all'])
    resolve_parser.add_argument(
        '--wrong-answer', help='wrong answer forged by GFW, for UDP only', action='append')
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
    serve_parser.add_argument('--local', help='local address bind to', default='*:53')
    serve_parser.add_argument('--upstream', help='upstream dns server forwarding to', default=[], action='append')
    serve_parser.add_argument('--direct', help='direct forward to first upstream via UDP', action='store_true')
    serve_parser.set_defaults(handler=serve)
    args = argument_parser.parse_args()
    sys.stderr.write(json.dumps(args.handler(**{k: getattr(args, k) for k in vars(args) if k != 'handler'})))
    sys.stderr.write('\n')


def serve(local, upstream, direct):
    address = parse_ip_colon_port(local)
    upstreams = [parse_ip_colon_port(e) for e in upstream] or [('8.8.8.8', 53)]
    server = DNSServer(address, upstreams, direct)
    logging.info('dns server started at %r, forwarding to %r', address, upstreams)
    server.serve_forever()


class DNSServer(gevent.server.DatagramServer):
    def __init__(self, address, upstreams, direct):
        super(DNSServer, self).__init__(address)
        self.upstreams = upstreams
        self.direct = direct

    def handle(self, raw_request, address):
        request = dpkt.dns.DNS(raw_request)
        LOGGER.info('received downstream request: %s' % repr(request))
        domains = [question.name for question in request.qd if dpkt.dns.DNS_A == question.type]
        if len(domains) == 1 and not self.direct:
            domain = domains[0]
            response = dpkt.dns.DNS(raw_request)
            if not self.query_smartly(domain, response):
                return # let client retry
        else:
            response = self.query_first_upstream_via_udp(request)
        LOGGER.info('forward to downstream response: %s' % repr(response))
        self.sendto(str(response), address)

    def query_smartly(self, domain, response):
        answers = resolve(dpkt.dns.DNS_A, [domain], 'udp', self.upstreams, 1).get(domain)
        if not answers:
            return False
        response.an = [dpkt.dns.DNS.RR(
            name=domain, type=dpkt.dns.DNS_A, ttl=3600,
            rlen=len(socket.inet_aton(answer)),
            rdata=socket.inet_aton(answer)) for answer in answers]
        return True

    def query_first_upstream_via_udp(self, request):
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        with contextlib.closing(sock):
            sock.sendto(str(request), self.upstreams[0])
            return dpkt.dns.DNS(sock.recv(512))


def resolve(record_type, domain, server_type, at, timeout, strategy='pick-right', wrong_answer=()):
    if isinstance(record_type, basestring):
        record_type = getattr(dpkt.dns, 'DNS_%s' % record_type)
    servers = [parse_ip_colon_port(e) for e in at] or [('8.8.8.8', 53)]
    domains = set(domain)
    greenlets = []
    queue = gevent.queue.Queue()
    try:
        for domain in domains:
            for server in servers:
                server_ip, server_port = server
                greenlets.append(gevent.spawn(
                    resolve_one, record_type, domain, server_type,
                    server_ip, server_port, timeout - 0.1, strategy, wrong_answer, queue=queue))
        started_at = time.time()
        domains_answers = {}
        remaining_timeout = started_at + timeout - time.time()
        while remaining_timeout > 0:
            try:
                domain, answers = queue.get(timeout=remaining_timeout)
                domains_answers[domain] = answers
                if len(domains_answers) == len(domains):
                    return domains_answers
            except gevent.queue.Empty:
                LOGGER.warn('did not finish resovling: %s' % (domains - set(domains_answers.keys())))
                return domains_answers
        return domains_answers
    finally:
        for greenlet in greenlets:
            greenlet.kill(block=False)


def parse_ip_colon_port(ip_colon_port):
    if not isinstance(ip_colon_port, basestring):
        return ip_colon_port
    if ':' in ip_colon_port:
        server_ip, server_port = ip_colon_port.split(':')
        server_port = int(server_port)
    else:
        server_ip = ip_colon_port
        server_port = 53
    return '' if '*' == server_ip else server_ip, server_port


def resolve_one(record_type, domain, server_type, server_ip, server_port, timeout, strategy, wrong_answer, queue=None):
    try:
        LOGGER.info('resolve %s at %s:%s' % (domain, server_ip, server_port))
        if 'udp' == server_type:
            wrong_answers = set(wrong_answer) if wrong_answer else set()
            wrong_answers |= BUILTIN_WRONG_ANSWERS()
            answers = resolve_over_udp(
                record_type, domain, server_ip, server_port, timeout, strategy, wrong_answers)
            if answers and queue:
                queue.put((domain, answers))
            return answers
        elif 'tcp' == server_type:
            answers = resolve_over_tcp(record_type, domain, server_ip, server_port, timeout)
            if answers and queue:
                queue.put((domain, answers))
            return answers
        else:
            LOGGER.error('unsupported server type: %s' % server_type)
            return []
    except:
        LOGGER.exception('failed to resolve one: %s' % domain)
        return []


def resolve_over_tcp(record_type, domain, server_ip, server_port, timeout):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    with contextlib.closing(sock):
        sock.setblocking(0)
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
    with contextlib.closing(sock):
        sock.setblocking(0)
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
            try:
                response = dpkt.dns.DNS(receive(sock, time.time() + timeout))
                LOGGER.info('received response: %s' % repr(response))
                return [answer.rdata for answer in response.an]
            except SocketTimeout:
                return []


def receive(sock, deadline, size=512):
    remaining_timeout = deadline - time.time()
    while remaining_timeout > 0:
        LOGGER.info('wait for max %s seconds' % remaining_timeout)
        ins, outs, errors = select.select([sock], [], [sock], remaining_timeout)
        if errors:
            LOGGER.error('failed to receive')
            raise Exception('failed to receive')
        if sock not in ins:
            raise SocketTimeout()
        try:
            return sock.recv(size)
        except socket.error, e:
            if ERROR_NO_DATA == e[0]:
                remaining_timeout = deadline - time.time()
                continue
            raise
    raise SocketTimeout()


def pick_responses(sock, timeout, strategy, wrong_answers):
    picked_responses = []
    started_at = time.time()
    deadline = started_at + timeout
    remaining_timeout = deadline - time.time()
    while remaining_timeout > 0:
        try:
            response = dpkt.dns.DNS(receive(sock, deadline))
        except SocketTimeout:
            return picked_responses
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
    server_ip, server_port = parse_ip_colon_port(at)
    domains = domain or [
        'facebook.com', 'youtube.com', 'twitter.com', 'plus.google.com', 'drive.google.com']
    wrong_answers = set()
    greenlets = []
    for domain in domains:
        right_answers = resolve_over_tcp(dpkt.dns.DNS_A, domain, server_ip, server_port, timeout * 2)
        right_answer = right_answers[0] if right_answers else None
        for i in range(repeat):
            greenlets.append(gevent.spawn(
                discover_one, domain, server_ip, server_port, timeout, right_answer))
    for greenlet in greenlets:
        wrong_answers |= greenlet.get()
    if only_new:
        return wrong_answers - BUILTIN_WRONG_ANSWERS()
    else:
        return wrong_answers


def discover_one(domain, server_ip, server_port, timeout, right_answer):
    wrong_answers = set()
    responses_answers = resolve_over_udp(
        dpkt.dns.DNS_A, domain, server_ip, server_port, timeout, 'pick-all', set())
    contains_right_answer = any(len(answers) > 1 for answers in responses_answers)
    if right_answer or contains_right_answer:
        for answers in responses_answers:
            if len(answers) == 1 and answers[0] != right_answer:
                wrong_answers |= set(answers)
    return wrong_answers


class SocketTimeout(BaseException):
    pass


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

# TODO IPV6
# TODO complete record types
# TODO --recursive

if '__main__' == __name__:
    main()