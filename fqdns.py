#!/usr/bin/env python
# thanks @phuslu https://github.com/phus/dnsproxy/blob/master/dnsproxy.py
# thanks @ofmax https://github.com/madeye/gaeproxy/blob/master/assets/modules/python.mp3
import argparse
import socket
import logging
import logging.handlers
import sys
import select
import contextlib
import time
import struct
import json
import random

import dpkt
import gevent.server
import gevent.queue
import gevent.monkey


LOGGER = logging.getLogger('fqdns')

ERROR_NO_DATA = 11
SO_MARK = 36
OUTBOUND_MARK = 0
OUTBOUND_IP = None
SPI = {}


def main():
    global OUTBOUND_MARK
    global OUTBOUND_IP
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('--log-file')
    argument_parser.add_argument('--log-level', choices=['INFO', 'DEBUG'], default='INFO')
    argument_parser.add_argument('--outbound-mark', help='for example 0xcafe, set to every packet send out',
                                 default='0')
    argument_parser.add_argument('--outbound-ip', help='the ip address for every packet send out')
    sub_parsers = argument_parser.add_subparsers()
    resolve_parser = sub_parsers.add_parser('resolve', help='start as dns client')
    resolve_parser.add_argument('domain')
    resolve_parser.add_argument(
        '--at', help='one or more dns servers', default=[], action='append')
    resolve_parser.add_argument(
        '--strategy', help='anti-GFW strategy, for UDP only', default='pick-right',
        choices=['pick-first', 'pick-later', 'pick-right', 'pick-right-later', 'pick-all'])
    resolve_parser.add_argument('--timeout', help='in seconds', default=1, type=float)
    resolve_parser.add_argument('--record-type', default='A', choices=['A', 'TXT'])
    resolve_parser.add_argument('--retry', default=1, type=int)
    resolve_parser.set_defaults(handler=resolve)
    discover_parser = sub_parsers.add_parser('discover', help='resolve black listed domain to discover wrong answers')
    discover_parser.add_argument('--at', help='dns server', default='8.8.8.8:53')
    discover_parser.add_argument('--timeout', help='in seconds', default=1, type=float)
    discover_parser.add_argument('--repeat', help='repeat query for each domain many times', default=30, type=int)
    discover_parser.add_argument('--only-new', help='only show the new wrong answers', action='store_true')
    discover_parser.add_argument(
        '--domain', help='black listed domain such as twitter.com', default=[], action='append')
    discover_parser.set_defaults(handler=discover)
    serve_parser = sub_parsers.add_parser('serve', help='start as dns server')
    serve_parser.add_argument('--listen', help='local address bind to', default='*:53')
    serve_parser.add_argument(
        '--upstream', help='upstream dns server forwarding to for non china domain', default=[], action='append')
    serve_parser.add_argument(
        '--china-upstream', help='upstream dns server forwarding to for china domain', default=[], action='append')
    serve_parser.add_argument(
        '--original-upstream', help='the original dns server')
    serve_parser.add_argument(
        '--hosted-domain', help='the domain a.com will be transformed to a.com.b.com', default=[], action='append')
    serve_parser.add_argument(
        '--hosted-at', help='the domain b.com will host a.com.b.com')
    serve_parser.add_argument(
        '--enable-china-domain', help='otherwise china domain will not query against china-upstreams',
        action='store_true')
    serve_parser.add_argument(
        '--enable-hosted-domain', help='otherwise hosted domain will not query with suffix hosted-at',
        action='store_true')
    serve_parser.add_argument(
        '--fallback-timeout', help='fallback from udp to tcp after timeout, in seconds')
    serve_parser.add_argument(
        '--strategy', help='anti-GFW strategy, for UDP only', default='pick-right',
        choices=['pick-first', 'pick-later', 'pick-right', 'pick-right-later', 'pick-all'])
    serve_parser.set_defaults(handler=serve)
    args = argument_parser.parse_args()
    OUTBOUND_MARK = eval(args.outbound_mark)
    OUTBOUND_IP = args.outbound_ip
    log_level = getattr(logging, args.log_level)
    logging.basicConfig(stream=sys.stdout, level=log_level, format='%(asctime)s %(levelname)s %(message)s')
    if args.log_file:
        handler = logging.handlers.RotatingFileHandler(
            args.log_file, maxBytes=1024 * 256, backupCount=0)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        handler.setLevel(log_level)
        logging.getLogger('fqdns').addHandler(handler)
    gevent.monkey.patch_all(thread=False, ssl=False)
    try:
        gevent.monkey.patch_ssl()
    except:
        LOGGER.exception('failed to patch ssl')
    return_value = args.handler(**{k: getattr(args, k) for k in vars(args) \
                                   if k not in {'handler', 'log_file', 'log_level', 'outbound_mark', 'outbound_ip'}})
    sys.stderr.write(json.dumps(return_value))
    sys.stderr.write('\n')


def serve(listen, upstream, china_upstream, hosted_domain, hosted_at,
          enable_china_domain, enable_hosted_domain, fallback_timeout,
          strategy, original_upstream):
    address = parse_ip_colon_port(listen)
    upstreams = [parse_ip_colon_port(e) for e in upstream]
    china_upstreams = [parse_ip_colon_port(e) for e in china_upstream]
    if original_upstream:
        original_upstream = parse_ip_colon_port(original_upstream)
    handler = DnsHandler(
        upstreams, enable_china_domain, china_upstreams, original_upstream,
        enable_hosted_domain, hosted_domain, hosted_at, fallback_timeout, strategy)
    server = HandlerDatagramServer(address, handler)
    LOGGER.info('dns server started at %r, forwarding to %r', address, upstreams)
    try:
        server.serve_forever()
    except:
        LOGGER.exception('dns server failed')
    finally:
        LOGGER.info('dns server stopped')


class HandlerDatagramServer(gevent.server.DatagramServer):
    def __init__(self, address, handler):
        super(HandlerDatagramServer, self).__init__(address)
        self.handler = handler

    def handle(self, request, address):
        self.handler(self.sendto, request, address)


class DnsHandler(object):
    def __init__(
            self, upstreams=(), enable_china_domain=True, china_upstreams=(), original_upstream=None,
            enable_hosted_domain=True, hosted_domains=(), hosted_at='fqrouter.com',
            fallback_timeout=None, strategy=None):
        super(DnsHandler, self).__init__()
        self.upstreams = []
        if upstreams:
            for ip, port in upstreams:
                self.upstreams.append(('udp', ip, port))
            for ip, port in upstreams:
                self.upstreams.append(('tcp', ip, port))
        else:
            self.upstreams.append(('udp', '208.67.222.222', 443))
            self.upstreams.append(('udp', '8.8.8.8', 53))
            self.upstreams.append(('udp', '87.118.85.241', 110))
            self.upstreams.append(('udp', '209.244.0.3', 53))
            self.upstreams.append(('tcp', '208.67.222.222', 443))
            self.upstreams.append(('tcp', '8.8.8.8', 53))
            self.upstreams.append(('tcp', '87.118.85.241', 110))
            self.upstreams.append(('tcp', '209.244.0.3', 53))
        self.china_upstreams = []
        if enable_china_domain:
            if china_upstreams:
                for ip, port in china_upstreams:
                    self.china_upstreams.append(('udp', ip, port))
                for ip, port in china_upstreams:
                    self.china_upstreams.append(('tcp', ip, port))
            else:
                self.china_upstreams.append(('udp', '114.114.114.114', 53))
                self.china_upstreams.append(('udp', '114.114.115.115', 53))
                self.china_upstreams.append(('udp', '199.91.73.222', 3389))
                self.china_upstreams.append(('udp', '101.226.4.6', 53))
        self.original_upstream = original_upstream
        self.failed_times = {}
        if enable_hosted_domain:
            self.hosted_domains = hosted_domains or HOSTED_DOMAINS()
        else:
            self.hosted_domains = set()
        self.hosted_at = hosted_at or 'fqrouter.com'
        self.fallback_timeout = fallback_timeout or 3
        self.strategy = strategy or 'pick-right'


    def __call__(self, sendto, raw_request, address):
        request = dpkt.dns.DNS(raw_request)
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('received downstream request from %s: %s' % (str(address), repr(request)))
        try:
            response = self.query(request, raw_request)
        except:
            LOGGER.error('failed to query %s due to %s' % (repr(request), sys.exc_info()[1]))
            return
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('forward response to downstream %s: %s' % (str(address), repr(response)))
        sendto(str(response), address)

    def query(self, request, raw_request):
        domains = [question.name for question in request.qd if dpkt.dns.DNS_A == question.type]
        if len(domains) != 1:
            return self.query_directly(request)
        domain = domains[0]
        response = dpkt.dns.DNS(raw_request)
        response.set_qr(True)
        if '.' not in domain:
            response.set_rcode(dpkt.dns.DNS_RCODE_NXDOMAIN)
            if self.original_upstream:
                response = query_directly_once(request, self.original_upstream, self.fallback_timeout)
            return response
        else:
            try:
                if domain.startswith('ignore-hosted-domain.'):
                    querying_domain = domain.replace('ignore-hosted-domain.', '')
                else:
                    querying_domain = '%s.%s' % (domain, self.hosted_at) if domain in self.hosted_domains else domain
                answers = self.query_smartly(querying_domain)
                response.an = [dpkt.dns.DNS.RR(
                    name=domain, type=dpkt.dns.DNS_A, ttl=3600,
                    rlen=len(socket.inet_aton(answer)),
                    rdata=socket.inet_aton(answer)) for answer in answers]
                return response
            except NoSuchDomain:
                response.set_rcode(dpkt.dns.DNS_RCODE_NXDOMAIN)
                return response

    def query_smartly(self, domain):
        if self.china_upstreams and is_china_domain(domain):
            first_china_upstream = self.china_upstreams[0]
            try:
                _, answers = resolve_once(
                    dpkt.dns.DNS_A, domain, [first_china_upstream], self.fallback_timeout, strategy=self.strategy)
                return answers
            except ResolveFailure:
                pass # try following
            sample_china_upstreams = pick_three(self.china_upstreams[1:]) + [random.choice(self.upstreams)]
            try:
                _, answers = resolve_once(
                    dpkt.dns.DNS_A, domain, sample_china_upstreams, self.fallback_timeout, strategy=self.strategy)
                self.demote_china_upstream(first_china_upstream)
                return answers
            except ResolveFailure:
                pass # try following
        else:
            first_upstream = self.upstreams[0]
            try:
                _, answers = resolve_once(
                    dpkt.dns.DNS_A, domain, [first_upstream], self.fallback_timeout, strategy=self.strategy)
                return answers
            except ResolveFailure:
                pass # try following
            sample_upstreams = pick_three(self.upstreams[1:])
            try:
                _, answers = resolve_once(
                    dpkt.dns.DNS_A, domain, sample_upstreams, self.fallback_timeout, strategy=self.strategy)
                self.demote_upstream(first_upstream)
                return answers
            except ResolveFailure:
                pass # try following
        if self.original_upstream:
            _, answers = resolve(
                dpkt.dns.DNS_A, domain, [self.original_upstream], self.fallback_timeout, strategy=self.strategy)
            LOGGER.critical('WTF! this network is doomed')
        raise ResolveFailure('no upstream can resolve: %s' % domain)

    def query_directly(self, request):
        if self.original_upstream and any(True for question in request.qd if dpkt.dns.DNS_PTR == question.type):
            response = query_directly_once(request, self.original_upstream, self.fallback_timeout)
            if response:
                return response
        first_upstream = self.upstreams[0]
        response = query_directly_once(request, first_upstream, self.fallback_timeout)
        if response:
            return response
        random_upstream = random.choice(self.upstreams[1:])
        response = query_directly_once(request, random_upstream, self.fallback_timeout)
        if response:
            self.demote_upstream(first_upstream)
            return response
        if self.original_upstream:
            response = query_directly_once(request, self.original_upstream, self.fallback_timeout)
            if response:
                LOGGER.critical('WTF! this network is doomed')
        raise ResolveFailure('no upstream can query directly: %s' % repr(request))

    def demote_upstream(self, first_upstream):
        if first_upstream == self.upstreams[0]:
            LOGGER.error('!!! put %s %s:%s to tail' % first_upstream)
            self.upstreams.remove(first_upstream)
            self.upstreams.append(first_upstream)

    def demote_china_upstream(self, first_upstream):
        if not first_upstream:
            return
        if first_upstream == self.china_upstreams[0]:
            LOGGER.error('!!! put %s %s:%s to tail' % first_upstream)
            self.china_upstreams.remove(first_upstream)
            self.china_upstreams.append(first_upstream)


def pick_three(full_list):
    return random.sample(full_list, min(len(full_list), 3))


def query_directly_once(request, upstream, timeout):
    server_type, server_ip, server_port = upstream
    try:
        if 'udp' == server_type:
            response = query_directly_over_udp(request, server_ip, server_port, timeout)
        elif 'tcp' == server_type:
            response = query_directly_over_udp(request, server_ip, server_port, timeout)
        else:
            LOGGER.error('unsupported server type: %s' % server_type)
            return None
        LOGGER.info('%s://%s:%s query %s directly => %s'
                    % (server_type, server_ip, server_port, repr(request), repr(response)))
        return response
    except:
        LOGGER.error('%s://%s:%s query %s directly failed due to %s'
                     % (server_type, server_ip, server_port, repr(request), sys.exc_info()[1]))
        return None


def query_directly_over_udp(request, server_ip, server_port, timeout):
    sock = create_udp_socket()
    with contextlib.closing(sock):
        sock.settimeout(timeout)
        sock.sendto(str(request), (server_ip, server_port))
        response = dpkt.dns.DNS(sock.recv(2048))
        if response.get_rcode() & dpkt.dns.DNS_RCODE_NXDOMAIN:
            return response
        if 0 == response.an:
            raise Exception('udp://%s:%s query directly returned empty response: %s'
                            % (server_ip, server_port, repr(response)))
        return response


def query_directly_over_tcp(request, server_ip, server_port, timeout):
    sock = create_tcp_socket(server_ip, server_port, connect_timeout=3)
    with contextlib.closing(sock):
        sock.settimeout(timeout)
        data = str(request)
        sock.send(struct.pack('>h', len(data)) + data)
        data = sock.recv(8192)
        if len(data) < 3:
            raise Exception('response incomplete')
        data = data[2:]
        response = dpkt.dns.DNS(data)
        if response.get_rcode() & dpkt.dns.DNS_RCODE_NXDOMAIN:
            return response
        if 0 == response.an:
            raise Exception('tcp://%s:%s query directly returned empty response: %s'
                            % (server_ip, server_port, repr(response)))
        return response


def resolve(record_type, domain, at, timeout, strategy='pick-right', retry=1):
    record_type = getattr(dpkt.dns, 'DNS_%s' % record_type)
    servers = [parse_dns_server_specifier(e) for e in at] or [('udp', '8.8.8.8', 53)]
    for i in range(retry):
        try:
            return resolve_once(record_type, domain, servers, timeout, strategy)[1]
        except ResolveFailure:
            LOGGER.warn('did not finish resolving %s via %s' % (domain, at))
        except NoSuchDomain:
            LOGGER.warn('no such domain: %s' % domain)


def resolve_once(record_type, domain, servers, timeout, strategy):
    greenlets = []
    queue = gevent.queue.Queue()
    try:
        for server in servers:
            server_type, server_ip, server_port = server
            greenlets.append(gevent.spawn(
                resolve_one, record_type, domain, server_type,
                server_ip, server_port, timeout, strategy, queue))
        try:
            server, answers = queue.get(timeout=timeout)
            if isinstance(answers, NoSuchDomain):
                raise answers
            return server, answers
        except gevent.queue.Empty:
            raise ResolveFailure()
    finally:
        for greenlet in greenlets:
            greenlet.kill(block=False)


class ResolveFailure(Exception):
    pass


def parse_dns_server_specifier(dns_server_specifier):
    if '://' in dns_server_specifier:
        server_type, _, ip_and_port = dns_server_specifier.partition('://')
        ip, port = parse_ip_colon_port(ip_and_port)
        return server_type, ip, port
    else:
        ip, port = parse_ip_colon_port(dns_server_specifier)
        return 'udp', ip, port


def parse_ip_colon_port(ip_colon_port):
    if ':' in ip_colon_port:
        server_ip, server_port = ip_colon_port.split(':')
        server_port = int(server_port)
    else:
        server_ip = ip_colon_port
        server_port = 53
    return '' if '*' == server_ip else server_ip, server_port


def resolve_one(record_type, domain, server_type, server_ip, server_port, timeout, strategy, queue):
    server = (server_type, server_ip, server_port)
    answers = []
    try:
        if 'udp' == server_type:
            answers = resolve_over_udp(record_type, domain, server_ip, server_port, timeout, strategy)
        elif 'tcp' == server_type:
            answers = resolve_over_tcp(record_type, domain, server_ip, server_port, timeout)
        else:
            LOGGER.error('unsupported server type: %s' % server_type)
    except NoSuchDomain as e:
        queue.put((server, e))
        return
    except:
        LOGGER.exception('failed to resolve one: %s' % domain)
    if answers:
        queue.put((server, answers))
        LOGGER.info('%s://%s:%s resolved %s => %s' % (server_type, server_ip, server_port, domain, answers))


def resolve_over_tcp(record_type, domain, server_ip, server_port, timeout):
    try:
        sock = create_tcp_socket(server_ip, server_port, connect_timeout=3)
    except gevent.GreenletExit:
        return []
    except:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.exception('failed to connect to %s:%s' % (server_ip, server_port))
        else:
            LOGGER.error('failed to connect to %s:%s due to %s' % (server_ip, server_port, sys.exc_info()[1]))
        return []
    try:
        with contextlib.closing(sock):
            sock.settimeout(timeout)
            request = dpkt.dns.DNS(id=get_transaction_id(), qd=[dpkt.dns.DNS.Q(name=domain, type=record_type)])
            LOGGER.debug('send request: %s' % repr(request))
            data = str(request)
            sock.send(struct.pack('>h', len(data)) + data)
            data = sock.recv(8192)
            data = data[2:]
            response = dpkt.dns.DNS(data)
            if response.get_rcode() & dpkt.dns.DNS_RCODE_NXDOMAIN:
                raise NoSuchDomain()
            if not is_right_response(response): # filter opendns "nxdomain"
                response = None
            if response:
                if dpkt.dns.DNS_A == record_type:
                    return list_ipv4_addresses(response)
                elif dpkt.dns.DNS_TXT == record_type:
                    return [answer.text[0] for answer in response.an]
                else:
                    LOGGER.error('unsupported record type: %s' % record_type)
                    return []
            else:
                return []
    except NoSuchDomain:
        raise
    except:
        report_error('failed to resolve %s via tcp://%s:%s' % (domain, server_ip, server_port))
        return []


def report_error(msg):
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.exception(msg)
    else:
        if sys.exc_info()[1]:
            LOGGER.error('%s due to %s' % (msg, sys.exc_info()[1]))
        else:
            LOGGER.exception(msg)

def resolve_over_udp(record_type, domain, server_ip, server_port, timeout, strategy):
    sock = create_udp_socket()
    try:
        with contextlib.closing(sock):
            sock.settimeout(timeout)
            request = dpkt.dns.DNS(id=get_transaction_id(), qd=[dpkt.dns.DNS.Q(name=domain, type=record_type)])
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('send request: %s' % repr(request))
            sock.sendto(str(request), (server_ip, server_port))
            if dpkt.dns.DNS_A == record_type:
                responses = pick_responses(sock, timeout, strategy)
                if 'pick-all' == strategy:
                    return [list_ipv4_addresses(response) for response in responses]
                if len(responses) == 1:
                    return list_ipv4_addresses(responses[0])
                elif len(responses) > 1:
                    ips = []
                    for response in responses:
                        ips.extend(list_ipv4_addresses(response))
                    return ips
                else:
                    return []
            elif dpkt.dns.DNS_TXT == record_type:
                response = dpkt.dns.DNS(sock.recv(8192))
                LOGGER.debug('received response: %s' % repr(response))
                return [answer.text[0] for answer in response.an]
            else:
                LOGGER.error('unsupported record type: %s' % record_type)
                return []
    except NoSuchDomain:
        raise
    except:
        report_error('failed to resolve %s via udp://%s:%s' % (domain, server_ip, server_port))
        return []


def get_transaction_id():
    return random.randint(1, 65535)


def pick_responses(sock, timeout, strategy):
    picked_responses = []
    started_at = time.time()
    deadline = started_at + timeout
    remaining_timeout = deadline - time.time()
    try:
        while remaining_timeout > 0:
            sock.settimeout(remaining_timeout)
            response = dpkt.dns.DNS(sock.recv(8192))
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('received response: %s' % repr(response))
            if response.get_rcode() & dpkt.dns.DNS_RCODE_NXDOMAIN:
                raise NoSuchDomain()
            if 'pick-first' == strategy:
                return [response]
            if 'pick-all' != strategy and len(response.an) > 1:
                return [response] # GFW does not forge multiple answers
            if 'pick-later' == strategy:
                picked_responses = [response]
            elif 'pick-right' == strategy:
                if is_right_response(response):
                    return [response]
                else:
                    if LOGGER.isEnabledFor(logging.DEBUG):
                        LOGGER.debug('drop wrong answer: %s' % repr(response))
            elif 'pick-right-later' == strategy:
                if is_right_response(response):
                    picked_responses = [response]
                else:
                    if LOGGER.isEnabledFor(logging.DEBUG):
                        LOGGER.debug('drop wrong answer: %s' % repr(response))
            elif 'pick-all' == strategy:
                picked_responses.append(response)
            else:
                raise Exception('unsupported strategy: %s' % strategy)
            remaining_timeout = deadline - time.time()
        return picked_responses
    except socket.timeout:
        return picked_responses


class NoSuchDomain(Exception):
    pass


def is_right_response(response):
    answers = list_ipv4_addresses(response)
    if not answers: # GFW can forge empty response
        return False
    if len(answers) > 1: # GFW does not forge response with more than one answer
        return True
    return not any(is_wrong_answer(answer) for answer in answers)


def list_ipv4_addresses(response):
    return [socket.inet_ntoa(answer.ip) for answer in response.an if dpkt.dns.DNS_A == answer.type]


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
        return list(wrong_answers - list_wrong_answers())
    else:
        return list(wrong_answers)


def discover_one(domain, server_ip, server_port, timeout, right_answer):
    wrong_answers = set()
    responses_answers = resolve_over_udp(
        dpkt.dns.DNS_A, domain, server_ip, server_port, timeout, 'pick-all')
    contains_right_answer = any(len(answers) > 1 for answers in responses_answers)
    if right_answer or contains_right_answer:
        for answers in responses_answers:
            if len(answers) == 1 and answers[0] != right_answer:
                wrong_answers |= set(answers)
    return wrong_answers


def create_tcp_socket(server_ip, server_port, connect_timeout):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    sock.setblocking(0)
    sock.settimeout(connect_timeout)
    try:
        sock.connect((server_ip, server_port))
    except:
        sock.close()
        raise
    sock.settimeout(None)
    return sock


def create_udp_socket():
    return SPI['create_udp_socket']()


def _create_udp_socket():
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    if OUTBOUND_MARK:
        sock.setsockopt(socket.SOL_SOCKET, SO_MARK, OUTBOUND_MARK)
    if OUTBOUND_IP:
        sock.bind((OUTBOUND_IP, 0))
    return sock


SPI['create_udp_socket'] = _create_udp_socket


class SocketTimeout(BaseException):
    pass


WRONG_ANSWERS = {
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
    '159.24.3.173',
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
    '243.185.187.30',
    # plus.google.com
    '74.125.127.102',
    '74.125.155.102',
    '74.125.39.113',
    '74.125.39.102',
    '209.85.229.138',
    # opendns
    '67.215.65.132',
    # https://github.com/fqrouter/fqdns/issues/2
    '69.55.52.253'
}


def is_wrong_answer(answer):
    return answer in WRONG_ANSWERS


def list_wrong_answers():
    return WRONG_ANSWERS


CHINA_DOMAINS = [
    '07073.com',
    '10010.com',
    '100ye.com',
    '114la.com',
    '115.com',
    '120ask.com',
    '126.com',
    '126.net',
    '1616.net',
    '163.com',
    '17173.com',
    '1778.com',
    '178.com',
    '17u.com',
    '19lou.com',
    '1o26.com',
    '1ting.com',
    '21cn.com',
    '2345.com',
    '265.com',
    '265g.com',
    '28.com',
    '28tui.com',
    '2hua.com',
    '2mdn.net',
    '315che.com',
    '3366.com',
    '360buy.com',
    '360buyimg.com',
    '360doc.com',
    '36kr.com',
    '39.net',
    '3dmgame.com',
    '4399.com',
    '4738.com',
    '500wan.com',
    '51.com',
    '51.la',
    '5173.com',
    '51auto.com',
    '51buy.com',
    '51cto.com',
    '51fanli.com',
    '51job.com',
    '52kmh.com',
    '52pk.net',
    '52tlbb.com',
    '53kf.com',
    '55bbs.com',
    '55tuan.com',
    '56.com',
    '58.com',
    '591hx.com',
    '5d6d.net',
    '61.com',
    '70e.com',
    '777wyx.com',
    '778669.com',
    '7c.com',
    '7k7k.com',
    '88db.com',
    '91.com',
    '99bill.com',
    'a135.net',
    'abang.com',
    'abchina.com',
    'ad1111.com',
    'admin5.com',
    'adnxs.com',
    'adobe.com',
    'adroll.com',
    'ads8.com',
    'adsame.com',
    'adsonar.com',
    'adtechus.com',
    'aibang.com',
    'aifang.com',
    'aili.com',
    'aipai.com',
    'aizhan.com',
    'ali213.net',
    'alibaba.com',
    'alicdn.com',
    'aliexpress.com',
    'alimama.com',
    'alipay.com',
    'alipayobjects.com',
    'alisoft.com',
    'alivv.com',
    'aliyun.com',
    'allyes.com',
    'amazon.com',
    'anjuke.com',
    'anzhi.com',
    'aol.com',
    'apple.com',
    'arpg2.com',
    'atdmt.com',
    'b2b168.com',
    'babytree.com',
    'baidu.com',
    'baihe.com',
    'baixing.com',
    'bankcomm.com',
    'baomihua.com',
    'bdimg.com',
    'bdstatic.com',
    'bendibao.com',
    'betrad.com',
    'bilibili.tv',
    'bing.com',
    'bitauto.com',
    'blog.163.com',
    'blogchina.com',
    'blueidea.com',
    'bluekai.com',
    'booksky.org',
    'caixin.com',
    'ccb.com',
    'ccidnet.com',
    'cctv*.com',
    'china.com',
    'chinabyte.com',
    'chinahr.com',
    'chinanews.com',
    'chinaunix.net',
    'chinaw3.com',
    'chinaz.com',
    'chuangelm.com',
    'ci123.com',
    'cmbchina.com',
    'cnbeta.com',
    'cnblogs.com',
    'cncn.com',
    'cnhubei.com',
    'cnki.net',
    'cnmo.com',
    'cnxad.com',
    'cnzz.com',
    'cocoren.com',
    'compete.com',
    'comsenz.com',
    'coo8.com',
    'cqnews.net',
    'crsky.com',
    'csdn.net',
    'ct10000.com',
    'ctrip.com',
    'dangdang.com',
    'daqi.com',
    'dayoo.com',
    'dbank.com',
    'ddmap.com',
    'dedecms.com',
    'dh818.com',
    'diandian.com',
    'dianping.com',
    'discuz.net',
    'doc88.com',
    'docin.com',
    'donews.com',
    'dospy.com',
    'douban.com',
    'douban.fm',
    'doubleclick.com',
    'doubleclick.net',
    'duba.net',
    'duote.com',
    'duowan.com',
    'dzwww.com',
    'eastday.com',
    'eastmoney.com',
    'ebay.com',
    'elong.com',
    'ename.net',
    'etao.com',
    'exam8.com',
    'eye.rs',
    'fantong.com',
    'fastcdn.com',
    'fblife.com',
    'fengniao.com',
    'fenzhi.com',
    'flickr.com',
    'fobshanghai.com',
    'ftuan.com',
    'funshion.com',
    'fx120.net',
    'game3737.com',
    'gamersky.com',
    'gamestlbb.com',
    'gamesville.com',
    'ganji.com',
    'gfan.com',
    'gongchang.com',
    'google-analytics.com',
    'gougou.com',
    'gtimg.com',
    'hao123.com',
    'haodf.com',
    'harrenmedianetwork.com',
    'hc360.com',
    'hefei.cc',
    'hf365.com',
    'hiapk.com',
    'hichina.com',
    'homeinns.com',
    'hotsales.net',
    'house365.com',
    'huaban.com',
    'huanqiu.com',
    'hudong.com',
    'hupu.com',
    'iask.com',
    'iciba.com',
    'icson.com',
    'ifeng.com',
    'iloveyouxi.com',
    'im286.com',
    'imanhua.com',
    'img.cctvpic.com',
    'imrworldwide.com',
    'invitemedia.com',
    'ip138.com',
    'ipinyou.com',
    'iqilu.com',
    'iqiyi.com',
    'irs01.com',
    'irs01.net',
    'it168.com',
    'iteye.com',
    'iyaya.com',
    'jb51.net',
    'jiathis.com',
    'jiayuan.com',
    'jing.fm',
    'jinti.com',
    'jqw.com',
    'jumei.com',
    'jxedt.com',
    'jysq.net',
    'kaixin001.com',
    'kandian.com',
    'kdnet.net',
    'kimiss.com',
    'ku6.com',
    'ku6cdn.com',
    'ku6img.com',
    'kuaidi100.com',
    'kugou.com',
    'l99.com',
    'lady8844.com',
    'lafaso.com',
    'lashou.com',
    'legolas-media.com',
    'lehecai.com',
    'leho.com',
    'letv.com',
    'liebiao.com',
    'lietou.com',
    'linezing.com',
    'linkedin.com',
    'live.com',
    'longhoo.net',
    'lusongsong.com',
    'lxdns.com',
    'lycos.com',
    'lygo.com',
    'm18.com',
    'm1905.com',
    'made-in-china.com',
    'makepolo.com',
    'mangocity.com',
    'manzuo.com',
    'mapbar.com',
    'mathtag.com',
    'mediaplex.com',
    'mediav.com',
    'meilele.com',
    'meilishuo.com',
    'meishichina.com',
    'meituan.com',
    'meizu.com',
    'miaozhen.com',
    'microsoft.com',
    'miercn.com',
    'mlt01.com',
    'mmstat.com',
    'mnwan.com',
    'mogujie.com',
    'mookie1.com',
    'moonbasa.com',
    'mop.com',
    'mosso.com',
    'mplife.com',
    'msn.com',
    'mtime.com',
    'mumayi.com',
    'mydrivers.com',
    'net114.com',
    'netease.com',
    'newsmth.net',
    'nipic.com',
    'nowec.com',
    'nuomi.com',
    'oadz.com',
    'oeeee.com',
    'onetad.com',
    'onlinedown.net',
    'onlylady.com',
    'oschina.net',
    'otwan.com',
    'paipai.com',
    'paypal.com',
    'pchome.net',
    'pcpop.com',
    'pengyou.com',
    'php100.com',
    'phpwind.net',
    'pingan.com',
    'pixlr.com',
    'pp.cc',
    'ppstream.com',
    'pptv.com',
    'ptlogin2.qq.com',
    'pubmatic.com',
    'q150.com',
    'qianlong.com',
    'qidian.com',
    'qingdaonews.com',
    'qire123.com',
    'qiushibaike.com',
    'qiyou.com',
    'qjy168.com',
    'qq.com',
    'qq937.com',
    'qstatic.com',
    'quantserve.com',
    'qunar.com',
    'rakuten.co.jp',
    'readnovel.com',
    'renren.com',
    'rtbidder.net',
    'scanscout.com',
    'scorecardresearch.com',
    'sdo.com',
    'seowhy.com',
    'serving-sys.com',
    'sf-express.com',
    'shangdu.com',
    'si.kz',
    'sina.com',
    'sinahk.net',
    'sinajs.com',
    'smzdm.com',
    'snyu.com',
    'sodu.org',
    'sogou.com',
    'sohu.com',
    'soku.com',
    'sootoo.com',
    'soso.com',
    'soufun.com',
    'sourceforge.net',
    'staticsdo.com',
    'stockstar.com',
    'sttlbb.com',
    'suning.com',
    'szhome.com',
    'sznews.com',
    'tangdou.com',
    'tanx.com',
    'tao123.com',
    'taobao.com',
    'taobaocdn.com',
    'tdimg.com',
    'tenpay.com',
    'tgbus.com',
    'theplanet.com',
    'thethirdmedia.com',
    'tiancity.com',
    'tianji.com',
    'tiao8.info',
    'tiexue.net',
    'titan24.com',
    'tmall.com',
    'tom.com',
    'toocle.com',
    'tremormedia.com',
    'tuan800.com',
    'tudou.com',
    'tudouui.com',
    'tui18.com',
    'tuniu.com',
    'twcczhu.com',
    'u17.com',
    'ucjoy.com',
    'ulink.cc',
    'uniontoufang.com',
    'up2c.com',
    'uuu9.com',
    'uuzu.com',
    'vancl.com',
    'verycd.com',
    'vipshop.com',
    'vizu.com',
    'vjia.com',
    'weibo.com',
    'weiphone.com',
    'west263.com',
    'whlongda.com',
    'wrating.com',
    'wumii.com',
    'xiami.com',
    'xiaomi.com',
    'xiazaiba.com',
    'xici.net',
    'xinhuanet.com',
    'xinnet.com',
    'xitek.com',
    'xiu.com',
    'xunlei.com',
    'xyxy.net',
    'yaolan.com',
    'yesky.com',
    'yieldmanager.com',
    'yihaodian.com',
    'yingjiesheng.com',
    'yinyuetai.com',
    'yiqifa.com',
    'ykimg.com',
    'ynet.com',
    'yoka.com',
    'yolk7.com',
    'youboy.com',
    'youdao.com',
    'yougou.com',
    'youku.com',
    'youshang.com',
    'yupoo.com',
    'yxlady.com',
    'yyets.com',
    'zhaodao123.com',
    'zhaopin.com',
    'zhenai.com',
    'zhibo8.cc',
    'zhihu.com',
    'zhubajie.com',
    'zongheng.com',
    'zoosnet.net',
    'zqgame.com',
    'ztgame.com',
    'zx915.com',
    'miui.com',
    'mi-idc.com',
    'wandoujia.com'
]


def is_china_domain(domain):
    if domain.endswith('.cn'):
        return True
    for chain_domain in CHINA_DOMAINS:
        if domain == chain_domain or domain.endswith('.%s' % chain_domain):
            return True
    return False


def HOSTED_DOMAINS():
    return {
        # cdn
        'd2anp67vmqk4wc.cloudfront.net',
        # google.com
        'google.com', 'www.google.com',
        'mail.google.com', 'chatenabled.mail.google.com',
        'filetransferenabled.mail.google.com', 'apis.google.com',
        'mobile-gtalk.google.com', 'mtalk.google.com',
        # google.com.hk
        'google.com.hk', 'www.google.com.hk',
        # google.cn
        'google.cn', 'www.google.cn',
        # youtube
        'youtube.com', 'www.youtube.com'
    }

# TODO use original dns for PTR query, http://stackoverflow.com/questions/5615579/how-to-get-original-destination-port-of-redirected-udp-message
# TODO cache
# TODO PTR support, check cache then check remote
# TODO IPV6
# TODO complete record types
# TODO --recursive

if '__main__' == __name__:
    main()