#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author: lazydog <lazyago at gmail dot com>
import asyncio
import aiodns
import functools
import pycares


query_type_map = {'A'     : pycares.QUERY_TYPE_A,
                  'AAAA'  : pycares.QUERY_TYPE_AAAA,
                  'CNAME' : pycares.QUERY_TYPE_CNAME,
                  'MX'    : pycares.QUERY_TYPE_MX,
                  'NAPTR' : pycares.QUERY_TYPE_NAPTR,
                  'NS'    : pycares.QUERY_TYPE_NS,
                  'PTR'   : pycares.QUERY_TYPE_PTR,
                  'SOA'   : pycares.QUERY_TYPE_SOA,
                  'SRV'   : pycares.QUERY_TYPE_SRV,
                  'TXT'   : pycares.QUERY_TYPE_TXT
        }


class DomainInfo(object):
    __slots__ = ('__storage__')

    def __init__(self, **kwargs):
        object.__setattr__(self, '__storage__', {})
        for k,v in kwargs.items():
            self.__storage__[k] = v

    def __eq__(self, other):
        return isinstance(other, DomainInfo) and self.domain == other.domain

    def __repr__(self):
        return "DomainInfo(domain='{}', ip={})".format(self.domain, self.ip)

    def __hash__(self):
        return hash(self.__repr__())

    def __getattr__(self, name):
        try:
            return self.__storage__[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        storage = self.__storage__
        try:
            storage[name] = value
        except KeyError:
            storage[name] = {name: value}

    def __delattr__(self, name):
        try:
            del self.__storage__[name]
        except KeyError:
            raise AttributeError(name)


class DNSError(Exception):
    pass


class DNSResolver(aiodns.DNSResolver):
    def __init__(self, loop):
        super(DNSResolver, self).__init__()

    @staticmethod
    def _callback(fut, domain, result, errorno):
        # type: (asyncio.Future, Any, int) -> None
        if fut.cancelled():
            return
        if errorno is not None:
            fut.set_exception(DNSError(errorno, pycares.errno.strerror(errorno)))
        else:
            domain_ip = [r.host for r in result]
            result = result = DomainInfo(domain = domain, ip = domain_ip)
            print(result)
            fut.set_result(result)

    def query(self, host, qtype):
        # type: (str, str) -> asyncio.Future
        try:
            qtype = query_type_map[qtype]
        except KeyError:
            raise ValueError('invalid query type: {}'.format(qtype))
        fut = asyncio.Future(loop=self.loop)
        cb = functools.partial(self._callback, fut, host)
        self._channel.query(host, qtype, cb)
        return fut


class subnameGetter(object):
    def __init__(self, domain, options, queue = None, loop = None, dict_file = None):
        self.loop = loop if loop else asyncio.get_event_loop()
        assert self.loop is not None
        self.sem = asyncio.Semaphore(options.rate)
        self.domain = domain
        self.tasks = []
        self.queue = queue or asyncio.Queue()
        self.result = []
        self.dict_file = dict_file or 'subnames.txt'
        self.resolver = DNSResolver(loop = self.loop)
        self._load_sub_names()

    @property
    def nameservers(self):
        return self.resolver.nameservers

    @nameservers.setter
    def nameservers(self, value):
        if isinstance(value, list) is not True: raise TypeError('value must be a list!')
        self.resolver.nameservers = value

    async def dns_query(self):
        async with self.sem:
            try:
                subname = await self.queue.get()
                domainName = subname + '.' + self.domain
                r = await self.resolver.query(domainName, 'A')
                return r
            except:
                pass

    def run(self):
        size = self.queue.qsize()
        print('qsize: {}'.format(size))

        for i in range(size):
            task = asyncio.ensure_future(self.dns_query())
            self.tasks.append(task)
        try:
            responses = asyncio.gather(*self.tasks)
            result = self.loop.run_until_complete(responses)
            result = list(filter(lambda r:r is not None, result))
            print('[+] Found {} subdomain'.format(len(result)))
        except Exception as e:
            print(e)

    def test_resolver(self):
        t = self.resolver.query('www.google.com', 'A')
        result = self.loop.run_until_complete(t)
        print(result)

    def _load_sub_names(self):
        try:
            print('[+] Load {}... '.format(self.dict_file))
            with open(self.dict_file) as f:
                for line in f:
                    subname = line.strip()
                    if not subname:
                        continue
                    self.queue.put_nowait(subname)
        except Exception as e:
            print('[-] Load file failed:{}'.format(e))
            exit(2)
        return

        
if __name__ == '__main__':
    import sys, optparse
    parser = optparse.OptionParser("""
    usage:
        python3.6 %prog [Options] {target domain}
    example:
        python3.6 %prog --rate 10000 kuihua.com
    """, version="%prog 0.99999")
    parser.add_option('--rate', dest='rate', default=5000, type=int,
            help='Num of scan rate,default: 5000')
    (options, args) = parser.parse_args()
    if 1 > len(args):
        parser.print_help()
        exit(1)

    domain = args[0]
    oo = subnameGetter(domain, options)
    oo.nameservers = ['223.5.5.5', '223.6.6.6', '114.114.114.114', '8.8.4.4', '8.8.8.8']
    oo.run()
