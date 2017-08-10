#!/usr/bin/env python

"""This program interrogates Google Suggestions to passively discover sub-domains for a given domain."""

import json
import logging
from argparse import *
from httplib import HTTPSConnection
from itertools import product
from string import ascii_lowercase, digits
from multiprocessing import Pool
from urllib import urlencode
from urlparse import urlparse


__author__ = 'Nadeem Douba'
__email__ = 'ndouba@redcanari.com'
__copyright__ = 'Copyright 2017, Red Canari'

__license__ = 'LGPLv3'
__version__ = '0.1'
__status__ = 'Beta'


FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger('goodns')

SUPPORTED_DOMAIN_CHARACTERS = ascii_lowercase + digits + "-"

DEFAULT_SUPPORTED_DOMAINS = set("""com
ad
ae
com.af
com.ag
com.ai
al
am
co.ao
com.ar
as
at
com.au
az
ba
com.bd
be
bf
bg
com.bh
bi
bj
com.bn
com.bo
com.br
bs
bt
co.bw
by
com.bz
ca
cd
cf
cg
ch
ci
co.ck
cl
cm
cn
com.co
co.cr
com.cu
cv
com.cy
cz
de
dj
dk
dm
com.do
dz
com.ec
ee
com.eg
es
com.et
fi
com.fj
fm
fr
ga
ge
gg
com.gh
com.gi
gl
gm
gp
gr
com.gt
gy
com.hk
hn
hr
ht
hu
co.id
ie
co.il
im
co.in
iq
is
it
je
com.jm
jo
co.jp
co.ke
com.kh
ki
kg
co.kr
com.kw
kz
la
com.lb
li
lk
co.ls
lt
lu
lv
com.ly
co.ma
md
me
mg
mk
ml
com.mm
mn
ms
com.mt
mu
mv
mw
com.mx
com.my
co.mz
com.na
com.nf
com.ng
com.ni
ne
nl
no
com.np
nr
nu
co.nz
com.om
com.pa
com.pe
com.pg
com.ph
com.pk
pl
pn
com.pr
ps
pt
com.py
com.qa
ro
ru
rw
com.sa
com.sb
sc
se
com.sg
sh
si
sk
com.sl
sn
so
sm
sr
st
com.sv
td
tg
co.th
com.tj
tk
tl
tm
tn
to
com.tr
tt
com.tw
co.tz
com.ua
co.ug
co.uk
com.uy
co.uz
com.vc
co.ve
vg
co.vi
com.vn
vu
ws
rs
co.za
co.zm
co.zw
cat""".split("\n"))


def download_supported_domains():
    logger.info("Downloading Google supported domains.")
    conn = HTTPSConnection("www.google.com")
    conn.request("GET", "/supported_domains")
    response = conn.getresponse()

    if response.status == 200:
        global DEFAULT_SUPPORTED_DOMAINS
        DEFAULT_SUPPORTED_DOMAINS = [d.replace('.google.', '') for d in response.read().strip().split("\n")]
    logger.info("Download complete")


def pool_scan(*args):
    tld, domain, term = args[0]
    logging.info("Scanning for %s on TLD %s", term, tld)
    conn = HTTPSConnection('www.google.%s' % tld)

    params = urlencode({
        'client': 'chrome-omni',
        'gs_ri': 'chrome-ext-ansg',
        'q': term,
        'oit': '3',
        'cp': '1',
        'pgcl': '9',
        'gs_rn': '42'
    })

    conn.request("GET", "/complete/search?%s" % params, headers={
        'Connection': 'close',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.8'
    })

    response = conn.getresponse()

    if response.status == 200:
        result = json.loads(response.read())
        logger.debug("Result was: %r", result)

        suggestions = set([
            urlparse(u).hostname for u, t in zip(result[1], result[4]['google:suggesttype'])
            if t == 'NAVIGATION' and urlparse(u).hostname.endswith('.%s' % domain)
        ])
        if suggestions:
            logging.info("Got back %s", ', '.join(suggestions))
            return suggestions

    logging.warn("Got nothing back for %s :( (status code=%s)", term, response.status)

    if response.status == 403:
        return None

    return set()


def scan(term):
    pass


def wordlist_scan(domain, word_list, tlds):
    pool = Pool(32)
    domain = domain.strip('.')
    results = set()

    for prefix in file(word_list).readlines():
        if not prefix:
            continue
        prefix = prefix.strip()
        if not prefix.startswith('-'):
            for r in pool.map(pool_scan, [(t, domain, '%s.%s' % (prefix, domain)) for t in tlds]):
                if r is None:
                    logging.fatal("This machine has been flagged by Google :(")
                    print 'Discovered %s domains' % len(results)
                    print '\n'.join(results)
                    exit(-1)
                results.update(r)

    print 'Discovered %s domains' % len(results)
    print '\n'.join(results)
    exit(0)


def prefix_scan(domain, prefix_length, tlds):
    pool = Pool(32)
    domain = domain.strip('.')
    results = set()

    for current_len in range(prefix_length):
        current_len += 1
        for prefix in product(SUPPORTED_DOMAIN_CHARACTERS, repeat=current_len):
            prefix = ''.join(prefix)
            if not prefix.startswith('-'):
                for r in pool.map(pool_scan, [(t, domain, '%s.%s' % (prefix, domain)) for t in tlds]):
                    if r is None:
                        logging.fatal("This machine has been flagged by Google :(")
                        print 'Discovered %s domains' % len(results)
                        print '\n'.join(results)
                        exit(-1)
                    results.update(r)

    print 'Discovered %s domains' % len(results)
    print '\n'.join(results)
    exit(0)

def main(args):
    download_supported_domains()

    if not args.l:
        logger.info("Scanning all Google TLDs")
        args.l = DEFAULT_SUPPORTED_DOMAINS
    elif not set(args.l).issubset(DEFAULT_SUPPORTED_DOMAINS):
        logger.fatal("Invalid TLD(s) (%s) specified.", ', '.join(set(args.l).difference(DEFAULT_SUPPORTED_DOMAINS)))
        exit(-1)

    if args.w:
        logger.info("Starting word list scan using %s...", args.w)
        wordlist_scan(args.domain, args.w, args.l)
    else:
        logger.info("Starting prefix scan with length %s..." % args.c)
        prefix_scan(args.domain, args.c, args.l)


if __name__ == '__main__':
    parser = ArgumentParser(description='Google DNS recon tool')
    parser.add_argument("domain", help="The domain you want to search.")
    parser.add_argument("-c", default=1, metavar="i", type=int, help="Length of sub-domain prefix to try")
    parser.add_argument("-w", nargs=1, metavar="wordlist", help="Wordlist file", type=FileType('r'))
    parser.add_argument("-l", metavar="tld", action="append", help="Top level domain (e.g. 'ca' or 'com')", default=[])
    args = parser.parse_args()

    main(args)
