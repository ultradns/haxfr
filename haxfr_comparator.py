#!/usr/bin/env python

from __future__ import with_statement
from Queue import Queue
from threading import Thread

import haxfr
import logging
from logging import INFO

from haxfr import __author__  
from haxfr import __version__
from haxfr import __revision__
from haxfr import _product
from haxfr import _banner

from haxfr import DEFAULT_SERVER
from haxfr import DEFAULT_PORT
from haxfr import DEFAULT_ALGORITHM
from haxfr import DEFAULT_TIMEOUT
from haxfr import DEFAULT_LIFETIME
from haxfr import HAxfr

class WorkerData:
    def __init__(self, args1, zone1):
        self.args = args1
        self.zone = zone1

if __name__ == '__main__':

    q = Queue()
    workers = []
    logging.basicConfig()
    FORMAT = '%(asctime)-15s %(clientip)s %(user)-8s %(message)s'
    logging.basicConfig(format=FORMAT)
    logger = logging.getLogger('haxfr')
    logger.setLevel(INFO)
    def worker():
        while True:
            worker_data = q.get()
            logger.info("Comparing AXFR from '%s' and '%s' for zone '%s'", worker_data.args.server1, worker_data.args.server2, worker_data.zone)
            import time
            start_time = time.time()
            try:
                (num_recs1, soa_rdata1, hash1) = HAxfr(
                    worker_data.args.server1, 
                    worker_data.args.port, 
                    worker_data.zone,
                    worker_data.args.algorithm, 
                    worker_data.args.timeout,
                    worker_data.args.lifetime,
                    worker_data.args.dump,
                    worker_data.args.verbose,
                    worker_data.args.skipttl).run()
                (num_recs2, soa_rdata2, hash2) = HAxfr(
                    worker_data.args.server2, 
                    worker_data.args.port, 
                    worker_data.zone,
                    worker_data.args.algorithm, 
                    worker_data.args.timeout,
                    worker_data.args.lifetime,
                    worker_data.args.dump,
                    worker_data.args.verbose,
                    worker_data.args.skipttl).run() 
                stop_time = time.time()
                if hash2 != hash1:
                    logger.info('AXFR responses for zone "%s" are different', worker_data.zone)
                else:
                    logger.info('AXFR responses for zone "%s" are same', worker_data.zone)
            except Exception as e:
                logger.error('Failed to compare AXFRs for zone "%s" : {%s} %s ', worker_data.zone, e.__class__.__name__, e)
                if worker_data.args.verbose:
                    raise

            q.task_done()

    for i in range(100):
        t = Thread(target=worker)
        t.setDaemon(True)
        workers.append(t)
        t.start()

    # Print startup banner:
    print '#', _banner

    # Parse command-line:
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='Compare sum of hash values for AXFR\'d zones from two servers')
    parser.add_argument('-f', '--file', dest='file',
        metavar='s',
        help='Input file having list of zones')
    parser.add_argument('-s1', '--server1', dest='server1',
        default=DEFAULT_SERVER, metavar='s',
        help='DNS server1 address [%s]' % (DEFAULT_SERVER))
    parser.add_argument('-s2', '--server2', dest='server2',
        default=DEFAULT_SERVER, metavar='s',
        help='DNS server2 address [%s]' % (DEFAULT_SERVER))
    parser.add_argument('-p', '--port', dest='port',
        default=DEFAULT_PORT, metavar='i', type=int,
        help='DNS server port [%d]' % (DEFAULT_PORT))
    parser.add_argument('-a', '--algorithm', dest='algorithm',
        default=DEFAULT_ALGORITHM, metavar='s',
        choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
        help='Hash algorithm [%s]' % (DEFAULT_ALGORITHM))
    parser.add_argument('-t', '--timeout', dest='timeout',
        default=DEFAULT_TIMEOUT, metavar='s',
        help='Seconds waiting for AXFR response, or None [%s]' % (str(DEFAULT_TIMEOUT)))
    parser.add_argument('-l', '--lifetime', dest='lifetime',
        default=DEFAULT_LIFETIME, metavar='s',
        help='Seconds to allow for entire AXFR, or None [%s]' % (str(DEFAULT_LIFETIME)))
    parser.add_argument('-d', '--dump', dest='dump',
        default=False, action='store_true',
        help='Dump resource records to stdout')
    parser.add_argument('-k', '--skipttl', dest='skipttl',
        default=False, action='store_true',
        help='Skip TTL while calculating hash')
    parser.add_argument('-v', '--verbose', dest='verbose',
        default=False, action='store_true',
        help='Show detailed processing info')
    args = parser.parse_args()

    with open(args.file, 'r') as fin:
        for line in fin :
           workerData = WorkerData(args, line[:-1].strip())
           q.put(workerData)
    q.join()

#
