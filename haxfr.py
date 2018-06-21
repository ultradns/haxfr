#!/usr/bin/env python
'''
haxfr - Hash a zone via AXFR
Copyright (C) 2013 Neustar, Inc.

Requires: python 2.7+, dnspython 1.10+
'''

__author__   = "ashley.roeckelein@neustar.biz"
__version__  = "$Revision: 74232 $"
__revision__ = "$Id: haxfr.py 74232 2013-04-12 08:00:39Z aroeckel $"

import cStringIO
import hashlib
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.query

_product = 'haxfr'
_banner = '%s (%s) by Neustar Inc.' % (_product, __version__)

DEFAULT_SERVER    = '127.0.0.1'
DEFAULT_PORT      = 53
DEFAULT_ALGORITHM = 'sha256'
DEFAULT_TIMEOUT   = 1.0
DEFAULT_LIFETIME  = None

class HAxfr(object):
    '''
    Pulls a zone via DNS AXFR and computes a user-defined hash value for the 
    zone.  The returned hash value is an (order-independent) ADD of resource
    record hash values.  The consequence of this choice is that the AXFR can
    be processed in a streaming, one-pass manner, minimizing memory consumption 
    and processing overhead.
    '''
    
    def __init__(self, server, port, zone, algorithm, timeout, lifetime,
                 dump, verbose, skipttl, **kwargs):
        '''
        Constructs a HAxfr instance.
        @param server The DNS server address.
        @param port The DNS server port.
        @param zone The zone name to hash.
        @param algorithm The hashing algorithm.
        @param timeout Seconds to wait for AXFR to start (or None for infinite).
        @param lifetime Seconds to allow for entire AXFR (or None for infinite).
        @param dump True to dump records to stdout.
        @param kwargs Other key-values (to absorb/ignore).
        @param verbose True to dump record hashes to stdout.
        '''
        self._server = server
        self._port = int(port)
        self._zone = zone
        self._algorithm = algorithm
        self._timeout = timeout and float(timeout) or None
        self._lifetime = lifetime and float(lifetime) or None
        self._dump = dump
        self._verbose = verbose
        self._skipttl = skipttl

    def run(self):
        '''
        Runs the HAxfr instance.
        @return tuple of (num_recs, soa_rdata, zone_hashvalue).
        @note A variety of exceptions can be thrown; caller should be prepared!
        '''
        
        # Create master hasher.  We'll use this to copy() individual record
        # hashers from, for speed (since hashlib.new() is not as fast as
        # directly hard-coding a specific algorithm, we'll do it just once):
        #
        master_hasher = hashlib.new(self._algorithm)
        bin_size = master_hasher.digest_size
        hex_size = bin_size * 2
        
        # Initialize the hash accumulator:
        accum = '\x00' * bin_size
                
        # Initiate zone AXFR stream:
        xfr = dns.query.xfr(
            where=self._server,
            port=self._port,
            zone=self._zone,
            relativize=False,
            timeout=self._timeout,
            lifetime=self._lifetime)
                
        # Hash the zone.  We'll pull messages from the xfr generator and 
        # extract rrset's, rdataset's and ultimately rdata's from them.
        # We need to drill-down to individual rdata's because the higher-level
        # dnspython structures (such as rrset's and rdataset's) are collections
        # of records, whose orderings are random, thus making hashes of such 
        # collections indeterminate: 
        #
        soa_rdata = None
        num_recs = 0
        for msg in xfr:
            for rrset in msg.answer:
                
                # Extract owner name from rrset:
                name = rrset.name
                
                # Convert rrset to rdataset:
                rdataset = rrset.to_rdataset()
                
                # Extract class, type and ttl from rdataset:
                rdclass = rdataset.rdclass
                rdtype = rdataset.rdtype
                
                if self._skipttl == True:
                    ttl = 0
                else:
                    ttl = rdataset.ttl
                # For each rdata in the rdataset:
                for rdata in rdataset:
                    # If this is the first record, it is the SOA, so save it
                    # off, and don't process it (the AXFR will end with the
                    # identical SOA so it will ultimately be included):
                    #
                    if soa_rdata is None:
                        soa_rdata = rdata

                    # It is not the first record; process it:
                    else:
                        num_recs = num_recs + 1
                        
                        # Construct a "canonical" text-oriented representation 
                        # of the resource record that we'll hash (similar to 
                        # the BIND presentation format, except no origin, use
                        # of FQDN's, and using single spaces to delimit fields).
                        # We'll use this format (vs. others like wire format) 
                        # because it is comprehensible and easy to synthesize, 
                        # even in other environments:
                        #
                        rec = '%s %d %s %s %s' % (
                            name,
                            ttl,
                            dns.rdataclass.to_text(rdclass),
                            dns.rdatatype.to_text(rdtype),
                            rdata.to_text(relativize=False))
                    
                        # Hash the resource record representation:
                        hasher = master_hasher.copy()
                        hasher.update(rec)
                        hash = hasher.digest()
                                        
                        # ADD the hash into the accumulator.  We do this for 
                        # speed, vs. something like hashing the join()'d sorted
                        # list of record hashes (which would require caching 
                        # and sorting every record hash value, increasing memory
                        # consumption and processing time).  Although the chosen
                        # technique may not produce the "most strongly-hashed"
                        # hash values, it should be sufficient for our purposes
                        # (especially used with those hash algorithms that  
                        # produce larger values):
                        #
                        new_accum = cStringIO.StringIO()
                        carry = 0
                        for i in xrange(bin_size - 1, -1, -1):
                            byte_sum = ord(hash[i]) + ord(accum[i]) + carry
                            byte = byte_sum % 256
                            carry = byte_sum // 256
                            new_accum.write(chr(byte))
                        accum = new_accum.getvalue()[::-1]
                    
                        # Dump the record/hash if specified:
                        if self._dump and self._verbose:
                            print '# %s  <==  "%s"' % (
                                dns.rdata._hexify(hash, chunksize=hex_size),
                                rec)
                        elif self._dump:
                            print '#', rec
                        elif self._verbose:
                            print '#', dns.rdata._hexify(hash, chunksize=hex_size)
                    
        # Return the SOA rdata, and accumulated hash value as a hex string:
        return (num_recs, soa_rdata, dns.rdata._hexify(accum, chunksize=hex_size))
        
if __name__ == '__main__':

    # Print startup banner:
    print '#', _banner

    # Parse command-line:
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='Calculate sum of hash values for AXFR\'d zone')
    parser.add_argument('zone',
        help='Name of zone to hash')
    parser.add_argument('-s', '--server', dest='server',
        default=DEFAULT_SERVER, metavar='s',
        help='DNS server address [%s]' % (DEFAULT_SERVER))
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

    # Construct and run a HAxfr instance:
    import time
    start_time = time.time()
    try:
        (num_recs, soa_rdata, hash) = HAxfr(
            args.server, 
            args.port, 
            args.zone,
            args.algorithm, 
            args.timeout,
            args.lifetime,
            args.dump,
            args.verbose,
            args.skipttl).run()
        
        stop_time = time.time()
        print '# Processed %d records in %f seconds' % (
            num_recs, (stop_time - start_time))
        print 'SOA-SERIAL: %d' % (soa_rdata.serial)
        print 'ZONE-HASH: %s [%s]' % (hash, args.algorithm)
        
    except Exception as e:
        print 'ERROR: {%s} %s' % (e.__class__.__name__, e)
        if args.verbose:
            raise

# end of file
