# Haxfr Comparator

A utility to compare AXFR response of zones from different servers. It compares modular sum of hash for each record in a zone between the given servers. While this utility supports several different hashing algorithms, the default (SHA-256) shall be utilized for the task. It uses haxfr as core component.

## Haxfr

A utility to "finger-print" a zone's contents across DNS servers. It calculates a modular sum of hash values calculated for every record in a zone that is AXFR'd from a particular DNS server.

## Installation

### Requirements
* Python 2.7 or above
* dnspython 1.10 or above

### Pre-requisites
* Host machine should have AXFR rights from DNS servers it queries

## Usage

### Haxfr Comparator

`$./haxfr_comparator.py --help`
        
        # haxfr ($Revision: 74232 $) by Neustar Inc.
        usage: haxfr_comparator.py [-h] [-f s] [-s1 s] [-s2 s] [-p i] [-a s] [-t s]
                           [-l s] [-d] [-k] [-v]

        Compare sum of hash values for AXFR'd zones from two servers

        optional arguments:
        -h, --help           show this help message and exit
        -f s, --file s       Input file having list of zones
        -s1 s, --server1 s   DNS server1 address [127.0.0.1]
        -s2 s, --server2 s   DNS server2 address [127.0.0.1]
        -p i, --port i       DNS server port [53]
        -a s, --algorithm s  Hash algorithm [sha256]
        -t s, --timeout s    Seconds waiting for AXFR response, or None [1.0]
        -l s, --lifetime s   Seconds to allow for entire AXFR, or None [None]
        -d, --dump           Dump resource records to stdout
        -k, --skipttl        Skip TTL while calculating hash
        -v, --verbose        Show detailed processing info

The one required argument is 'file'.  The DNS servers' address may be specified with the -s1 (--server1) and -s2 (--server2) option, if the default 127.0.0.1 isn't appropriate.  Similarly, if the port is not the default 53, it can be specified with the -p (--port) option.

As mentioned previously, the default SHA-256 algorithm shall be used, but if another algorithm is desired for experimentation, it may be specified with the -a (--algorithm) option.  Two timeout parameters are available: an AXFR initiation timeout specified with the -t (--timeout) parameter, and an overall AXFR operation timeout specified with the -l (--lifetime) parameter.  The defaults for these should be adequate for most cases.

Finally, some debugging-type options are available: -d (--dump) will show the text-oriented representation of the records in the zone (which are used as input to the hashing algorithm), and -v (--verbose) will show the hash values calculated for every record in the zone.  Either -d or -v or both can be specified.

The following show a few sample runs of the utility:

  `$ ./haxfr_comparator.py -s1 54.197.245.255  -s2 52.54.208.218 -k -f sample.txt`
        
     # haxfr ($Revision: 74232 $) by Neustar Inc.
     INFO:haxfr:Comparing AXFR from '54.197.245.255' and '52.54.208.218' for zone 'scene7.com'
     INFO:haxfr:AXFR responses for zone "scene7.com" are different

  `$ ./haxfr_comparator.py -s1 54.197.245.255  -s2 52.54.208.218 -k -f sample.txt`
        
    # haxfr ($Revision: 74232 $) by Neustar Inc.
    INFO:haxfr:Comparing AXFR from '54.197.245.255' and '52.54.208.218' for zone 'scene7.com'
    INFO:haxfr:AXFR responses for zone "scene7.com" are same

### Haxfr

`$ ./haxfr.py -h`
         
    # haxfr ($Revision: 72766 $) by Neustar Inc.
    usage: haxfr.py [-h] [-s s] [-p i] [-a s] [-t f] [-l f] [-d] [-v] zone

    Calculate sum of hash values for AXFR'd zone

    positional arguments:
    zone                 Name of zone to hash

    optional arguments:
    -h, --help           show this help message and exit
    -s s, --server s     DNS server address [127.0.0.1]
    -p i, --port i       DNS server port [53]
    -a s, --algorithm s  Hash algorithm [sha256]
    -t f, --timeout f    Seconds waiting for AXFR response [1.000000]
    -l f, --lifetime f   Seconds to allow for entire AXFR [120.000000]
    -d, --dump           Dump resource records to stdout
    -v, --verbose        Show detailed processing info
    
The one required argument is 'zone'.  The DNS server's address may be specified with the -s (--server) option, if the default 127.0.0.1 isn't appropriate.  Similarly, if the port is not the default 53, it can be specified with the -p (--port) option.

The following show a few sample runs of the utility.  For the first run, a
small test zone from the local DNS server is hashed, with both debugging
options activated:

`$ ./haxfr.py neustar.com -s localhost -d -v`
      
    # haxfr ($Revision: 72766 $) by Neustar Inc.
    # 7a32e391ffea53d804c1c8f62456ba7ff8ec1267be9a84162df8de0174f915ff  <==  "neustar.com. 86101 IN NS pdns6.ultradns.co.uk."
    # 11b42c9255256d6cc79c17f96a06a752b552f8fd1b11b36cecd60bf225054dbd  <==  "neustar.com. 86101 IN NS udns1.ultradns.net."
    # 8645dda5e9e19225e93feaabf544023fcf75d0f26f5a97ec591712dc1981cf8c  <==  "neustar.com. 86101 IN NS udns2.ultradns.net."
    # 0a873631fdf52b2f325d54a60baae1b60b495449128e91b6e1519f14c3241d4e  <==  "neustar.com. 86400 IN A 209.173.53.182"
    # 1400600e4fbce69d7de6210bc28c865cdd872e2ce2e836741a766627083e7a12  <==  "neustar.com. 86101 IN NS pdns2.ultradns.net."
    # e68f8162000782ff1284fa4f6a4a0f4c5c5031e5050358ef4db452f1e004d4fa  <==  "neustar.com. 86101 IN NS pdns3.ultradns.org."
    # c60e5a98244618f3fe3b91a4e4c232f0355e873b4febc228979916122fc09ece  <==  "neustar.com. 86101 IN NS pdns4.ultradns.org."
    # d3c98adb9b4c556c80ae94487149b4bc91391963a435922d7eb95571bcc094e9  <==  "neustar.com. 86101 IN NS pdns5.ultradns.info."
    # 4ac14a169ba96f9e194045f2957b64b4820476df6946b6012e5b72d4638e4c8b  <==  "smartmail.neustar.com. 86400 IN CNAME stihiron2.va.neustar.com."
    # 659acde16ad5107a308290259ea73e7f10497353d9286814b6de6e6154cc3dd6  <==  "smartmail.neustar.com. 86400 IN CNAME stihiron1.va.neustar.com."
    # a5ff1ae6dee5d13c785f01f1311a768a0384b1a96d4e6877c0d2ae7180658bcc  <==  "smartiron.neustar.com. 86101 IN CNAME smartmail.neustar.com."
    # e4d19f82ba1cbb0bf42556a195340aebe94ed9f63e144234de059ce6f779d0eb  <==  "neustar.com. 86101 IN NS pdns1.ultradns.net."
    # 586c317e6707f317f90ae5e2a43223f827b2a3d1101fdb1cec74468a4298d879  <==  "neustar.com. 86101 IN MX 20 smartmail.neustar.com."
    # 3d3c13317179ac489f2efc619433a3a83a15846e4e765fac81d692aad8f94760  <==  "smartmail.neustar.com. 86400 IN CNAME chihiron1.nc.neustar.com."
    # 44c825d534e1502a98081b179a0aec848bed1c0d8f9847f69e4bdb379fbf77dd  <==  "smartmail.neustar.com. 86400 IN CNAME chihiron2.nc.neustar.com."
    # 2ba727af43830012095388fe020fbb2986698e0358bffe9d067d3f623f0745b1  <==  "neustar.com. 86400 IN SOA pdns2.ultradns.net. nusqalab.neustar.biz. 2010101300 5 19 100 86101"
    # Processed 16 records in 0.071384 seconds
    SOA-SERIAL: 2010101300
    ZONE-HASH: f2604f763ca45294e72d168ee12057167cad79746c628eff6adae0de75fb97d8 [sha256]

The next sample run shows a calculation over a larger zone (with no debugging
options activated) from a remote DNS server:

`$ ./haxfr.py amazonaws.com -s 10.31.141.29`
  
    # haxfr ($Revision: 72766 $) by Neustar Inc.
    # Processed 3195 records in 1.158125 seconds
    SOA-SERIAL: 2012060711
    ZONE-HASH: 7266334d554f2532e511ec7a7033399a1c0eee041ae0f1a1ca7165d6e3db6215 [sha256]
