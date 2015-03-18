# Blacklist Builder
Fetches multiple blacklists, formats, outputs to text file for use with Palo Alto firewalls (possibly others).

#Installation
In order to run this script you will need argparse, urllib2, and netaddr.  It was built and tested on python2.6.

#Usage
##Syntax
    python blacklist_builder.py --help
    usage: blacklist_builder.py [-h] -if INPUT_FILE -of OUTPUT_FILE    

    IP Blacklist Generator    

    optional arguments:
      -h, --help       show this help message and exit
      -if INPUT_FILE   Input file with blacklist URLs
      -of OUTPUT_FILE  Output file

##Example
    python blacklist_builder.py -if urls.txt -of blacklist.txt

##Current Blacklists
These are the blacklists that are currently tested and working.  You can likely add more with no issue, but these have been tested.

    #Open BL list
    http://www.openbl.org/lists/base.txt
    #Spamhaus DROP list
    http://www.spamhaus.org/drop/drop.txt
    #Spamhaus extended DROP list (EDROP)
    http://www.spamhaus.org/drop/edrop.txt
    #Malware Domain List - Active IP Addresses
    http://www.malwaredomainlist.com/hostslist/ip.txt
    #Emerging threats firewall rules - Block IPs
    http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
    #Team Cymru Bogon List
    https://www.team-cymru.org/Services/Bogons/bogon-bn-nonagg.txt

##Adding Blacklists
Just add another entry to urls.txt
