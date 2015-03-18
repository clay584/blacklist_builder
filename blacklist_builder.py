#!/usr/bin/env python

'''
This module will download from various IP blacklists and compile them
for use with Palo Alto firewalls and possibly others.
'''
try:
	import argparse
	import urllib2
	from netaddr import IPNetwork, IPRange, AddrFormatError, cidr_merge
	import os.path
except ImportError as e:
	print e
	print 'This requires argparse, urllib2, and netaddr modules.'

def open_file(parser, filename):
	if not os.path.exists(filename):
		parser.error('File %s does not exist.' % filename)
	else:
		return open(filename, 'r')

def get_urls(data):
	urls = []
	while 1:
		line = data.readline()
		#Ignore commented lines
		if line.startswith('#'):
			pass
		else:
			if not line or len(line) == 0:
				break
			urls.append(line.rstrip())
	return urls

def download_list(url):
	'''
	INPUT: Takes URL string object.

	ACTION: Tries to download IP blacklist from http location

	OUTPUT: Returns retrieved content, or None if downloading fails.
	'''

	try:
		#Download blacklist and assign each line to list object
		#fool SpamHaus by setting user agent string
		headers = {'User-agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.89 Safari/537.36'}
		req = urllib2.Request(url, None, headers)
		response = urllib2.urlopen(req)
		content = []
		while 1:
			line = response.readline()
			if not line:
				break
			content.append(line.rstrip())
		return content
	except urllib2.HTTPError as e:
		print e
		print 'Failed to download blacklist from ' + url
		return None

def parse_list(raw_list):
	'''
	INPUT: Takes raw data that was downloaded from the download_list function.

	ACTION: Verifies each line is a valid IPv4 or IPv6 address or address range.

	OUTPUT: Returns a list of valid IP addresses.
	'''

	ip_list = []
	for line in raw_list:
		try:
			#Ignore commented lines
			if line.startswith('#') or line.startswith(';') or len(line) == 0:
				pass
			else:
				#drops extraneous data that is included after IP addresses in some lists (41.138.172.0/23 ; SBL208940)
				line = line.split()[0]
				#parse generic IP ranges. i.e. - 192.168.1.5-192.168.1.65
				if '-' in line:
					start_ip = line.split('-')[0]
					end_ip = line.split('-')[1]
					ip_range = IPRange(start_ip, end_ip)
					subnets = ip_range.cidrs()
					for subnet in subnets:
						ip_list.append(subnet)
				else:
					#parse anything else. i.e. - 10.0.0.0/8, 1.2.3.4
					netblock = IPNetwork(line)
					ip_list.append(netblock)
		except AddrFormatError as e:
			print e
			print 'Failed to parse ' + line
	return ip_list

def export_list(master_list, output_filename):
	'''
	INPUT: Takes in a list of valid IP addresses from the parse_list function, and an output file name.

	ACTION: Writes output file correctly formatted for Palo Alto firewalls.

	OUTPUT: Writes output file
	'''

	try:
		with open(output_filename, 'w') as f:
			for item in master_list:
				#for /32 ip blocks (hosts), write just the IP address without the CIDR length
				if item.size == 1:
					f.write(str(item.network) + '\n')
				#for anything larger than a /32, write the CIDR block. i.e. - 12.2.3.0/24
				else:
					f.write(str(item.cidr) + '\n')
	except IOError as e:
		print e
		print 'Failed to write output file ' + output_filename


def main():

	parser = argparse.ArgumentParser(description='IP Blacklist Generator')

	parser.add_argument('-if', type=lambda x: open_file(parser, x), dest='input_file', metavar='INPUT_FILE', required=True, help='Input file with blacklist URLs')
	parser.add_argument('-of', type=str, dest='output_file', metavar='OUTPUT_FILE', required=True, help='Output file')

	args = parser.parse_args()

	output_filename = args.output_file
	input_file = args.input_file


	#Create master list that will ultimately get written to file
	master_list = []

	#Read in URLs from file and build list
	urls = get_urls(input_file)

	#Download lists, parse, and append to master list
	for url in urls:
		raw_list = download_list(url)
		if raw_list is not None:
			formatted_list = parse_list(raw_list)
			for address_block in formatted_list:
				master_list.append(address_block)

	#aggregate and remove duplicates
	master_list = cidr_merge(master_list)

	#sort the list of IP objects
	master_list.sort()

	#Export list to file
	export_list(master_list, output_filename)


if __name__ == '__main__':
	main()
