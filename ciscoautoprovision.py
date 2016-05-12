from __future__ import print_function
#import pandas as pd
#from pprint import pprint
from easysnmp import snmp_walk, snmp_get
from socket import gethostbyaddr
from getpass import getpass
import requests
import json
import os

class Ciscoautoprovision():
	def __init__(self,name='null'):
		self.name = name

	def pinghost(self):
		ping_str = "ping -W1 -c 1 " + self.ipaddress + " > /dev/null 2>&1 "
		response = os.system(ping_str)
		#Note:original response is 1 for fail; 0 for success; so we flip it
		return not response

	def search(self,target='http://localhost',index='logstash-networkswitches',time=3,port=None,user=None):
		target = 'https://sea.byu.edu/es/'
		index = 'mda-network'  
		if port is None:
			port = ''
		else:
			port = ':' + port  + '/' 
		if user:
			passwd = getpass()
		url = target + port + index + '*/_search/?pretty' 
		term = 'Native VLAN mismatch*'
		query = { 
			'query': {
				'filtered': {
					'query': {
						'query_string': {
							'query': term,
							'analyze_wildcard': 'true'
						}
					}
				},
			},
			'filter': {
				'bool': {
					'must': [{
						'range': {
							'@timestamp': {
								'gte': 'now-' + str(time) + 'h',
								'lte': 'now'
							}
						}
					}],
				}
			},
			'size': 3000
		}
		#
		if user:
			r = requests.get(url=url, data=json.dumps(query), verify=False, auth=(user,passwd))
		else:
			r = requests.get(url=url,data=json.dumps(query),verify=False)
		hits = r.json()['hits']['hits']
		results = set()
		for x in hits:
			result = {}
			if '(1),' in x['_source']['message']:
				result = {}
				if x['_source'].has_key('logSourceIP'):
					result['IPaddress'] = x['_source']['logSourceIP']
				elif x['_source'].has_key('host'):
					result['IPaddress'] = x['_source']['host']
				result['hostname'] = gethostbyaddr(result['IPaddress'])[0]
				result['feed'] = x['_source']['message'].split('with')[1].split()[0] # word after with
				print(result['hostname'])
				if 'null' in result['hostname']:
					results.add((result['hostname'],result['IPaddress'],result['feed']))
		self.switches = list(results)
		#list(set(map(lambda x: {x['_source']['host'] : x['_source']['message']},r.json()['hits']['hits'])))
		#[(x['_source']['host'] , x['_source']['message']) for x in r.json()['hits']['hits']  if '(1),' in x['_source']['message']]
		[(x['_source']['logSource'], x['_source']['logSourceIP'], x['_source']['message']) for x in r.json()['hits']['hits']  if '(1),' in x['_source']['message']]
		print()


	def generate_config(self):
		modelmap = {
			'C3560': 'c3560-ipbasek9-mz.122-53.SE2.bin',
			'C3560CG': 'c3560c405ex-universalk9-mz.150-2.SE.bin',
			'C3560CX': 'c3560cx-universalk9-mz.152-4.E1.bin',
			'C3560G': 'c3560-ipbasek9-mz.122-53.SE2.bin',
			'C3560V2': 'c3560-ipbasek9-mz.122-53.SE2.bin',
			'C3560X': 'c3560e-universalk9-mz.122-55.SE3.bin',
			'C3750': 'c3750-ipbasek9-mz.122-55.SE9.bin',
			'C3750G': 'c3750-ipbasek9-mz.122-55.SE9.bin',
			'C3750V2': 'c3750-ipbasek9-mz.122-55.SE9.bin',
			'C3750X': 'c3750e-ipbasek9-mz.122-53.SE2.bin',
			'C3850': 'cat3k_caa-universalk9.SPA.03.07.03.E.152-3.E3.bin',
			'C4506': 'cat4500e-universalk9.SPA.03.07.03.E.152-3.E3.bin',
			'community': 'private',
			'tftpserver': '10.0.0.254'
		}
		modelmap

	def upgradeswitch(self,switchname,community):
		
		try:
			modeloid = 'ENTITY-MIB::entPhysicalDescr'
			imageoid  = '1.3.6.1.2.1.16.19.6.0'

			model = snmp_walk(modeloid,hostname=switchname,community=community,version=2)
			activeimage = snmp_get(imageoid,hostname=switchname,community=community,version=2).value
			activeimage.split('/')[-1]
		except Exception as e:
			print(e)


host = '10.3.35.5'
user = getuser()
passwd = getpass()
s = pexpect.spawn ('telnet ' + host)
s.logfile = open("telnetlog.txt", "w")
s.expect('Username: ')
s.sendline(user)
s.expect('Password: ')
s.sendline(passwd)
s.expect('#')
s.sendline('config t')
s.expect('#')
s.sendline('crypto key generate rsa')
s.expect(']: ')
if 'yes' in s.before:
	s.sendline('yes')
	s.expect(']: ')
s.sendline('1024')
print("generating key.",end='')
sleep(2)
print('.')
s.expect('#')
s.close()
with open("telnetlog.txt", "r") as f:
	output = f.read()
print(output)
if not '[OK]' in  output:
	print('did not exit rsa key generation correctly!\n')
	print(s.before)
	raise Exception