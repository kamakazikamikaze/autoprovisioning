from __future__ import print_function
#import pandas as pd
from easysnmp import snmp_walk, snmp_get
from socket import gethostbyaddr
from getpass import getpass, getuser
from time import sleep
import pexpect
import requests
from pprint import pprint
import sys
import json
import os
try:    # Python 3 compatibility
    input = raw_input
except NameError:
    pass

def generate_config(filename='autoProv.confg'):
	d = {
		'target firmware':{
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
		},
		'debug':'1',
		'default rwcommunity': 'private',
		'switch username': 'default',
		'switch password': 'l4y3r2',
		'switch enable': 'p4thw4y',
		'tftp server': '10.0.0.254',
		'telnet timeout':90
	}
	with open('./cfg/' + filename, 'w') as dc:
		json.dump(d, dc, indent=4, sort_keys=True)

class Ciscoautoprovision:
	def __init__(self,configfile=None,username=None,password=None):
		#requests.packages.urllib3.disable_warnings()
		if configfile:
			self.parseconfig(configfile)
		if username is None:
			self.user = getuser()
		else:
			self.user = username
		if password is None:
			self.passwd = getpass('sea kibana password: ')
		else:
			self.passwd = password

	def parseconfig(self,filename):
		with open('./cfg/' + filename) as f:
			data = json.load(f)
		#pprint(data)
		try:
			if int(data['debug']) <= 1  and int(data['debug']) >= 0:
				self.debug = int(data['debug'])
			else:
				raise Exception('\'debug\' is not a valid value!')
			if isinstance(data['target firmware'],dict):
				self.firmwares = data['target firmware']
			else:
				raise Exception('target firmware is not a valid dictionary')
			if data['default rwcommunity']:
				self.community = data['default rwcommunity']
			if data['switch username']:
				self.suser = data['switch username']
			if data['switch password']:
				self.spasswd = data['switch password']
			if data['switch enable']:
				self.senable = data['switch enable']
			if data['tftp server']:
				self.tftp = data['tftp server']
			if int(data['telnet timeout']) < 30:
				raise Exception('telnet timeout must be greater than 30 seconds')
			else:
				self.telnettimeout = int(data['telnet timeout'])
		except Exception as e:
			sys.exit("An error occurred while parsing the config file: " + str(e))


	def removeunreachable(self):
		for i, d in enumerate(self.switches):
			ping_str = "ping -W1 -c 1 " + d['IPaddress'] + " > /dev/null 2>&1 "
			response = os.system(ping_str)
			#Note:original response is 1 for fail; 0 for success; so we flip it
			if response:
				self.switches.pop(i)
	#user=None,passwd=None
	def search(self,target='http://localhost',index='logstash-networkswitches',time=3,port=None,authenticate=False):
		if port is None:
			port = ''
		else:
			port = ':' + port  + '/' 
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
		if authenticate:
			r = requests.get(url=url, data=json.dumps(query), verify=False, auth=(self.user,self.passwd))
		else:
			r = requests.get(url=url,data=json.dumps(query),verify=False)
		r.raise_for_status()
		result_dict = r.json()
		hits = result_dict['hits']['hits']
		results = []
		for x in hits:
			if '(1),' in x['_source']['message']:
				result = {}
				if 'logSourceIP' in x['_source'].keys():
					result['IPaddress'] = x['_source']['logSourceIP']
				elif 'host' in x['_source'].keys():
					result['IPaddress'] = x['_source']['host']
				result['hostname'] = gethostbyaddr(result['IPaddress'])[0]
				result['feed'] = x['_source']['message'].split('with')[1].split()[0] # word after with
				if 'null' in result['hostname']:
					results.append(result)
		self.switches = [dict(t) for t in set([tuple(d.items()) for d in results])]
		self.removeunreachable() # remove unreachable switches from list
		#list(set(map(lambda x: {x['_source']['host'] : x['_source']['message']},r.json()['hits']['hits'])))
		#[(x['_source']['host'] , x['_source']['message']) for x in r.json()['hits']['hits']  if '(1),' in x['_source']['message']]
		#[(x['_source']['logSource'], x['_source']['logSourceIP'], x['_source']['message']) for x in r.json()['hits']['hits']  if '(1),' in x['_source']['message']]
		pprint(self.switches)


		#modelmap

	def rm_nonalnum(self,string):
		return ''.join(map(lambda x: x if x.isalnum() else '',string))


	def checkswitchmodels(self):
		modeloid = 'entPhysicalModelName'
		imageoid  = u'sysDescr.0' #.1.3.6.1.2.1.16.19.6.0'
		

		for host in self.switches:
			try:
				softimage_raw = snmp_get(imageoid,hostname=host['IPaddress'],community=self.community,version=2).value
				softimage_raw = softimage_raw.split("Version")[1].strip().split(" ")[0].split(",")[0]
				softimage = self.rm_nonalnum(softimage_raw)
				physical = snmp_walk(modeloid,hostname=host['IPaddress'],community=self.community,version=2)
				if len(physical[0].value) == 0:
				    del physical[0]
				model = str(physical[0].value.split('-')[1])
				
				print(model,softimage)
				if model not in self.firmwares.keys():
					raise Exception('model' + model + 'not found in firmware list!')
					#TODO: make a way to add firmware
				if softimage in self.rm_nonalnum(self.firmwares[model]):
					print('yay!')
				else:
					print(self.rm_nonalnum(self.firmwares[model]))
				#if not softimage or not '.bin' in softimage:
				#	print('its none')
				#	softimage = self.telnet_switchmodel(host)
			except Exception as e:
				print(e)

	def upgradeswitch(self,switchname,community):
		try:
			#modeloid = 'ENTITY-MIB::entPhysicalDescr'
			
			imageoid  = '1.3.6.1.2.1.16.19.6.0'
			

			activeimage = snmp_get(imageoid,hostname=switchname,community=community,version=2).value
			activeimage.split('/')[-1]
		except Exception as e:
			print(e)

	def generate_rsa(self):

		for host in self.switches:
			try:
				print('connecting to host ' + host['hostname'])
				s = pexpect.spawnu('telnet ' + host['IPaddress'])
				s.timeout = self.telnettimeout
				logfilename = host['hostname'] + 'log.txt'
				s.logfile = open(logfilename, "w")
				s.expect('Username: ')
				s.sendline(self.suser)
				s.expect('Password: ')
				s.sendline(self.spasswd)
				s.expect('>')
				s.sendline('enable')
				s.expect('Password: ')
				s.sendline(self.senable)
				s.expect('#')
				s.sendline('config t')
				s.expect('#')
				s.sendline('crypto key generate rsa')
				s.expect(']: ')
				if 'yes' in s.before:
				    s.sendline('yes')
				    s.expect(']: ')
				#get largest possible keysize
				s.sendline('?')
				s.expect(']: ')
				keysize = s.before.split('.')[0].split()[-1]
				if not keysize.isnumeric():
					keysize = '2048' # default if didnt split the output correctly
				s.sendline(keysize)
				print("generating key of size " + keysize,end='')
				for n in range(0,30):
					print('.',end='')
					sleep(1)
				print('.')
				s.expect('#')
				s.logfile.close()
				s.close()
				with open(logfilename, "r") as f:
					output = f.read()
				if not '[OK]' in  output:
					print(s.before)
					raise Exception('did not exit rsa key generation correctly!')
				else:
					print('rsa key generated successfully!')
			except Exception as e:
				print(e)
				with open(logfilename, "r") as f:
					output = f.read()
				print(output)



#
#
#
#
#-A udpIn -p udp -m udp -i eth0 --source 10.11.168.0.1/32 --dport 514 -m state --state NEW -j ACCEPT
'''
	def telnet_switchmodel(self,host):
		try:
			s = pexpect.spawnu('telnet ' + host['IPaddress'])
			s.timeout = self.telnettimeout
			logfilename = host['hostname'] + 'log.txt'
			s.logfile = open(logfilename, "w")
			s.expect('Username: ')
			s.sendline(self.suser)
			s.expect('Password: ')
			s.sendline(self.spasswd)
			s.expect('>')
			s.sendline('enable')
			s.expect('Password: ')
			s.sendline(self.senable)
			s.expect('#')
			s.sendline('dir all | include bin')
			s.expect('#')
			return s.before.split()
		except Exception as e:
			print(e)
			return
'''
