from __future__ import print_function
#import pandas as pd
from easysnmp import snmp_walk, snmp_get
from socket import gethostbyaddr, gethostbyname
from getpass import getpass, getuser
from time import sleep
import pexpect
import requests
from pprint import pprint
import sys
import json
import os
import re
#import imp
import traceback
#cup = imp.load_source('ciscoupgrade', os.path.join(os.path.abspath('.'),'ciscoupgrade.py'))
import ciscoupgrade as cup

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
		'output dir':'./output/',
		'default rwcommunity': 'private',
		'switch username': 'default',
		'switch password': 'l4y3r2',
		'switch enable': 'p4thw4y',
		'tftp server': '10.0.0.254',
		'telnet timeout': 90
	}
	with open('./cfg/' + filename, 'w') as dc:
		json.dump(d, dc, indent=4, sort_keys=True)

class Ciscoautoprovision:
	def __init__(self,configfile=None,username=None,password=None):
		self.pver3 = (sys.version_info > (3, 0))
		if not self.pver3:
			requests.packages.urllib3.disable_warnings()
		self.switches = []
		self.upgrades = []
		self.debug = 0
		self.firmwares = {}
		self.community = ''
		self.suser = ''
		self.spasswd = ''
		self.senable = ''
		self.tftp = ''
		self.telnettimeout = 60
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

	def ping(self,host):
		ping_command = "ping -W1 -c 1 " + host + " > /dev/null 2>&1 "
		response = os.system(ping_command)
		#Note:response is 1 for fail; 0 for success;
		return not response


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
			if data['output dir']:
				self.output_dir = data['output dir']
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
		for  i, d in enumerate(self.switches):
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
			'size': 300000
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
		#self.removeunreachable() # remove unreachable switches from list
		#list(set(map(lambda x: {x['_source']['host'] : x['_source']['message']},r.json()['hits']['hits'])))
		#[(x['_source']['host'] , x['_source']['message']) for x in r.json()['hits']['hits']  if '(1),' in x['_source']['message']]
		#[(x['_source']['logSource'], x['_source']['logSourceIP'], x['_source']['message']) for x in r.json()['hits']['hits']  if '(1),' in x['_source']['message']]
		pprint(self.switches)


	def search_from_syslogs(self,filename='/var/log/cisco/cisco.log'):
		try:
			logs = []
			with open(filename) as f:
				logs = [line.strip().split() for line in f.readlines() if len(line)]
			results = []
			errs = set()
			for log in logs:
   				 for x in log:
					if 'null' in x:
						host = {}
						host['hostname'] = x
						try:
							host['IPaddress'] = gethostbyname(x)
							results.append(host)
						except:
							if x not in list(errs):
								errs.add(x)
								print('cannot resolve hostname: ' + x)
			self.switches = [dict(t) for t in set([tuple(d.items()) for d in results])]
			pprint(self.switches)
		except Exception as e:
			traceback.print_exc()
			print(e)

	def rm_nonalnum(self,string):
		return ''.join(map(lambda x: x if x.isalnum() else '',string))


	def checkswitchmodels(self):
		# Boot image: SNMPv2-SMI::enterprises.9.2.1.73.0
		# https://supportforums.cisco.com/discussion/9696971/which-oid-used-get-name-cisco-device-boot-image
		# This doesn't show up in new devices, apparently...

		# CISCO-ENHANCED-IMAGE-MIB
		# IOS-XE: SNMPv2-SMI::enterprises.9.9.249.1.2.1.1.2.1000.1
		#	or CISCO-ENHANCED-IMAGE-MIB::ceImage
		# You can check if IOS-XE under the sysDescr.0 value

		# CISCO-FLASH-MIB::ciscoFlashFileName
		# C3560CG: ? SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.1
		modeloid = 'entPhysicalModelName'
		imageoid  = u'sysDescr.0' #.1.3.6.1.2.1.16.19.6.0'
		# filesoid = u'CISCO-FLASH-MIB::ciscoFlashFileName'
		bootoid = u'SNMPv2-SMI::enterprises.9.2.1.73.0'
		self.upgrades
		for host in self.switches:
			try:
				# Get the actual file name; not likely to work if startup-config is not present
				softimage_raw = snmp_get(bootoid, hostname=host['IPaddress'],community=self.community,version=2).value.split('/')[-1]
				if not softimage_raw:
					softimage_raw = snmp_get(imageoid,hostname=host['IPaddress'],community=self.community,version=2).value
					#softimage_raw = softimage_raw.split("Version")[1].strip().split(" ")[0].split(",")[0]
					#softimage = self.rm_nonalnum(softimage_raw)
					if re.findall(r'\d+\(.+?\)\.[eE]', softimage_raw):
						t = softimage_raw
						t = re.sub(r'\.','',t)
						t = re.sub(r'\((?=\d)','-',t)
						softimage_raw = re.sub(r'\)(?=\w+\d+)','.',t)
					softimage = [re.sub(r'\-m$', '', x.lower()) for x in re.findall(r'(?<=Software \()[\w\d-]+(?=\))|(?<=Version )[\d\.\w-]+',softimage_raw)]
				physical = snmp_walk(modeloid,hostname=host['IPaddress'],community=self.community,version=2)
				if len(physical[0].value) == 0:
				    del physical[0]
				model = str(physical[0].value.split('-')[1])
				
				print(host['IPaddress'],model,softimage)
				if model not in self.firmwares.keys():
					raise Exception('model' + model + 'not found in firmware list!')
					#TODO: make a way to add firmware
				if  all(x in self.firmwares[model].lower() for x in softimage):
					pass
				else:
					host['model'] = model
					host['bin'] = self.firmwares[model] 
					self.upgrades.append(host)
				#if not softimage or not '.bin' in softimage:
				#	print('its none')
				#	softimage = self.telnet_switchmodel(host)
			except Exception as e:
				print(e)
		if len(self.upgrades):
			print("upgrades needed for:")
			for host in self.upgrades:
				print('upgrade', host['IPaddress'], 'to', host['bin'])

	def upgradeswitch(self):
		for host in self.upgrades:
			try:
				print('\n####################################################\n')
				print('\ntry upgrade ', host['IPaddress'],host['model'],'\n')
				if not self.ping(host['IPaddress']):
					raise Exception('host not reachable')
				if host['model'].startswith('C38'):
					up = cup.c38XXUpgrade(host=host['IPaddress'],tftpserver=self.tftp,
						username=self.suser,password=self.spasswd,
						binary_file=host['bin'],
						enable_password=self.senable, debug=self.debug)
				elif host['model'].startswith('C45'):
					up = cup.c45xxUpgrade(host=host['IPaddress'],tftpserver=self.tftp,
						username=self.suser,password=self.spasswd,
						binary_file=host['bin'],
						enable_password=self.senable, debug=self.debug)
				else:
					print('Using default upgrade profile')
					up = cup.ciscoUpgrade(host=host['IPaddress'],tftpserver=self.tftp,
						username=self.suser,password=self.spasswd,
						binary_file=host['bin'],model=host['model'],
						enable_password=self.senable, debug=self.debug)
				if self.debug:
					print('\n####tftp_setup####\n')
				up.tftp_setup()
				if self.debug:
					print('\n####clean software#####')
				up.cleansoftware()
				if self.debug:
					print('\n####tftp get#####')
				up.tftp_getimage()
				if self.debug:
					print('\n#####software install####')
				up.softwareinstall()
				if self.debug:
					print('\n####send reload####')
				up.sendreload('no')
				if self.debug:
					print(up.log)

			except Exception as e:
  				traceback.print_exc()
				if self.debug:
					print('ERROR: ' + str(e))

	def generate_rsa(self):

		for host in self.switches:
			logfilename = os.path.abspath(os.path.join(self.output_dir, host['hostname'] + 'log.txt'))
			try:
				if self.debug:
					print('connecting to host ' + host['hostname'])
				if self.pver3:
					s = pexpect.spawnu('telnet ' + host['IPaddress'])
				else:
					s = pexpect.spawn('telnet ' + host['IPaddress'])
				s.timeout = self.telnettimeout
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
				if not keysize.isdigit():
					keysize = '2048' # default if didnt split the output correctly
				s.sendline(keysize)
				if self.debug:
					print("generating key of size " + keysize,end='')
				for n in range(0,30):
					if self.debug:
						print('.',end='')
					sleep(1)
				if self.debug:
					print('.')
				s.expect('#')
				s.logfile.close()
				s.close()
				with open(logfilename, "r") as f:
					output = f.read()
				if not '[OK]' in  output:
					if self.debug:
						print(s.before)
					raise Exception('did not exit rsa key generation correctly!')
				else:
					print('rsa key generated successfully!')
			except Exception as e:
				if self.debug:
					print(e)
				with open(logfilename, "r") as f:
					output = f.read()
				if self.debug:
					print(output)
