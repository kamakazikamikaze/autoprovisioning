from __future__ import print_function
from easysnmp import snmp_walk, snmp_get, EasySNMPTimeoutError
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
import mmap
import tftpy
import multiprocessing as mp
import subprocess
import tempfile
import string
import random
import traceback
import ciscoupgrade as cup

try:    # Python 3 compatibility
	input = raw_input
except NameError:
	pass

def generate_config(filename='autoProv.confg'):
	d = {
		'target firmware':{
			'C3560': 'c3560-ipbasek9-mz.122-55.SE10.bin',
			'C3560CG': 'c3560c405ex-universalk9-mz.150-2.SE.bin',
			'C3560CX': 'c3560cx-universalk9-mz.152-4.E1.bin',
			'C3560G': 'c3560-ipbasek9-mz.122-55.SE10.bin',
			'C3560V2': 'c3560-ipbasek9-mz.122-55.SE10.bin',
			'C3560X': 'c3560e-universalk9-mz.122-55.SE3.bin',
			'C3750': 'c3750-ipbasek9-mz.122-55.SE9.bin',
			'C3750G': 'c3750-ipbasek9-mz.122-55.SE9.bin',
			'C3750V2': 'c3750-ipbasek9-mz.122-55.SE9.bin',
			'C3750X': 'c3750e-ipbasek9-mz.150-2.SE9.bin',
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
		'telnet timeout': 90,
		'production rwcommunity' : ''
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
		self.prodcommunity = ''
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
			self.passwd = None
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
			if data['production rwcommunity']:
				self.prodcommunity = data['production rwcommunity']
			if data['switch username']:
				self.suser = data['switch username']
			if data['switch password']:
				self.spasswd = data['switch password']
			if data['switch enable']:
				self.senable = data['switch enable']
			if data['tftp server']:
				self.tftp = data['tftp server']
			self._rsa_pass_size = 32 if not 'rsa pass size' in data.keys() else data['rsa pass size']
			if int(data['telnet timeout']) < 30:
				raise Exception('telnet timeout must be greater than 30 seconds')
			else:
				self.telnettimeout = int(data['telnet timeout'])
		except Exception as e:
			sys.exit("An error occurred while parsing the config file: " + str(e))


	#def removeunreachable(self):
	#	for i, d in enumerate(self.switches):
	#		ping_str = "ping -W1 -c 1 " + d['IPaddress'] + " > /dev/null 2>&1 "
	#		response = os.system(ping_str)
	#		#Note:original response is 1 for fail; 0 for success; so we flip it
	#		if response:
	#			self.switches.pop(i)


	#user=None,passwd=None
	#def search(self,target='http://localhost',index='logstash-networkswitches',time=3,port=None,authenticate=False):
	#	self.passwd = getpass('sea password: ')
	#	if port is None:
	#		port = ''
	#	else:
	#		port = ':' + port  + '/' 
	#	url = target + port + index + '*/_search/?pretty' 
	#	term = 'Native VLAN mismatch*'
	#	query = { 
	#		'query': {
	#			'filtered': {
	#				'query': {
	#					'query_string': {
	#						'query': term,
	#						'analyze_wildcard': 'true'
	#					}
	#				}
	#			},
	#		},
	#		'filter': {
	#			'bool': {
	#				'must': [{
	#					'range': {
	#						'@timestamp': {
	#							'gte': 'now-' + str(time) + 'h',
	#							'lte': 'now'
	#						}
	#					}
	#				}],
	#			}
	#		},
	#		'size': 300000
	#	}
	#	#
	#	if authenticate:
	#		r = requests.get(url=url, data=json.dumps(query), verify=False, auth=(self.user,self.passwd))
	#	else:
	#		r = requests.get(url=url,data=json.dumps(query),verify=False)
	#	r.raise_for_status()
	#	result_dict = r.json()
	#	hits = result_dict['hits']['hits']
	#	results = []
	#	for x in hits:
	#		if '(1),' in x['_source']['message']:
	#			result = {}
	#			if 'logSourceIP' in x['_source'].keys():
	#				result['IPaddress'] = x['_source']['logSourceIP']
	#			elif 'host' in x['_source'].keys():
	#				result['IPaddress'] = x['_source']['host']
	#			result['hostname'] = gethostbyaddr(result['IPaddress'])[0]
	#			result['feed'] = x['_source']['message'].split('with')[1].split()[0] # word after with
	#			if 'null' in result['hostname']:
	#				results.append(result)
	#	self.switches = [dict(t) for t in set([tuple(d.items()) for d in results])]
	#	#self.removeunreachable() # remove unreachable switches from list
	#	#list(set(map(lambda x: {x['_source']['host'] : x['_source']['message']},r.json()['hits']['hits'])))
	#	#[(x['_source']['host'] , x['_source']['message']) for x in r.json()['hits']['hits']  if '(1),' in x['_source']['message']]
	#	#[(x['_source']['logSource'], x['_source']['logSourceIP'], x['_source']['message']) for x in r.json()['hits']['hits']  if '(1),' in x['_source']['message']]
	#	pprint(self.switches)


	def search_from_syslogs(self,filename='/var/log/cisco/cisco.log'):
		try:
			results = []
			errs = set()
			with open(filename, 'r+b') as f:
				log = mmap.mmap(f.fileno(), 0)
				res = set(re.findall(r'null\-[\w\d\.\-]+', log))
				for s in res:
					host = {}
					host['hostname'] = s
					try:
						host['IPaddress'] = gethostbyname(s)
						host['neighbors'] = {}
						neighbors = []
						for r in [re.findall(r'(?<=, with )([\d\w\-\.\/]+ [\d\w\-\.\/]+)', x) for x in re.findall(r'.*' + re.escape(s) + r'.*CDP.*', log)]:
							neighbors.extend(r)
						neighbors = list(set(neighbors))
						for neighbor in neighbors:
							neighbor = neighbor.split()
							if neighbor[0] in host['neighbors'].keys():
								host['neighbors'][neighbor[0]].append(neighbor[1])
							else:
								host['neighbors'][neighbor[0]] = [neighbor[1]]
						# host['neighbors'] = neighbors
						results.append(host)
					except:
						if s not in list(errs):
							errs.add(s)
							print('cannot resolve hostname: ' + s)
			#self.switches = [dict(t) for t in set([tuple(d.items()) for d in results])]
			self.switches = results
			pprint(self.switches)
		except Exception as e:
			traceback.print_exc()
			print(e)


	#def rm_nonalnum(self,string):
	#	return ''.join(map(lambda x: x if x.isalnum() else '',string))

	def get_information(self):
		for switch in self.switches:
			try:
				self.__get_model__(switch)
				self.__get_new_name__(switch)
				self.__get_serial__(switch)
			except EasySNMPTimeoutError:
				print(switch['IPaddress'] + ' timed out.')
				print('removing ' + switch['IPaddress'] + ' from switch list.')
				self.switches.pop(self.switches.index(switch))
			except Exception:
				if self.debug:
					print('error retrieving switch information from ' + switch['IP'])
					traceback.print_exc()


	def get_model(self):
		for switch in self.switches:
			try:
				self.__get_model__(switch)
			except EasySNMPTimeoutError:
				print(switch['IPaddress'] + ' timed out.')
				print('removing ' + switch['IPaddress'] + ' from switch list.')
				self.switches.pop(self.switches.index(switch))
			except Exception as e:
				traceback.print_exc()
				print(e)
		

	def get_new_name(self):
		for switch in self.switches:
			try:
				self.__get_new_name__(switch)
			except:
				if self.debug:
					print('Could not get new name for ' + switch['IPaddress'])
					traceback.print_exc()


	def get_serial(self):
		for switch in self.switches:
			try:
				serialnum = snmp_get(hostname=switch['IPaddress'], version=2, community=self.community, oids='SNMPv2-SMI::enterprises.9.3.6.3.0')
				switch['serial'] = serialnum.value
				if self.debug:
					print('serial number for ' + switch['IPaddress'] + ' is ' + switch['serial'])
			except Exception:
				print('error while getting serial for switch ' + switch['IPaddress'])
				if self.debug:
					traceback.print_exc()




	def ssh_opensession(self):
		for switch in self.switches:
			try:
				self.__ssh_opensession__(switch)
			except Exception as e:
				print(e)
				if self.debug:
					traceback.print_exc()


	def prepupgrade(self):
		for switch in self.switches:
			if switch['IPaddress'] in self.upgrades:
				try:
					self.__prepupgrade__(switch)
				except Exception as e:
					print(e)
					traceback.print_exc()


	def tftp_replace(self):
		for switch in self.switches:
			if switch['IPaddress'] not in self.upgrades:
				try:
					self.__tftp_replace__(switch)
				except Exception as e:
					traceback.print_exc()
					if self.debug:
						print('ERROR: ' + str(e))


	def tftp_startup(self):
		for switch in self.switches:
			if switch['IPaddress'] in self.upgrades:
				try:
					self.__tftp_startup__(switch)
				except Exception as e:
					traceback.print_exc()
					if self.debug:
						print('ERROR: ' + str(e))

	
	def reboot_save(self):
		for switch in self.switches:
			try:
				switch['session'].sendreload('yes')
			except Exception as e:
				traceback.print_exc()
				if self.debug:
					print('ERROR: ' + str(e))



	def editswitchlist(self):
		for index, switch in enumerate(self.switches):
			print(str(index) + ': ' + switch['IPaddress'] + '\t'  + switch['hostname'])
			r = -69
		while r not in [''] + map(lambda (x,y): str(x), enumerate(self.switches)):
			r = raw_input('Enter switch number to pop. leave empty to stop editing.')
		if r and r.isdigit():
			print(self.switches[int(r)]['IPaddress'] + ' was removed')
			self.switches.pop(int(r))
		


	def __get_model__(self,switch):
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
		softimage_raw = snmp_get(bootoid, hostname=switch['IPaddress'],community=self.community,version=2).value
		softimage = softimage_raw.split('/')[-1].lower()
		if not softimage_raw:
			softimage_raw = snmp_get(imageoid,hostname=switch['IPaddress'],community=self.community,version=2).value
			#softimage_raw = softimage_raw.split("Version")[1].strip().split(" ")[0].split(",")[0]
			#softimage = self.rm_nonalnum(softimage_raw)
			# Is there a ##.#(##)EX in the string?
			if re.findall(r'\d+\(.+?\)[eE]', softimage_raw):
				t = softimage_raw
				t = re.sub(r'\.','',t)
				t = re.sub(r'\((?=\d)','-',t)
				softimage_raw = re.sub(r'\)(?=\w+\d+)','.',t)
				# Also remove the trailing '-m' in the reported image name
			softimage = [re.sub(r'\-m$', '', x.lower()) for x in re.findall(r'(?<=Software \()[\w\d-]+(?=\))|(?<=Version )[\d\.\w-]+',softimage_raw)]
		physical = snmp_walk(modeloid,hostname=switch['IPaddress'],community=self.community,version=2)
		if len(physical[0].value) == 0:
			del physical[0]
		model = str(physical[0].value.split('-')[1])
		print(model)
		print(switch['IPaddress'],model,softimage)
		if model not in self.firmwares.keys():
			raise Exception('model' + model + 'not found in firmware list!')
			#TODO: make a way to add firmware
		if type(softimage) is unicode and softimage in self.firmwares[model].lower():
			switch['model'] = model
			switch['bin'] = self.firmwares[model]
			print(switch['IPaddress'] + ' already on ' + switch['bin'])
		elif type(softimage) is list and all(x in self.firmwares[model].lower() for x in softimage):
			switch['model'] = model
			switch['bin'] = self.firmwares[model]
			print(switch['IPaddress'] + ' already on ' + switch['bin'])
		else:
			switch['model'] = model
			switch['bin'] = self.firmwares[model]
			self.upgrades.append(switch['IPaddress'])
			print('upgrade ' + switch['IPaddress'] + ' to ' + switch['bin'])





	def __get_new_name__(self,switch):
		oid_index = []
		for neighbor, ports in switch['neighbors'].iteritems():				
			alias = snmp_walk(hostname=neighbor, version=2, community=self.prodcommunity, oids='IF-MIB::ifAlias')
			descr = snmp_walk(hostname=neighbor, version=2, community=self.prodcommunity, oids='IF-MIB::ifDescr')
			oid_index += [x.oid_index for x in descr if x.value in ports]
		newname = ''
		for i in oid_index:
			try:
				newname = alias[int(i) - 1].value.split()[0]
				# newname = [x.value.split()[0] for x in alias if x.oid_index == i][0]
				if newname:
					if self.debug:
						print(switch['hostname'], 'found new name:', newname)
					switch['new name'] = newname
					pass # TODO
			except IndexError:
				print(switch['hostname'], 'is not specified on any feedports!')		




	def __get_serial__(self,switch):
		#switch['serial'] = None
		serialnum = ''
		serialnum = snmp_get(hostname=switch['IPaddress'], version=2, community=self.community, oids='SNMPv2-SMI::enterprises.9.3.6.3.0')
		if serialnum:
			switch['serial'] = serialnum.value
		print('serial number for ' + switch['IPaddress'] + ' is ' + switch['serial'])



	def __ssh_opensession__(self,switch):
		if self.debug:
			print('staring ssh session for ' + switch['IPaddress'])
		if not self.ping(switch['IPaddress']):
			raise Exception('host not reachable')
		if switch['model'].startswith('C38'):
			switch['session'] = cup.c38XXUpgrade(host=switch['IPaddress'],tftpserver=self.tftp,
				username=self.suser,password=self.spasswd,
				binary_file=switch['bin'],
				enable_password=self.senable, debug=self.debug)
		elif switch['model'].startswith('C45'):
			switch['session'] = cup.c45xxUpgrade(host=switch['IPaddress'],tftpserver=self.tftp,
				username=self.suser,password=self.spasswd,
				binary_file=switch['bin'],
				enable_password=self.senable, debug=self.debug)
		else:
			print('Using default upgrade profile')
			switch['session'] = cup.ciscoUpgrade(host=switch['IPaddress'],tftpserver=self.tftp,
				username=self.suser,password=self.spasswd,
				binary_file=switch['bin'],model=switch['model'],
				enable_password=self.senable, debug=self.debug)	


			#else:
			#	try:
			#		self.tftp_replace_conf(switch)
			#	except Exception as e:
			#		traceback.print_exc()


	def __prepupgrade__(self,switch):
		print('\ntry upgrade ', switch['IPaddress'],switch['model'],'\n')
		if self.debug:
			print('\n####tftp_setup####\n')
		switch['session'].tftp_setup()
		if self.debug:
			print('\n####clean software#####')
		switch['session'].cleansoftware()
		if self.debug:
			print('\n####tftp get#####')
		switch['session'].tftp_getimage()
		if self.debug:
			print('\n#####software install####')
		switch['session'].softwareinstall()


	def _genrsa(self, switch):
		"""
		Securely generate an RSA keypair for switch.
		The results are added as a dictionary with the key switch['rsa']

		Raises an Exception if an error occurs while generating a private or public key
		
		Keyword arguments:
		switch -- dictionary representing the device (switch)
		"""
		password = self._randstr(self._rsa_pass_size)
		modulus = '4096' if not switch['model'] in ['C3560', 'C3750', 'C2940', 'C2960'] else '2048'
		temp = tempfile.NamedTemporaryFile()
		proc = subprocess.Popen(['openssl', 'genrsa', '-des3', '-passout', 'pass:'+password, '-out', temp.name, modulus], stdout=subprocess.PIPE)
		(out, err) = proc.communicate()
		if err is not None:
			raise Exception("Error generating private RSA key!")
		proc = subprocess.Popen(['openssl', 'rsa', '-in', temp.name, '-passin', 'pass:'+password, '-outform', 'PEM', '-pubout'], stdout=subprocess.PIPE)
		(out, err) = proc.communicate()
		if err is not None or len(out) < 5:
			raise Exception("Error generating public RSA key!")
		public = out.split('\n')[0:-1]
		with open(temp.name, 'r+b') as f:
			private = [line.strip() for line in f]
		del temp
		switch['rsa'] = {}
		switch['rsa']['public'] = public
		switch['rsa']['private'] = private
		switch['rsa']['password'] = password


	def _randstr(self, size):
		"""
		Securely generate a random string of a specified length
		Can include uppercase or lowercase ASCII characters and/or integers

		Keyword arguments:
		length -- desired size of string

		Returns:
		Random string
		"""
		# http://stackoverflow.com/a/23728630/1993468
		return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(size))


	def generate_rsa(self):
		for switch in self.switches:
			logfilename = os.path.abspath(os.path.join(self.output_dir, switch['hostname'] + 'log.txt'))
			try:
				if self.debug:
					print('connecting to host ' + switch['hostname'])
				if self.pver3:
					s = pexpect.spawnu('telnet ' + switch['IPaddress'])
				else:
					s = pexpect.spawn('telnet ' + switch['IPaddress'])
				s.timeout = self.telnettimeout
				s.logfile = open(logfilename, "w")
				if self.debug:
					print('Opening telnet session...')
				s.expect('Username: ')
				s.sendline(self.suser)
				s.expect('Password: ')
				s.sendline(self.spasswd)
				s.expect('>')
				s.sendline('enable')
				s.expect('Password: ')
				s.sendline(self.senable)
				s.expect('#')
				if self.debug:
					print('Setting up environment...')
				s.send('')
				s.sendline('terminal length 0')
				s.expect('#')
				s.sendline('terminal width 0')
				s.expect('#')
				s.sendline('show crypto key mypubkey rsa')
				s.expect('#')
				keyout = s.before
				s.send('')
				s.sendline('config t')
				s.expect('#')
				if 'name' in keyout:
					if self.debug:
						print('Erasing all existing keys...')
					s.sendline('crypto key zeroize rsa')
					s.expect(']: ')
					s.sendline('yes')
					s.expect('#')
				if not 'rsa' in switch.keys():
					if self.debug:
						print('Generating RSA key pair locally...')
					self._genrsa(switch)
				# `selfsigned` is the name we're giving to the pair, for now
				s.sendline('crypto key import rsa selfsigned pem terminal ' + switch['rsa']['password'])
				s.expect('itself.')
				if self.debug:
					print('Transferring public RSA key...')
				for line in switch['rsa']['public']:
					s.sendline(line)
				s.sendline('quit')
				s.expect('itself.')
				if self.debug:
					print('Transferring private RSA key...')
				for line in switch['rsa']['private']:
					s.sendline(line)
				s.sendline('quit')
				s.expect('#')
				successful = True if 'Key pair import succeeded' in s.before else False
				s.logfile.close()
				s.close()
				if not successful:
					if self.debug:
						print(s.before)
					raise Exception('RSA key was not imported successfully...')
				else:
					print('RSA key was imported successfully!')
			except Exception as e:
				print(e)
				if self.debug:
					with open(logfilename, "r") as f:
						print(f.read())


	def __tftp_replace__(self,switch):
		# try get null-serial#.conf config
		trynewname = False
		if 'serial' in switch.keys():
			dir_prefix = '/autoprov'
			filename = '/' + switch['serial'] + '-confg'
			try:
				self.__replacecfg__(switch=switch,remotefilename=str(dir_prefix + filename))
			except Exception as e:
				print(e)
				trynewname = True
		elif trynewname and 'new name' in switch.keys():
			filename = '/' + switch['new name'] + '-conf'
			try:
				self.__replacecfg__(switch=switch,remotefilename=filename)
			except:
				raise Exception('not able to find any config files for switch ' + switch['IPaddress'])
		#except Exception as e:
		#	print('this is just a normal exception')
		#	print(e)


	def __replacecfg__(self,switch,remotefilename,outputfile='./output/temp_config'):
		try:
			success = Helper('10.0.0.254').tftp_getconf(remotefilename=remotefilename, outputfile=outputfile)
			if success:
					with open(outputfile) as f:
						switch['config'] = f.readlines()
					switch['session'].tftp_replaceconf(remotefilename)
			else:
				print('could not find file '  + remotefilename)
				raise Exception
		except Exception as e:
			traceback.print_exc()
			print(e)	




	def __tftp_startup__(self, switch):
		# try get null-serial#.conf config
		trynewname = False
		if 'serial' in switch.keys():
			dir_prefix = '/autoprov'
			filename = '/' + switch['serial'] + '-confg'
			try:
				self.__startupcfg__(switch=switch,remotefilename=dir_prefix + filename)
			except Exception as e:
				traceback.print_exc()
				print(e)
				trynewname = True
		elif trynewname and 'new name' in switch.keys():
			filename = '/' + switch['new name'] + '-conf'
			try:
				self.__startupcfg__(switch=switch,remotefilename=filename)
			except:
				raise Exception('not able to find any config files for switch ' + switch['IPaddress'])
		#except Exception as e:
		#	print('this is just a normal exception')
		#	print(e)


	def __startupcfg__(self,switch,remotefilename,outputfile='./output/temp_config'):
		try:
			success = Helper('10.0.0.254').tftp_getconf(remotefilename=remotefilename, outputfile=outputfile)
			if success:
					with open(outputfile) as f:
						switch['config'] = f.readlines()
					switch['session'].tftp_getstartup(remotefilename)
			else:
				print('could not find file '  + remotefilename)
				raise Exception
		except Exception as e:
			traceback.print_exc()
			print(e)			



class Helper:
	def __init__(self,tftp_server='10.0.0.254'):
		if self._ping_(tftp_server):
			self.server = tftp_server
		else:
			raise Exception('no response from server!')
		self.client = tftpy.TftpClient(host=self.server, port=69)
	
	def _ping_(self,host):
		ping_command = "ping -W1 -c 1 " + host + " > /dev/null 2>&1 "
		response = os.system(ping_command)
		#Note:response is 1 for fail; 0 for success;
		return not response
	
	def tftp_putconf(self, inputfile, remotefilename):
		self.client.upload(filename=remotefilename, input=inputfile)

	def tftp_getconf(self, remotefilename, outputfile='./output/temp_config'):
		try:
			print(remotefilename + ' goes to \t' + outputfile)
			self.client.download(filename=str(remotefilename),output=outputfile)
			print('checkpoint 8')
			return True
		except tftpy.TftpShared.TftpException as t:
			if 'File not found' in t.message:
				print('could not find file tftp://' + self.server + remotefilename)
				return False
			print(t)