from __future__ import print_function
from easysnmp import snmp_walk, snmp_get, EasySNMPTimeoutError
from socket import gethostbyaddr, gethostbyname
# from getpass import getpass, getuser
import logging
from time import sleep
import pexpect
import requests
from pprint import pprint, pformat
import sys
import json
import os
import re
import mmap
import tftpy
from multiprocessing import Pool
import subprocess
import tempfile
import string
import random
# import traceback
import ciscoupgrade as cup

try:    # Python 3 compatibility
	input = raw_input
	range = xrange
	import copy_reg
	import types
	def _reduce_method(m):
		if m.im_self is None:
			return getattr, (m.im_class, m.im_func.func_name)
		else:
			return getattr, (m.im_self, m.im_func.func_name)
	copy_reg.pickle(types.MethodType, _reduce_method)
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
			'debug print':'0',
			'log file':'autoprov.log',
			'output dir':'./output/',
			'default rwcommunity': 'private',
			'switch username': 'default',
			'switch password': 'l4y3r2',
			'switch enable': 'p4thw4y',
			'tftp server': '10.0.0.254',
			'telnet timeout': 20,
			'production rwcommunity' : ''
		}
		with open('./cfg/' + filename, 'w') as dc:
			json.dump(d, dc, indent=4, sort_keys=True)
		logging.getLogger('CAP')
		logging.debug('Config generated to %s', filename)


class CiscoAutoProvision:
	def __init__(self,configfile):
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
		self._parseconfig(configfile)
		self._setuplogger()
		self.logger.debug('Class instance created.')


	def _setuplogger(self):
		level = logging.DEBUG if self.debug else logging.INFO
		# http://stackoverflow.com/a/9321890/1993468
		logging.basicConfig(
			level=level,
			filename=os.path.join(os.path.abspath(self.output_dir), self.logfile),
			format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
			datefmt='%m-%d %H:%M:%S',
			filemode='a')
		formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s', datefmt='%m-%d %H:%M:%S')
		fh = logging.FileHandler(os.path.join(os.path.abspath(self.output_dir), self.logfile))
		fh.setLevel(level)
		fh.setFormatter(formatter)
		if self.debug_print:
			formatter = logging.Formatter(
				'%(name)-12s: %(levelname)-8s %(message)s')			
			console = logging.StreamHandler()
			console.setLevel(level)
			console.setFormatter(formatter)
			logging.getLogger('').addHandler(console)
			# self.logger.addHandler(console)
		self.logger = logging.getLogger('CAP')
		self.logger.setLevel(level)
		self.logger.addHandler(fh)
		self.logger.debug('Logger successfully created.')


	def ping(self,host):
		ping_command = "ping -W1 -c 1 " + host + " > /dev/null 2>&1 "
		response = os.system(ping_command)
		#Note:response is 1 for fail; 0 for success;
		return not response


	def _parseconfig(self,filename):
		with open('./cfg/' + filename) as f:
			data = json.load(f)
		#pprint(data)
		try:
			if int(data['debug']) <= 1  and int(data['debug']) >= 0:
				self.debug = int(data['debug'])
			else:
				raise Exception('\'debug\' is not a valid value!')
			if 'debug print' in data.keys():
				self.debug_print = int(data['debug print'])
			else:
				self.debug_print = 0
			if isinstance(data['target firmware'],dict):
				self.firmwares = data['target firmware']
			else:
				raise Exception('target firmware is not a valid dictionary')
			if 'log file' in data.keys():
				self.logfile = data['log file']
			else:
				self.logfile = 'autoprov.log'
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
			if int(data['telnet timeout']) < 5:
				raise Exception('telnet timeout must be greater than 30 seconds')
			else:
				self.telnettimeout = int(data['telnet timeout'])
		except Exception as e:
			sys.exit("An error occurred while parsing the config file: " + str(e))

	
	def search(self,target='http://localhost',index='logstash-autoprovision',time_minutes=60,port=9200): #,authenticate=False 
		if port is None:
			port = ''
		else:
			port = ':' + str(port)  + '/' 
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
								'gte': 'now-' + str(time_minutes) + 'm',
								'lte': 'now'
							}
						}
					}],
				}
			},
			'size': 10000
		}

		r = requests.get(url=url,data=json.dumps(query))
		r.raise_for_status()
		result_dict = r.json()
		hits = result_dict['hits']['hits']
		results = []
		errs = set()
		for log in hits:
			try:
				host = {}
				host['IPaddress'] = log['_source']['host']
				neighbors = ''
				for r in re.findall(r'(?<=, with )([\d\w\-\.\/]+ [\d\w\-\.\/]+)',log['_source']['message']):
					neighbors += r
				host['nei_raw'] = neighbors
				results.append(host)
			except Exception:
				# traceback.print_exc()
				self.logger.error(log['_source']['host'],exec_info=True)
				if log['_source']['host'] not in list(errs):
					errs.add(log['_source']['host'])
					# print('cannot parse log: ' + log['_source']['host'])
		self.switches = [dict(t) for t in set([tuple(d.items()) for d in results])]
		for switch in self.switches:
			try:
				switch['hostname'] = gethostbyaddr(switch['IPaddress'])[0]
				switch['neighbors'] = {}
				neighbor = switch['nei_raw'].encode().split()
				n = neighbor.pop(0)
				switch['neighbors'].setdefault(n,[])
				for nei in neighbor:
					switch['neighbors'][n].append(nei)
				del switch['nei_raw']
			except:
				# traceback.print_exc()
				self.logger.error(switch, exec_info=True)
				self.logger.debug('could not find hostname for ' + switch['IPaddress'])
				# print(switch)
				# print('could not find hostname for ' + switch['IPaddress'])
		self.logger.debug(pformat(self.switches))
		# if self.debug:
			# pprint(self.switches)


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
			# traceback.print_exc()
			print(e)


	def autoupgrade(self, switch):
		try:
			logging.getLogger('CAP.' + switch['hostname'])
			# if self.debug:
			# 	print('\n', switch['IPaddress'], '\t', switch['hostname'])
			logging.info(switch['IPaddress'])
			try:
				self._get_model(switch)
				self._get_serial(switch)
			except EasySNMPTimeoutError:
				raise Exception('Could not retrieve model and/or serial!')
			try:
				self._get_new_name(switch)
			except EasySNMPTimeoutError:
				# if self.debug:
				# 	print('could not access neighbor switch')
				logging.debug('Could not access neighbor switch')
			#generate RSA keys
			logfilename = os.path.abspath(os.path.join(self.output_dir, switch['hostname'] + 'log.txt'))
			self._gen_rsa(switch,logfilename=logfilename)
			# open ssh session
			self._ssh_opensession(switch)
			if switch['IPaddress'] in self.upgrades:
				# In order for the reboot to upgrade the device,
				# the running configuration must be saved. Therefore
				# the running-config should be overwritten with the 
				# to-be/startup-config, set the target boot image,
				# then save changes after applying the reboot command
				self._prepupgrade(switch)
				self._tftp_startup(switch)
				# reboot
				switch['session'].sendreload('no')
				# IOS-XE (3750X?, 3850, 4506) take a long time to upgrade
				self._wait(switch['new IPaddress'], timeout=1200)
				self._gen_rsa(switch, logfilename=logfilename)
			else:
				self._tftp_startup(switch)
				self._tftp_replace(switch,time=15)
				self._wait(switch['new IPaddress'])
			#continual ping
		except Exception as e:
			logging.error('Error occurred', exec_info=True)
			# print(e)
	

	def run(self):
		'''
		Full provisioning process
		'''
		self.search()
		# if self.switches:
		self.logger.info('Starting Autoprovision process')
		p = Pool()
		for switch in self.switches:
			self.logger.debug('Adding ' + switch['hostname'] + ' to pool.')
			p.apply_async(self.autoupgrade, (switch,))
		p.close()
		p.join()


	def _get_model(self,switch):
		# logger = logging.getLogger('CAP.' + switch['hostname'].split('.')[0])
		logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
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
		if len(softimage_raw.split('/')) <= 1:
			softimage = softimage_raw.split(':')[-1].lower()
		else:
			softimage = softimage_raw.split('/')[-1].lower()
		if not softimage_raw or softimage == 'packages.conf':
			softimage_raw = snmp_get(imageoid,hostname=switch['IPaddress'],community=self.community,version=2).value
			#softimage_raw = softimage_raw.split("Version")[1].strip().split(" ")[0].split(",")[0]
			#softimage = self.rm_nonalnum(softimage_raw)
			# Is there a ##.#(##)EX in the string?
			if re.findall(r'\d+\(.+?\)[eE][xX]', softimage_raw):
				t = softimage_raw
				t = re.sub(r'\.','',t)
				t = re.sub(r'\((?=\d)','-',t)
				softimage_raw = re.sub(r'\)(?=\w+\d+)','.',t)
				# Also remove the trailing '-m' in the reported image name
			# 03.07.03E is not in cat3k_caa-universalk9.SPA.03.07.03.E.152-3.E3.bin
			elif re.findall(r'\d+\.\d+\.\d+[eE]', softimage_raw):
				softimage_raw = re.sub(r'(?<=\d{2}\.\d{2}\.\d{2})[eE]','', softimage_raw)
			softimage = [re.sub(r'\-m$', '', x.lower()) for x in re.findall(r'(?<=Software \()[\w\d-]+(?=\))|(?<=Version )[\d\.\w-]+',softimage_raw)]
		physical = snmp_walk(modeloid,hostname=switch['IPaddress'],community=self.community,version=2)
		if len(physical[0].value) == 0:
			del physical[0]
		model = str(physical[0].value.split('-')[1])
		logger.debug('IOS image: %s', softimage)
		if model not in self.firmwares.keys():
			raise Exception('model' + model + 'not found in firmware list!')
			#TODO: make a way to add firmware
		if type(softimage) is unicode and softimage in self.firmwares[model].lower():
			switch['model'] = model
			switch['bin'] = self.firmwares[model]
			logger.debug('No upgrade needed. Target IOS: %s', switch['bin'])
		elif type(softimage) is list and all(x in self.firmwares[model].lower() for x in softimage):
			switch['model'] = model
			switch['bin'] = self.firmwares[model]
			logger.debug('No upgrade needed. Target IOS: %s', switch['bin'])
		else:
			switch['model'] = model
			switch['bin'] = self.firmwares[model]
			self.upgrades.append(switch['IPaddress'])
			logger.debug('Upgrade needed. Target IOS: %s', switch['bin'])


	def _get_new_name(self,switch):
		logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		oid_index = []
		for neighbor, ports in switch['neighbors'].iteritems():				
			alias = snmp_walk(hostname=neighbor, version=2, community=self.prodcommunity, oids='IF-MIB::ifAlias')
			descr = snmp_walk(hostname=neighbor, version=2, community=self.prodcommunity, oids='IF-MIB::ifDescr')
			oid_index += [x.oid_index for x in descr if x.value in ports]
		newname = ''
		for i in oid_index:
			try:
				newname = alias[int(i) - 1].value.split()[0]
				if newname:
					logger.debug('New name: %s', newname)
					switch['new name'] = newname
					pass # TODO
			except IndexError:
				logger.warning('Target hostname was not found on a neighboring switch for %s!', switch['IPaddress'])


	def _get_serial(self,switch):
		logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		serialnum = self.getoids[switch['model']](switch['IPaddress'],self.community)
		if serialnum:
			switch['serial'] = serialnum
			logger.info('Serial number: %s', serialnum)


	def _ssh_opensession(self,switch):
		logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		logger.debug('Preparing SSH session')
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
			logger.debug('Using default upgrade profile')
			switch['session'] = cup.ciscoUpgrade(host=switch['IPaddress'],tftpserver=self.tftp,
				username=self.suser,password=self.spasswd,
				binary_file=switch['bin'],model=switch['model'],
				enable_password=self.senable, debug=self.debug)	


	def _prepupgrade(self,switch):
		# logger = logging.getLogger('CAP.' + switch['hostname'].split('.')[0])
		logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		logger.info('Preparing upgrade process...')
		switch['session'].tftp_setup()
		logger.debug('Clearing out old images...')
		switch['session'].cleansoftware()
		logger.debug('Retrieving IOS image...')
		switch['session'].tftp_getimage()
		logger.debug('Installing software...')
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


	def _tftp_replace(self,switch,time):
		logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		if 'new IPaddress' in switch.keys():
			switch['session'].tftp_replaceconf(timeout=time)
			logger.info('Startup-config successfully transferred')
		else:
			logger.getLogger('CAP.' + switch['hostname'])
			logger.warning('Unable to find a configuration file on TFTP server!')
		del switch['session']


	def _tftp_startup(self, switch):
		logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		# try get null-serial#.conf config
		switch['session'].blastvlan()
		found_config = False
		if not found_config and 'serial' in switch.keys():
			for serial in switch['serial']:
				logger.info('Using config that matches the serial number!')
				dir_prefix = '/autoprov'
				filename = '/' + serial + '-confg'
				found_config = self._startupcfg(switch=switch,remotefilename=dir_prefix + filename)
				if found_config:
					switch['serial'] = [serial]
					break
		if not found_config and 'new name' in switch.keys():
			logger.info('No config matches serial number. Searching for one based on CDP neighbor\'s port description')
			filename = '/' + switch['new name'] + '-confg'
			found_config = self._startupcfg(switch=switch,remotefilename=filename)
		if not found_config:
			logger.warning('Unable to find target config file. Resorting to model default!')
			dir_prefix = '/autoprov'
			filename = '/cap' + switch['model'] + '-confg'
			found_config = self._startupcfg(switch=switch,remotefilename=filename)
		if not found_config:
			raise Exception('not able to find any config files for switch ' + switch['IPaddress'])


	def _startupcfg(self,switch,remotefilename,outputfile='./output/temp_config'):
		logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		success = Helper(self.tftp).tftp_getconf(remotefilename=remotefilename, outputfile=outputfile)
		if success:
				with open(outputfile,'r+b') as f:
					log = mmap.mmap(f.fileno(), 0)
				results = re.findall(r'\s(ip\saddress\s((?:\d{1,3}\.){3}\d{1,3})\s(?:\d{1,3}\.){3}\d{1,3})', log)
				switch['new IPaddress'] = map(lambda (g0,g1): g1, results)
				log.close()
				logger.debug('new ip address information: ' + str(results))
				switch['session'].tftp_getstartup(remotefilename)
		return success


	def _gen_rsa(self,switch,logfilename):
		logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		logger.debug('Attempting to setup RSA keys')
		if self.pver3:
			s = pexpect.spawnu('telnet ' + switch['IPaddress'])
		else:
			s = pexpect.spawn('telnet ' + switch['IPaddress'])
		s.timeout = self.telnettimeout
		s.logfile = open(logfilename, "w")
		logger.debug('Opening telnet session...')
		s.expect('Username: ')
		s.sendline(self.suser)
		s.expect('Password: ')
		s.sendline(self.spasswd)
		s.expect('>')
		s.sendline('enable')
		s.expect('Password: ')
		s.sendline(self.senable)
		s.expect('#')
		logger.debug('Setting up environment...')
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
			logger.debug('Erasing all existing keys...')
			s.sendline('crypto key zeroize rsa')
			s.expect(']: ')
			s.sendline('yes')
			s.expect('#')
		if not 'rsa' in switch.keys():
			logger.debug('Generating RSA key pair locally...')
			self._genrsa(switch)
		# `selfsigned` is the name we're giving to the pair, for now
		s.sendline('crypto key import rsa selfsigned pem terminal ' + switch['rsa']['password'])
		s.expect('itself.')
		logger.debug('Transferring public RSA key...')
		for line in switch['rsa']['public']:
			s.sendline(line)
		s.sendline('quit')
		s.expect('itself.')
		logger.debug('Transferring private RSA key...')
		for line in switch['rsa']['private']:
			s.sendline(line)
		s.sendline('quit')
		s.expect('#')
		successful = True if 'Key pair import succeeded' in s.before else False
		s.sendline('ip ssh version 2')
		s.expect('#')
		s.sendline('exit')
		s.expect('#')
		s.sendline('write mem')
		s.expect('#')
		s.logfile.close()
		s.close()
		if not successful:
			logger.debug(s.before)
			raise Exception('RSA key was not imported successfully...')
		else:
			logger.info('RSA key was imported successfully!')


	def _wait(self, target, cycle=5, timeout=300):
		"""
		Wait until the target is back online.
		Sends a periodic ping to the target.

		Keyword arguments:
		target -- device hostname or IP address
		cycle -- how long to wait between each ping, in seconds. Minimum is (and defaults to) 5
		timeout -- total wait time, in seconds, before returning to the caller. Minimum is 30, defaults to 300
		"""
		# TODO: Allow simultaneous ping attempts
		if type(target) is list:
			target = target[0]
		self.logger.info('Pinging %s', target)
		attempts = 1
		cycle = cycle if cycle > 5 else 5
		timeout = timeout if timeout >= 30 else 300
		retries = timeout / cycle
		while timeout > 0:
			if self.debug:
				self.logger.debug('%s: sending ping %i of %i', target, attempts, retries)
			#	sys.stdout.write("\rSending ping " + str(attempts) + " of " + str(retries))
			#	sys.stdout.flush()
			if self.ping(target):
				self.logger.info('%s responded to ping!', target)
				return True
			sleep(cycle - 1) # Timeout is 1, so remove that from the overall wait
			timeout -= cycle
			attempts += 1
		self.warning('%s did not respond to pings!', target)
		return False
	
	getoids = {
		'C4506': lambda hostname, community: [snmp_get(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11.1').value],
		'C4506R': lambda hostname, community: [snmp_get(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11.1').value],
		'C4507': lambda hostname, community: [snmp_get(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11.1').value],
		'C3850': lambda hostname, community: [x.value for x in snmp_walk(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11') if x.oid_index in ['1', '1000', '2000', '3000', '4000', '5000', '6000', '7000', '8000', '9000']],
		'C3750X': lambda hostname, community: [x.value for x in snmp_walk(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11') if x.oid_index in ['1001', '2001', '3001', '4001', '5001', '6001', '7001', '8001', '9001']],
		'C3750V2': lambda hostname, community: [x.value for x in snmp_walk(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11') if x.oid_index in ['1001', '2001', '3001', '4001', '5001', '6001', '7001', '8001', '9001']],
		'C3750': lambda hostname, community: [x.value for x in snmp_walk(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11') if x.oid_index in ['1001', '2001', '3001', '4001', '5001', '6001', '7001', '8001', '9001']],
		'C3560': lambda hostname, community: [snmp_get(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value],
		'C3560X': lambda hostname, community: [snmp_get(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value],
		'C3560CG': lambda hostname, community: [snmp_get(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value],
		'C3560CX': lambda hostname, community: [snmp_get(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value],
		'C2940': lambda hostname, community: [snmp_get(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value],    
		'C2960': lambda hostname, community: [snmp_get(hostname=hostname, version=2, community=community, oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value]
	}


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
		'''returns true or false depending on whether tftpget was successfull or not'''
		try:
			self.client.download(filename=str(remotefilename),output=outputfile)
			return True
		except tftpy.TftpShared.TftpException: # as t:
			#if 'File not found' in t.message:
				#pass	
			return False


class CapTest(CiscoAutoProvision):

	def editswitchlist(self):
		for index, switch in enumerate(self.switches):
			print(str(index) + ': ' + switch['IPaddress'] + '\t'  + switch['hostname'])
			r = -69
		while r not in [''] + map(lambda (x,y): str(x), enumerate(self.switches)):
			r = raw_input('Enter switch number to pop. leave empty to stop editing.')
		if r and r.isdigit():
			print(self.switches[int(r)]['IPaddress'] + ' was removed')
			self.switches.pop(int(r))


	def get_information(self):
		to_pop = []
		for switch in self.switches:
			try:
				self.logger.debug('IP for %s:\t%s', switch['hostname'], switch['IPaddress'])
				try:
					self._get_model(switch)
					self._get_serial(switch)
				except EasySNMPTimeoutError:
					self.logger.debug('%s timed out', switch['IPaddress'], exc_info=True)
					to_pop.append(switch)
					continue
				try:
					self._get_new_name(switch)
				except EasySNMPTimeoutError:
					print('could not access neighbor switch')
			except Exception:
				logging.error('Failed to retrieve information from %s', switch['IPaddress'], exc_info=True)
		for s in to_pop:
			self.logger.info('Removing %s from switch list', switch['IPaddress'])
			self.switches.pop(self.switches.index(s))


	def upgradeall(self):
		for switch in self.switches:
			self.autoupgrade(switch)


	def get_model(self):
		for switch in self.switches:
			try:
				self.logger.debug('Fetching model for %s', switch['IPaddress'])
				self._get_model(switch)
			except Exception as e:
				self.logger.warning('%s timed out. (%s)', switch['IPaddress'], e)


	def get_new_name(self):
		for switch in self.switches:
			try:
				self._get_new_name(switch)
			except:
				self.logger.warning('Could not get new name for %s', switch['IPaddress'], exc_info=True)


	def get_serial(self):
		for switch in self.switches:
			try:
				switch['serial'] = self.getoids[switch['model']](switch['IPaddress'],self.community)
				self.logger.debug('Serial no. for %s is %s', switch['IPaddress'], switch['serial'])
			except Exception:
				self.logger.error('Failed to get serial for %s', switch['IPaddress'], exc_info=True)


	def ssh_opensession(self):
		for switch in self.switches:
			try:
				self._ssh_opensession(switch)
			except Exception as e:
				self.logger.warning('Failed to open SSH session for %s!', switch['IPaddress'])
				self.logger.error('%s', e, exc_info=True)


	def prepupgrade(self):
		for switch in self.switches:
			if switch['IPaddress'] in self.upgrades:
				try:
					self._prepupgrade(switch)
				except Exception as e:
					self.logger.warning('Failed to upgrade %s!', switch['IPaddress'])
					self.logger.error('%s', e, exc_info=True)


	def tftp_replace(self):
		for switch in self.switches:
			if switch['IPaddress'] not in self.upgrades:
				try:
					self._tftp_replace(switch,time=17)
				except Exception as e:
					self.logger.warning('Could not transfer config file for %s!', switch['IPaddress'])
					self.logger.error('%s', e, exc_info=True)


	def tftp_startup(self):
		'''trys to pull a configuration from the given tftp server. the tftp_startup will first
		try and get a config based on the serial number in a serialnum-conf format in the tftpboot/autoprov/ folder
		if that fails then it checks in the base /tftpboot/ folder for a config that is the same as the feedport description 
		and in the event that fails it will look in the /tftpboot/ folder for a model specific base config. 
		 '''
		for switch in self.switches:
				try:
					self._tftp_startup(switch)
				except Exception as e:
					self.logger.error('%s: %s', switch['IPaddress'], e, exc_info=True)


	def reboot_save(self):
		for switch in self.switches:
			try:
				switch['session'].sendreload('no')
			except Exception as e:
				self.logger.warning('%s: %s', switch['IPaddress'], e, exc_info=True)


	def generate_rsa(self):
		for switch in self.switches:
			try:
				logfilename = os.path.abspath(os.path.join(self.output_dir, switch['IPaddress'] + 'log.txt'))
				self._gen_rsa(switch,logfilename=logfilename)
			except Exception as e:
				self.logger.error('%s: %s', switch['IPaddress'], e)
				# print(e)
				if self.debug:
					with open(logfilename, "r") as f:
						print(f.read())
