from __future__ import print_function
from easysnmp import snmp_walk, snmp_get, EasySNMPTimeoutError
from socket import gethostbyaddr  #, gethostbyname
import logging
from time import localtime, strftime, sleep
import pexpect
import requests
from pprint import pformat
import sys
import json
import os
import re
import mmap
import tftpy
from multiprocessing import Process, Pool, Manager
import subprocess
import tempfile
import string
import random
import ciscoupgrade as cup
import sqlite3 as sql


try:    # Python 3 compatibility
	input = raw_input
	range = xrange
	import copy_reg
	import types
	def _reduce_method(m):  # Allows instances to be pickled/serialized.
		if m.im_self is None:  # Note that this is not necessary in Python 3
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
		'database' : '/srv/autoprovision',
		'debug':'1',
		'debug print':'0',
		'lockfile folder':'./cfg/',
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
		self._msg = Manager().Queue()


	def __getstate__(self):
		# When the instance object is being serialized, this method is called.
		# Since the logging library is not multiprocessing.Pool-friendly, it
		# causes the Pool to be terminated immediately. While we may consider
		# spawning processes instead of using pools in the future, it still gives
		# a good example of how to exclude certain values/properties in a "hacky"
		# kind of way. Here we're creating a dictionary (which is serializable)
		# and removing the saved logger from it. This allows Pool to use our
		# instance and move along.
		d = dict(self.__dict__)
		del d['logger']
		return d


	def __setstate__(self, d):
		self.__dict__.update(d)
		

	def _setuplogger(self):
		self.loglevel = logging.DEBUG if self.debug else logging.INFO
		# http://stackoverflow.com/a/9321890/1993468
		logging.basicConfig(
			level=self.loglevel,
			filename=os.path.join(os.path.abspath(self.output_dir), self.logfile),
			format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
			datefmt='%m-%d %H:%M:%S',
			filemode='a')
		formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s', datefmt='%m-%d %H:%M:%S')
		fh = logging.FileHandler(os.path.join(os.path.abspath(self.output_dir), self.logfile))
		fh.setLevel(self.loglevel)
		fh.setFormatter(formatter)
		if self.debug_print:
			formatter = logging.Formatter(
				'%(name)-12s: %(levelname)-8s %(message)s')			
			console = logging.StreamHandler()
			console.setLevel(self.loglevel)
			console.setFormatter(formatter)
			logging.getLogger('').addHandler(console)
			# self.logger.addHandler(console)
		self.logger = logging.getLogger('CAP')
		self.logger.setLevel(self.loglevel)
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
		try:
			if int(data['debug']) <= 1  and int(data['debug']) >= 0:
				self.debug = int(data['debug'])
			else:
				self.debug = 0
				# raise Exception('\'debug\' is not a valid value!')
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
			if data['database']:
				self.database = data['database']
			if data['default rwcommunity']:
				self.community = data['default rwcommunity']
			if data['lockfile folder']:
				self._lockdir = data['lockfile folder']
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
				data['telnet timeout'] = 30
				# raise Exception('telnet timeout must be greater than 30 seconds')
			else:
				self.telnettimeout = int(data['telnet timeout'])
		except Exception as e:
			sys.exit("An error occurred while parsing the config file: " + str(e))

	
	def search(self,target='http://localhost',index='autoprovisioning',time_mins=5,port=9200): #,authenticate=False 
		self.switches = []
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
								'gte': 'now-' + str(time_mins) + 'm',
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
				self.logger.error(log['_source']['host'], exc_info=True)
				if log['_source']['host'] not in list(errs):
					errs.add(log['_source']['host'])
		temp_switches = [dict(t) for t in set([tuple(d.items()) for d in results])]
		sl = {}
		for switch in temp_switches:
			ip = switch['IPaddress'].encode()
			switch[ip] = ip
			sl[ip] = {}
			sl[ip]['IPaddress'] = switch['IPaddress']
			sl[ip].setdefault('hostname','')
			sl[ip].setdefault('neighbors',{})
			if switch['nei_raw'].encode().split():
				sl[ip]['neighbors'].setdefault(switch['nei_raw'].encode().split()[0],[])
		for switch in temp_switches:
			try:
				ip = switch['IPaddress'].encode()
				hostname = gethostbyaddr(ip)[0]
				sl[ip]['hostname'] = hostname
				neighbor = switch['nei_raw'].encode().split()
				if neighbor:
					n = neighbor.pop(0)
					sl[ip]['neighbors'].setdefault(n,[])
					for nei in neighbor:
						sl[ip]['neighbors'][n].append(nei)
				del switch['nei_raw']
			except:
				self.logger.error(switch, exc_info=True)
				self.logger.debug('could not find hostname for ' + switch['IPaddress'])
		for k,v in sl.iteritems():
			self.switches.append(v)
		self.logger.debug(pformat(self.switches))


	def run(self):
		'''
		Full provisioning process
		'''
		self.search()
		if not self.switches:
			self.logger.info('No switches require provisioning.')
			return
		# if self.switches:
		self.logger.info('Starting Autoprovision process')
		# logger = multiprocessing.log_to_stderr()
		# logger.setLevel(self.loglevel)
		# logger.info('Initializing pool')
		p = Pool()
		# self._remaining = []
		for switch in self.switches:
			# self._lock(switch)
			self.logger.debug('Adding ' + switch['hostname'] + ' to pool.')
			progress = p.apply_async(self.autoupgrade, (switch,), callback=self._unlock)#, callback=self._decr)  # Python 3 has an error_callback. Nice...
		p.close()
		while not progress.ready() or not self._msg.empty():
			if not self._msg.empty():
				log = self._msg.get()
				if type(log[-1]) is dict:  # Contains `exc_info=True`
					self.logger.log(*log[0], **log[1])
				else:
					self.logger.log(*log)
		p.join()
		# Extra safety net, just in case an error kills the pool prematurely.
		# The pool closed on me early last night and finished the script, however
		# a worker was still TFTP'ing (and printing out) in the background
		while not self._msg.empty():
			if not self._msg.empty():
				log = self._msg.get()
				if type(log[-1]) is dict:  # Contains `exc_info=True`
					self.logger.log(*log[0], **log[1])
				else:
					self.logger.log(*log)
		self.logger.info('Provisioning complete. See log for details.')
		# self._unlock()


	def autoupgrade(self, switch):
		try:
			# logger = logging.getLogger('CAP.' + switch['hostname'].split('.')[0])
			# logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
			# self.logger.info('Beginning provisioning process')
			# self.logger.info('[%s] Beginning provisioning process', switch['IPaddress'])
			# Jul 14, 2016: C3850 averages ~8.5mins to reboot (not upgrading)
			# Since spanning-tree must also discover VLAN routes, ~2 minutes
			# should be added for it to finish mapping the network
			timeout = 600
			self._msg.put((logging.INFO, '[%s] Beginning provisioning process', switch['IPaddress']))
			try:
				self._get_model(switch)
				self._get_serial(switch)
			except EasySNMPTimeoutError:
				raise Exception('Could not retrieve model and/or serial!')
			# Had to move the lock into here. We want the serial to be the  table's
			# primary key in the event the device appears with a different IP
			# We don't want to catch the exception; we want to exit ASAP
			# sql.IntegrityError, 
			self._lock(switch)
			try:
				self._get_new_name(switch)
			except EasySNMPTimeoutError:
				# logger.debug('Could not access neighbor switch')
				# self.logger.debug('[%s] Could not access neighbor switch', switch['IPaddress'])
				self._msg.put((logging.DEBUG, '[%s] Could not access neighbor switch', switch['IPaddress']))
			# Generate RSA keys. Since we're replacing the startup config, and
			# RSA keys require a "write mem" to be saved, it's okay to save the
			# running config to flash
			if not switch['crypto']:
				# raise Exception('Not yet implemented!')
				logfilename = os.path.abspath(os.path.join(self.output_dir, switch['hostname'] + '-to_k9-log.txt'))
				self._upgradefirst(switch,logfilename)
			logfilename = os.path.abspath(os.path.join(self.output_dir, switch['hostname'] + 'log.txt'))
			self._send_rsa(switch,logfilename=logfilename)
			# open ssh session
			self._ssh_opensession(switch)
			if switch['IPaddress'] in self.upgrades:
				# In order for the reboot to upgrade the device,
				# the running configuration must be saved. Therefore
				# the running-config should be overwritten with the 
				# to-be/startup-config, set the target boot image,
				# then save changes after applying the reboot command
				self._prepupgrade(switch)
				# IOS-XE (3750X?, 3850, 4506) take a long time to upgrade
				timeout = 1200
			self._tftp_startup(switch)
			# self._tftp_replace(switch,time=15)
			switch['session'].sendreload('no')
			self._msg.put((logging.INFO, '[%s] Reload command sent. Change feed on [%s] to trunk mode NOW!', switch['IPaddress'], switch['neighbors'].keys()[0]))
			if self._wait(switch['new IPaddress'], timeout=timeout):
				self._msg.put((logging.INFO, '[%s] Configuration successfully reloaded and is now reachable!', switch['new IPaddress']))
				switch['success'] = True
			else:
				self._msg.put((logging.CRITICAL, '[%s] Cannot reach via IP after loading startup-config in memory!', switch['new IPaddress']))
				switch['success'] = False
			#continual ping
		except sql.IntegrityError:
			self._msg.put((logging.DEBUG, '[%s] Already being provisioned by another process', switch['IPaddress']))
		except Exception as e:
			# self.logger.error('Error occurred: %s', e, exc_info=True)
			# self.logger.error('[%s] Error occurred: %s', switch['IPaddress'], e, exc_info=True)
			self._msg.put(((logging.ERROR, '[%s] Error occurred: %s', switch['IPaddress'], e), dict(exc_info=True)))
			switch['success'] = False
		finally:
			self._msg.put((logging.DEBUG, '[%s] Removing from queue', switch['IPaddress']))
			return switch


	def _get_model(self,switch):
		# logger = logging.getLogger('CAP.' + switch['hostname'].split('.')[0])
		# logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		
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
		# self.logger.debug('IOS image: %s', softimage)
		# self.logger.debug('[%s] IOS image: %s', switch['IPaddress'], softimage)
		self._msg.put((logging.DEBUG, '[%s] IOS image: %s', switch['IPaddress'], softimage))
		if model not in self.firmwares.keys():
			raise Exception('model' + model + 'not found in firmware list!')
			#TODO: make a way to add firmware
		elif type(softimage) is unicode and softimage in self.firmwares[model].lower() and (self._k9(softimage) and not '296' in model):
			switch['crypto'] = True
			switch['model'] = model
			switch['bin'] = self.firmwares[model]
			switch['softimage'] = softimage
			# self.logger.debug('[%s] No upgrade needed. Target IOS: %s', switch['IPaddress'], switch['bin'])
			self._msg.put((logging.DEBUG, '[%s] No upgrade needed. Target IOS: %s', switch['IPaddress'], switch['bin']))
		elif type(softimage) is list and all(x in self.firmwares[model].lower() for x in softimage) and (self._k9(softimage) and not '296' in model):
			switch['crypto'] = True
			switch['model'] = model
			switch['bin'] = self.firmwares[model]
			switch['softimage'] = softimage
			# logger.debug('No upgrade needed. Target IOS: %s', switch['bin'])
			# self.logger.debug('[%s] No upgrade needed. Target IOS: %s', switch['IPaddress'], switch['bin'])
			self._msg.put((logging.DEBUG, '[%s] No upgrade needed. Target IOS: %s', switch['IPaddress'], switch['bin']))
		else:
			switch['crypto'] = self._k9(softimage)
			switch['model'] = model
			switch['bin'] = self.firmwares[model]
			switch['softimage'] = softimage
			self.upgrades.append(switch['IPaddress'])
			# self.logger.debug('Upgrade needed. Target IOS: %s', switch['bin'])
			# self.logger.debug('[%s] Upgrade needed. Target IOS: %s', switch['IPaddress'], switch['bin'])
			self._msg.put((logging.DEBUG, '[%s] Upgrade needed. Target IOS: %s', switch['IPaddress'], switch['bin']))


	def _k9(self, image):
		'''
		Verify that the supplied IOS image supports Cryptography
		'''
		if type(image) is list:
			return any(x for x in image if 'k9' in x.lower())
		else:
			return 'k9' in image.lower()


	def _upgradefirst(self,switch,logfilename):
		self._msg.put((logging.DEBUG, '[%s] Attempting to upgrade to K9 binary first', switch['IPaddress']))
		# logger.debug('Opening telnet session...')
		# self.logger.debug('[%s] Opening telnet session...', switch['IPaddress'])
		self._msg.put((logging.DEBUG, '[%s] K9: Opening telnet session...', switch['IPaddress']))
		d = dict(host=switch['IPaddress'], tftpserver=self.tftp,
				username=self.suser, password=self.spasswd, 
				logfilename=logfilename, pver3=self.pver3,
				binary_file=switch['bin'], timeout=self.telnettimeout,
				enable_password=self.senable, debug=self.debug,
				)
		sess = None
		if not self.ping(switch['IPaddress']):
			raise Exception('host not reachable')
		if switch['model'].startswith('C38'):
			sess = cup.ciu3850(**d)
		elif switch['model'].startswith('C45'):
			sess = cup.ciu4500(**d)
		else:
			# logger.debug('Using default upgrade profile')
			# self.logger.debug('[%s] Using default upgrade profile', switch['IPaddress'])
			self._msg.put((logging.DEBUG, '[%s] K9: Using default upgrade profile', switch['IPaddress']))
			sess = cup.ciscoUpgrade(**d)
		# I won't try to catch errors. Let the autoupgrade method handle it
		self._msg.put((logging.DEBUG, '[%s] K9: Setting up TFTP...', switch['IPaddress']))
		sess.tftp_setup()
		self._msg.put((logging.DEBUG, '[%s] K9: Clearing out old software...', switch['IPaddress']))
		sess.cleansoftware()
		self._msg.put((logging.DEBUG, '[%s] K9: Fetching and verifying image...', switch['IPaddress']))
		sess.tftp_getimage()
		# self._msg.put((logging.DEBUG, '[%s] K9: Verifying image...', switch['IPaddress']))
		# sess.verifyimage()
		self._msg.put((logging.DEBUG, '[%s] K9: Installing image...', switch['IPaddress']))
		sess.softwareinstall()
		self._msg.put((logging.DEBUG, '[%s] K9: Setting boot image...', switch['IPaddress']))
		sess.writemem()
		self._msg.put((logging.DEBUG, '[%s] K9: Erasing startup-config...', switch['IPaddress']))
		sess.erasestartup()
		self._msg.put((logging.DEBUG, '[%s] K9: Reloading switch!', switch['IPaddress']))
		sess.sendreload('no')
		# self._msg.put((logging.DEBUG, '[%s] K9: Reload (probably) sent...', switch['IPaddress']))
		self._msg.put((logging.INFO, '[%s] K9: Rebooting switch; waiting for graceful shutdown before sending pings', switch['IPaddress']))
		sleep(8)
		if not self._wait(switch['IPaddress'], timeout=1200):
			raise Exception('Switch did not come back online after upgrading it to a crypto version!')
		self.upgrades.remove(switch['IPaddress'])
		self._msg.put((logging.DEBUG, '[%s] K9: Validating upgrade...'))
		try:
			self._get_model(switch)
		except EasySNMPTimeoutError:
			sleep(8) # Because, ya know, 8 is the optimal number, right?
			self._get_model(switch)
		if not self._k9(switch['softimage']):
			raise Exception('Switch did not upgrade properly to crypto image!')
		else:
			self._msg.put((logging.DEBUG, '[%s] K9: Upgrade verified. Resuming normal provisioning procedure.', switch['IPaddress']))


	def _get_new_name(self,switch):
		# logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
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
					# logger.debug('New name: %s', newname)
					# self.logger.debug('[%s] New name: %s', switch['IPaddress'], newname)
					switch['new name'] = newname
					self._msg.put((logging.INFO, '[%s] New hostname found from neighrbor\'s port description. To-be: %s', switch['IPaddress'], switch['new name']))
					pass # TODO
			except IndexError:
				# logger.warning('Target hostname was not found on a neighboring switch for %s!', switch['IPaddress'])
				# self.logger.warning('[%s] Target hostname was not found on a neighboring switch!', switch['IPaddress'])
				self._msg.put((logging.WARNING, '[%s] Target hostname was not found on a neighboring switch!', switch['IPaddress']))


	def _get_serial(self,switch):
		# logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		serialnum = self.getoids[switch['model']](switch['IPaddress'],self.community)
		if serialnum:
			switch['serial'] = serialnum
			# logger.info('Serial number: %s', serialnum)
			# self.logger.info('[%s] Serial number: %s', switch['IPaddress'], serialnum)
			self._msg.put((logging.INFO, '[%s] Serial number: %s', switch['IPaddress'], serialnum))


	def _ssh_opensession(self,switch):
		# logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		# logger.debug('Preparing SSH session')
		# self.logger.debug('[%s] Preparing SSH session', switch['IPaddress'])
		d = dict(host=switch['IPaddress'], tftpserver=self.tftp,
				binary_file=switch['bin'],
				username=self.suser, password=self.spasswd,
				enable_password=self.senable, debug=self.debug)
		self._msg.put((logging.DEBUG, '[%s] Preparing SSH session', switch['IPaddress']))
		if not self.ping(switch['IPaddress']):
			raise Exception('host not reachable')
		if switch['model'].startswith('C38'):
			switch['session'] = cup.c38XXUpgrade(**d)
		elif switch['model'].startswith('C45'):
			switch['session'] = cup.c45xxUpgrade(**d)
		else:
			# logger.debug('Using default upgrade profile')
			# self.logger.debug('[%s] Using default upgrade profile', switch['IPaddress'])
			self._msg.put((logging.DEBUG, '[%s] Using default upgrade profile', switch['IPaddress']))
			switch['session'] = cup.ciscoUpgrade(**d)	


	def _prepupgrade(self,switch):
		# logger = logging.getLogger('CAP.' + switch['hostname'].split('.')[0])
		# logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		# logger.info('Preparing upgrade process...')
		# self.logger.info('[%s] Preparing upgrade process...', switch['IPaddress'])
		self._msg.put((logging.INFO, '[%s] Preparing upgrade process...', switch['IPaddress']))
		switch['session'].tftp_setup()
		# logger.debug('Clearing out old images...')
		# self.logger.debug('[%s] Clearing out old images...', switch['IPaddress'])
		self._msg.put((logging.DEBUG, '[%s] Clearing out old images...', switch['IPaddress']))
		switch['session'].cleansoftware()
		# logger.debug('Retrieving IOS image...')
		# self.logger.debug('[%s] Retrieving IOS image...', switch['IPaddress'])
		self._msg.put((logging.DEBUG, '[%s] Retrieving IOS image...', switch['IPaddress']))
		switch['session'].tftp_getimage()
		# logger.debug('Installing software...')
		# self.logger.debug('[%s] Installing software...', switch['IPaddress'])
		self._msg.put((logging.DEBUG, '[%s] Installing software...', switch['IPaddress']))
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
		# logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		if 'new IPaddress' in switch.keys():
			switch['session'].tftp_replaceconf(timeout=time)
			# logger.info('Startup-config successfully transferred')
			# self.logger.info('[%s] Startup-config successfully transferred', switch['IPaddress'])
			self._msg.put((logging.INFO, '[%s] Startup-config successfully transferred', switch['IPaddress']))
		else:
			# logger.warning('Unable to find a configuration file on TFTP server!')
			# self.logger.warning('[%s] Unable to find a configuration file on TFTP server!', switch['IPaddress'])
			self._msg.put((logging.WARNING, '[%s] Unable to find a configuration file on TFTP server!', switch['IPaddress']))
		del switch['session']


	def _tftp_startup(self, switch):
		# logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		# try get null-serial#.conf config
		switch['session'].blastvlan()
		found_config = False
		if not found_config and 'serial' in switch.keys():
			for serial in switch['serial']:
				# logger.info('Using config that matches the serial number!')
				# self.logger.info('[%s] Using config that matches the serial number!', switch['IPaddress'])
				dir_prefix = '/autoprov'
				filename = '/' + serial + '-confg'
				found_config = self._startupcfg(switch=switch,remotefilename=dir_prefix + filename)
				if found_config:
					self._msg.put((logging.INFO, '[%s] Using config that matches the serial number!', switch['IPaddress']))
					# switch['serial'] = [serial]
					break
		if not found_config and 'new name' in switch.keys():
			# logger.info('No config matches serial number. Searching for one based on CDP neighbor\'s port description')
			# self.logger.info('[%s] No config matches serial number. Searching for one based on CDP neighbor\'s port description', switch['IPaddress'])
			self._msg.put((logging.INFO, '[%s] No config matches serial number. Searching for one based on CDP neighbor\'s port description', switch['IPaddress']))
			filename = '/' + switch['new name'].lower() + '-confg'
			found_config = self._startupcfg(switch=switch,remotefilename=filename)
			if found_config:
				self._msg.put((logging.INFO, '[%s] Found a config file based on hostname. Will use "%s"', switch['IPaddress'], filename))		
		if not found_config:
			# logger.warning('Unable to find target config file. Resorting to model default!')
			# self.logger.warning('[%s] Unable to find target config file. Resorting to model default!', switch['IPaddress'])
			self._msg.put((logging.WARNING, '[%s] Unable to find target config file. Resorting to model default!', switch['IPaddress']))
			dir_prefix = '/autoprov'
			filename = '/cap' + switch['model'].lower() + '-confg'
			found_config = self._startupcfg(switch=switch,remotefilename=filename)
		if not found_config:
			raise Exception('not able to find any config files for switch ' + switch['IPaddress'])


	def _startupcfg(self,switch,remotefilename,outputfile='./output/temp_config'):
		# logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		success = Helper(self.tftp).tftp_getconf(remotefilename=remotefilename, outputfile=outputfile)
		if success:
			with open(outputfile,'r+b') as f:
				log = mmap.mmap(f.fileno(), 0)
			results = re.findall(r'\s(ip\saddress\s((?:\d{1,3}\.){3}\d{1,3})\s(?:\d{1,3}\.){3}\d{1,3})', log)
			switch['new IPaddress'] = map(lambda (g0,g1): g1, results)
			log.close()
			# logger.debug('new ip address information: ' + str(results))
			# self.logger.debug('[%s] New ip address: %s', switch['IPaddress'], switch['new IPaddress'])
			self._msg.put((logging.DEBUG, '[%s] New ip address: %s', switch['IPaddress'], switch['new IPaddress']))
			switch['session'].tftp_getstartup(remotefilename)
		return success


	def _send_rsa(self,switch,logfilename):
		# logger = logging.getLogger('CAP.(' + switch['IPaddress'] + ')')
		# self.logger.debug('[%s] Attempting to setup RSA keys', switch['IPaddress'])
		self._msg.put((logging.DEBUG, '[%s] Attempting to setup RSA keys', switch['IPaddress']))
		if self.pver3:
			s = pexpect.spawnu('telnet ' + switch['IPaddress'])
		else:
			s = pexpect.spawn('telnet ' + switch['IPaddress'])
		s.timeout = self.telnettimeout
		s.logfile = open(logfilename, 'w')
		# logger.debug('Opening telnet session...')
		# self.logger.debug('[%s] Opening telnet session...', switch['IPaddress'])
		self._msg.put((logging.DEBUG, '[%s] Opening telnet session...', switch['IPaddress']))
		s.expect('Username: ')
		s.sendline(self.suser)
		s.expect('Password: ')
		s.sendline(self.spasswd)
		s.expect('>')
		s.sendline('enable')
		s.expect('Password: ')
		s.sendline(self.senable)
		s.expect('#')
		# logger.debug('Setting up environment...')
		# self.logger.debug('[%s] Setting up environment...', switch['IP address'])
		self._msg.put((logging.DEBUG, '[%s] Setting up environment...', switch['IPaddress']))
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
			# logger.debug('Erasing all existing keys...')
			# self.logger.debug('[%s] Erasing all existing keys...', switch['IPaddress'])
			self._msg.put((logging.DEBUG, '[%s] Erasing all existing keys...', switch['IPaddress']))
			s.sendline('crypto key zeroize rsa')
			s.expect('\]: ')
			s.sendline('yes')
			s.expect('#')
		if not 'rsa' in switch.keys():
			# logger.debug('Generating RSA key pair locally...')
			# self.logger.debug('[%s] Generating RSA key pair locally...', switch['IPaddress'])
			self._msg.put((logging.DEBUG, '[%s] Generating RSA key pair locally...', switch['IPaddress']))
			self._genrsa(switch)
		# `selfsigned` is the name we're giving to the pair, for now
		s.sendline('crypto key import rsa selfsigned pem terminal ' + switch['rsa']['password'])
		s.expect('itself.')
		# logger.debug('Transferring public RSA key...')
		# self.logger.debug('[%s] Transferring public RSA key...', switch['IPaddress'])
		self._msg.put((logging.DEBUG, '[%s] Transferring public RSA key...', switch['IPaddress']))
		for line in switch['rsa']['public']:
			s.sendline(line)
		s.sendline('quit')
		s.expect('itself.')
		# logger.debug('Transferring private RSA key...')
		# self.logger.debug('[%s] Transferring private RSA key...', switch['IPaddress'])
		self._msg.put((logging.DEBUG, '[%s] Transferring private RSA key...', switch['IPaddress']))
		for line in switch['rsa']['private']:
			s.sendline(line)
		s.sendline('quit')
		s.expect('#')
		successful = True if 'Key pair import succeeded' in s.before else False
		s.sendline('ip ssh version 2')
		s.expect('#')
		s.sendline('exit')
		s.expect('#')
		self._msg.put((logging.DEBUG, '[%s] Saving RSA keys (and running-config)...', switch['IPaddress']))
		s.sendline('write mem')
		s.send('')
		s.expect('#')
		s.logfile.close()
		s.close()
		if not successful:
			# logger.debug(s.before)
			# self.logger.debug('[%s] :: %s', switch['IPaddress'], s.before)
			self._msg.put((logging.DEBUG, '[%s] :: %s', switch['IPaddress'], s.before))
			raise Exception('RSA key was not imported successfully...')
		else:
			# logger.info('RSA key was imported successfully!')
			# self.logger.info('[%s] RSA key was imported successfully!', switch['IPaddress'])
			self._msg.put((logging.INFO, '[%s] RSA key was imported successfully!', switch['IPaddress']))


	def _lock(self, switch):
		while True:
			try:
				device = (switch['hostname'], switch['IPaddress'], switch['model'], switch['serial'][0], strftime('%a %b %d %Y %H:%M:%S', localtime()))
				db  = os.path.join(self.database, 'lockfile.db')
				conn = sql.connect(db)
				c = conn.cursor()
				# Initialize tables, if not already existant
				# When tables are created, the DB immediately commits them.
				# Another process may, however, lock the table between CREATEs
				c.execute('''CREATE TABLE IF NOT EXISTS devices
				                (name text, ip text, model text, serial text primary key, date text)''')
				c.execute('''CREATE TABLE IF NOT EXISTS locked
				                (name text, ip text, model text, serial text primary key, date text)''')
				# Lock device first; this will abort the provisioning process
				# if another one is already working on it
				c.execute('INSERT INTO locked VALUES (?,?,?,?,?)', device)
				# Update the date info
				c.execute('INSERT OR REPLACE INTO devices VALUES (?,?,?,?,?)', device)
				conn.commit()
				break
			# Database is currently locked; try again
			except sql.OperationalError as e:
				# Another process has locked the database. Try again
				if 'locked' in str(e).lower():
					pass
				else:
					raise e
			finally:
				conn.close()


	def _unlock(self, switch):
		while True:
			try:
				db  = os.path.join(self.database, 'lockfile.db')
				conn = sql.connect(db)
				c = conn.cursor()
				c.execute('''CREATE TABLE IF NOT EXISTS success
				                (name text, ip text, model text, serial text primary key, date text, notify integer)''')
				c.execute('''CREATE TABLE IF NOT EXISTS failure
				                (name text, ip text, model text, serial text primary key, date text, attempts integer, notify integer)''')
				# Even if it's not in the table for some reason, this won't 
				# raise an error
				c.execute('DELETE FROM locked WHERE serial = ?', (switch['serial'][0]))
				if switch['success']:
					# TODO: Notification of success/failure
					device = (switch['hostname'], switch['IPaddress'], switch['model'], switch['serial'][0], strftime('%a %b %d %Y %H:%M:%S', localtime()), 'FALSE')
					c.execute('INSERT OR REPLACE INTO success VALUES (?,?,?,?,?,?)', device)
				else:
					c.execute('SELECT * FROM failure WHERE serial = ?', (switch['serial'][0]))
					d = c.fetchone()
					if d:
						c.execute('UPDATE failure SET attempts = attempts + 1, date = ? WHERE serial = ?', (strftime('%a %b %d %Y %H:%M:%S', localtime()), switch['serial'][0]))
					else:
						c.execute('INSERT INTO failure VALUES (?,?,?,?,?,?,?)',(switch['hostname'], switch['IPaddress'], switch['model'], switch['serial'][0], strftime('%a %b %d %Y %H:%M:%S', localtime()), 1, 'FALSE'))
				conn.commit()
				conn.close()
				break
			except sql.OperationalError as e:
				if 'locked' in str(e).lower():
					pass
				else:
					raise e
			finally:
				conn.close()

		# pass


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
		# self.logger.info('Pinging %s', target)
		self._msg.put((logging.INFO, 'Pinging %s', target))
		attempts = 1
		cycle = cycle if cycle > 5 else 5
		timeout = timeout if timeout >= 30 else 300
		retries = timeout / cycle
		while timeout > 0:
			if self.debug:
				# self.logger.debug('%s: sending ping %i of %i', target, attempts, retries)
				self._msg.put((logging.DEBUG, '[%s]: Sending ping %i of %i', target, attempts, retries))
			#	sys.stdout.write("\rSending ping " + str(attempts) + " of " + str(retries))
			#	sys.stdout.flush()
			if self.ping(target):
				# self.logger.info('%s responded to ping!', target)
				self._msg.put((logging.INFO, '[%s] Responded to ping!', target))
				return True
			sleep(cycle - 1) # Timeout is 1, so remove that from the overall wait
			timeout -= cycle
			attempts += 1
		# self.logger.warning('%s did not respond to pings!', target)
		self._msg.put((logging.WARNING, '[%s] Timed out!', target))
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

	def run(self):
		'''
		Full provisioning process
		'''
		# self.search()
		# if self.switches:
		self.logger.info('Starting Autoprovision process')
		# logger = multiprocessing.log_to_stderr()
		# logger.setLevel(self.loglevel)
		# logger.info('Initializing pool')
		# p = multiprocessing.Pool(initializer=multiprocessing_logging.install_mp_handler)
		# p = Pool()
		self._remaining = []
		for switch in self.switches:
			self._remaining.append(switch['IPaddress'])
			self.logger.debug('Creating a process for ' + switch['hostname'] + '.')
			p = Process(target=self.autoupgrade, args=(switch,))#, callback=self._decr)  # Python 3 has an error_callback. Nice...
			p.start()
			while p.is_alive() or not self._msg.empty():
				if not self._msg.empty():
					log = self._msg.get()
					if type(log[-1]) is dict:  # Contains `exc_info=True`
						self.logger.log(*log[0], **log[1])
					else:
						self.logger.log(*log)
			p.join()
			self._rem(switch['IPaddress'])
		# Extra safety net, just in case an error kills the pool prematurely.
		# The pool closed on me early last night and finished the script, however
		# a worker was still TFTP'ing (and printing out) in the background
		while not self._msg.empty():
			if not self._msg.empty():
				log = self._msg.get()
				if type(log[-1]) is dict:  # Contains `exc_info=True`
					self.logger.log(*log[0], **log[1])
				else:
					self.logger.log(*log)
		self.logger.info('Provisioning complete. See log for details.')


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
				self.logger.error('Failed to retrieve information from %s', switch['IPaddress'], exc_info=True)
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
				self._send_rsa(switch,logfilename=logfilename)
			except Exception as e:
				self.logger.error('%s: %s', switch['IPaddress'], e)
				# print(e)
				if self.debug:
					with open(logfilename, "r") as f:
						print(f.read())
