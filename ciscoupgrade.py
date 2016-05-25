from __future__ import print_function
import paramiko
import time
import sys
import os
#import multiprocessing
#from easysnmp import snmp_get, snmp_walk


class VerifyException(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)


class ciscoUpgrade:

	def __init__(self, host, model,tftpserver, binary_file, username='default', password='l4y3r2', enable_password=None, debug=True):
		self.host = host
		self.model = model
		self.bin = binary_file
		self.tftpserver = tftpserver
		self.debug = debug
		self.log = ''
		client = paramiko.SSHClient()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())	# I changed the timeout to 60 seconds so we're not waiting too long
		client.connect(self.host, username=username, password=password, timeout=60, allow_agent=False, look_for_keys=False)
		self.shell = client.invoke_shell()
		self.shell.keep_this = client
		if enable_password:
			self._sendrecieve('enable\r','assword:') #enabled status!!!
			self._sendrecieve(enable_password + '\r','#') #
		self._sendrecieve('terminal length 0\r','#')
	
	def _sendrecieve(self,command, expect, verbose=False):
		time.sleep(0.5)
		self.shell.send(command)
		#create recieve buffer
		receive_buffer = ''
		while not expect in receive_buffer:
			if self.shell.recv_ready():
				buf = self.shell.recv(100)
				if self.debug and len(buf) > 0:
					sys.stdout.write(buf)
					sys.stdout.flush()
				receive_buffer += buf
			if ('[confirm]' in receive_buffer):
				time.sleep(0.5)
				self.shell.send('\r')
				receive_buffer = ''
				if 'reload' in command:
					break
			elif ('[yes/no]:' in receive_buffer):
				time.sleep(0.5)
				self.shell.send('yes\r')
				receive_buffer = ''
		time.sleep(0.1)
		self.log += receive_buffer + '\n'
		if verbose:
			return receive_buffer

	def ping(self,host):
		ping_command = "ping -W1 -c 1 " + host + " > /dev/null 2>&1 "
		response = os.system(ping_command)
		#Note:response is 1 for fail; 0 for success;
		return not response


	def tftp_setup(self):
		#speed up the TFTP transfer
		self._sendrecieve('config t\r', '#')
		self._sendrecieve('ip tftp blocksize 8192\r','#')
		self._sendrecieve('end\r','#')

	def cleansoftware(self):
		# Clear out old software. We can place this at start of loop if desired
		# 
		bootfile_raw = ciscoUpgrade._sendrecieve(self,'show boot \r','#',verbose=True)
		bf = [x for x in bootfile_raw.split() if 'flash' in x][0].split(',')[0]
		print(bf)
		if len(bf.split('/')) > 2:
			os_folder = '/'.join(bf.split('/')[0:-1])
			self._sendrecieve('delete  /force /recursive ' + os_folder + ' \r' ,'#')
			#print('\n\n')
			#print('os_folder:', os_folder)
		else:

			self._sendrecieve('delete  /force ' + bf + '\r' ,'#')
		#delete /force /recursive flash
		#	current_file_systems = [x.split('.bin') for x in out.split() if '.bin' in x]
		#for ios in current_file_systems:
		
		#self._sendrecieve('\r','#')

	def tftp_getimage(self):
		'''Fetch image via TFTP. Allow no more than 5 failed attempts before moving on.'''

		successful = False
		attempts = 0
		while not successful and attempts < 5:
			#if file exists, a 'Do you want to over write? [confirm]' is displayed
			self._sendrecieve('copy tftp://' + self.tftpserver +'/bin/' + self.bin + ' flash:' + self.bin + '\r' ,'?')
			#destination host filename [iosversion]?
			output = self._sendrecieve('\r','#',verbose=True)
			if not 'Error' in output:
				successful = True
			else:
				attempts += 1
		if not successful and attempts >= 5:
			raise Exception('Too many failed TFTP attempts')

	def verifyimage(self):
		'''Check image for errors. Allow caller function to dictate number of attempts'''
		output = self._sendrecieve('verify flash:' + self.bin + '\r', '#',verbose=True)
		if 'Error' in output:
			raise VerifyException('Bad image')

	def softwareinstall(self):
		self._sendrecieve('config t\r', '#')
		self._sendrecieve('boot system switch all flash:/' + self.bin + '\r','#',verbose=True)
		self._sendrecieve('end\r','#')
		self._sendrecieve('write memory\r','#')

	def sendreload(self): #,ttreload = 'Now'
		#if not 'Now' in ttreload:
		#	ReasonforReload = ' pathway-eng automatic auto-provisioning switch upgrade...automatic'
		#	if self.debug:
		#		print("Sending reload command")
		#	self._sendrecieve(' reload in ' + str(ttreload) + ReasonforReload , ReasonforReload[-4:])
		#	self._sendrecieve('\r','#')
		#else:
		if self.debug:
			print("rebooting")
		try:
			self._sendrecieve("reload \r","[confirm]")
			self._sendrecieve('\r','')
			self.shell.keep_this.close()
		except Exception as e:
			if 'Socket is closed' in str(e):
				'Rebooted successfully!!'
		if self.debug:
			print("\n")

	def __exit__(self):
		self.keep_this.close()

class c38XXUpgrade(ciscoUpgrade):
	
	def __init__(self,host,tftpserver,binary_file,username,password,enable_password,debug):
		ciscoUpgrade.__init__(self,host=host,model='C3850',tftpserver=tftpserver,binary_file=binary_file,username=username,password=password,enable_password=enable_password,debug=debug)
	
	def cleansoftware(self):
		# Clear out old software. We can place this at start of loop if desired
		ciscoUpgrade._sendrecieve(self,'software clean \r' ,'#')
		ciscoUpgrade._sendrecieve(self,'\r','#')

	def Softwareinstall(self,iOS_TimingFlag = "on-reboot"):
		''' prepares and tells the switch to upgrade "on-reboot" by default'''
		ciscoUpgrade._sendrecieve(self,'software install file flash:' + ciscoUpgrade.bin +" "+ iOS_TimingFlag + '\r','#')
		time.sleep(0.5)


class c45xxUpgrade(ciscoUpgrade):
	
	def __init__(self,host,tftpserver,binary_file,username,password,enable_password,debug):
		ciscoUpgrade.__init__(self,host=host,model='C4506',tftpserver=tftpserver,binary_file=binary_file,username=username,password=password,enable_password=enable_password,debug=debug)

	def tftp_getimage(self):
		'''Fetch image via TFTP. Allow no more than 5 failed attempts before moving on.'''

		successful = False
		attempts = 0
		while not successful and attempts < 2:
			ciscoUpgrade._sendrecieve(self,'copy tftp://' + self.tftpserver +'/bin/' + self.bin + ' bootflash:' + self.bin + '\r' ,'?')	
			output = ciscoUpgrade._sendrecieve(self,'\r','#',verbose=True)
			if  'Error' not in output:
				successful = True
			else:
				attempts += 1
		if not successful and attempts >= 2:
			if 'No such file or directory' in output:
				'No such file or directory on server!'
			else:	
				raise Exception('Too many failed TFTP attempts')
		#print(self.bin)

	def verifyimage(self):
		'''Check image for errors. Allow caller function to dictate number of attempts'''
		output = ciscoUpgrade._sendrecieve(self,'verify bootflash:' + self.bin + '\r', '#',verbose=True)
		if 'Error' in output:
			raise VerifyException('Bad image')


	def cleansoftware(self):
		# Clear out old software. We can place this at start of loop if desired
		# 
		bootfile_raw = ciscoUpgrade._sendrecieve(self,'show bootvar \r','#',verbose=True)
		bf = [x for x in bootfile_raw.split() if 'flash' in x][0].split(',')[0]
		bf.split('.bin')[0] + '.bin'
		print(bf)
		if len(bf.split('/')) > 2:
			os_folder = '/'.join(bf.split('/')[0:-1])
			self._sendrecieve('delete  /force /recursive ' + os_folder + ' \r' ,'#')
			#print('\n\n')
			#print('os_folder:', os_folder)
		else:
			self._sendrecieve('delete  /force ' + bf + '\r' ,'#')
	
	def softwareinstall(self):
		ciscoUpgrade._sendrecieve(self,'config t\r', '#')
		ciscoUpgrade._sendrecieve(self,'boot system flash bootflash:/' + self.bin + ' \r','#',verbose=True)
		ciscoUpgrade._sendrecieve(self,'end\r','#')
		ciscoUpgrade._sendrecieve(self,'write memory\r','#')
