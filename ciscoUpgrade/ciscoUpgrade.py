import paramiko
import time
import sys
#import os
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
		client.connect(self.host, username = username, password = password, timeout = 60, allow_agent=False, look_for_keys=False)
		self.shell = client.invoke_shell()
		if enable_password:
			self.shell._sendrecieve('enable\r','assword:') #enabled status!!!
			self.shell._sendrecieve(enable_password,'#') #
		self.shell._sendrecieve('terminal length 0','#')
	
	def _sendrecieve(self,Command2Send, ExpectChar, verbose=False):
		time.sleep(0.5)
		self.shell.send(Command2Send)
		#create recieve buffer
		receive_buffer = ''
		while not ExpectChar in receive_buffer:
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
			elif ('[yes/no]:' in receive_buffer):
				time.sleep(0.5)
				self.shell.send('yes\r')
				receive_buffer = ''
		time.sleep(0.1)
		self.log += receive_buffer + '\n'
		if verbose:
			return receive_buffer


	def setupTFTP(self):
		self._sendrecieve('terminal length 0\r', '#')
		#speed up the TFTP transfer
		self._sendrecieve('config t\r', '#')
		self._sendrecieve('ip tftp blocksize 8192\r','#')
		self._sendrecieve('end\r','#')

	def cleansoftware(self):
		# Clear out old software. We can place this at start of loop if desired
		# 
		bootfile = self._sendrecieve('show boot | inc bin \r','#',verbose=True).split()[-1]
		if len(bootfile.split('/')) > 2:
			containing_folder = bootfile.split('/')[1]
			self._sendrecieve('delete  /force /recursive flash: \r' + containing_folder + '\r' ,'#')
		else:
			boot_file = bootfile.split('.bin') + '.bin'
			self._sendrecieve('delete  /force /recursive ' + boot_file + '\r' ,'#')
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
			self._sendrecieve('copy tftp://' + self.tftpserver +' /bin/' + self.bin + ' flash:' + self.bin + '\r' ,'?')
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

	def SoftwareInstall(self):
		self._sendrecieve('config t\r', '#')
		self._sendrecieve('boot system switch all flash flash:/' + self.bin + '\r','#',verbose=True)
		self._sendrecieve('end\r','#')
		self._sendrecieve('write memory\r','#')

class c38XXUpgrade(ciscoUpgrade):
	def __init__(self,host,model,tftpserver,binary_file,username,password,enable_password,debug):
		ciscoUpgrade.__init__(self,host=host,model='C3850',tftpserver=tftpserver,binary_file=binary_file,username=username,password=password,enable_password=None,debug=True)
	
	def cleansoftware(self, debug, shell):
		# Clear out old software. We can place this at start of loop if desired
		ciscoUpgrade._sendrecieve('software clean \r' ,'#', debug, shell)
		ciscoUpgrade._sendrecieve('\r','#',debug, shell)

	def SoftwareInstall(self,iOS_TimingFlag = "on-reboot"):
		''' prepares and tells the switch to upgrade "on-reboot" by default'''
		self._sendrecieve('software install file flash:' + ciscoUpgrade.bin +" "+ iOS_TimingFlag + '\r','#')
		time.sleep(0.5)


class c45xxUpgrade(ciscoUpgrade):
	def __init__(self,host,model,tftpserver,binary_file,username,password,enable_password,debug):
		ciscoUpgrade.__init__(self,host=host,model='C4506',tftpserver=tftpserver,binary_file=binary_file,username=username,password=password,enable_password=None,debug=True)

	def tftp_getimage(self):
		'''Fetch image via TFTP. Allow no more than 5 failed attempts before moving on.'''

		successful = False
		attempts = 0
		while not successful and attempts < 5:
			#if file exists, a 'Do you want to over write? [confirm]' is displayed
			ciscoUpgrade._sendrecieve('copy tftp://' + self.tftpserver +' /bin/' + ciscoUpgrade.bin + 'bootflash:' + self.bin + '\r' ,'?',verbose=True)	
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
		output = self._sendrecieve('verify bootflash:' + self.bin + '\r', '#',verbose=True)
		if 'Error' in output:
			raise VerifyException('Bad image')


	def cleansoftware(self):
		# Clear out old software. We can place this at start of loop if desired
		# 
		bootfile_raw = ciscoUpgrade._sendrecieve('show boot | inc bin \r','#',verbose=True).split()[-1]

		bootfile = bootfile_raw.split('.bin')[0] + '.bin'
		ciscoUpgrade._sendrecieve('delete  /force /recursive ' + bootfile + '\r' ,'#')
		#self._sendrecieve('\r','#')
	
	def SoftwareInstall(self):
		self._sendrecieve('config t\r', '#')
		self._sendrecieve('boot system switch all flash bootflash:/' + self.bin + '\r','#',verbose=True)
		self._sendrecieve('end\r','#')
		self._sendrecieve('write memory\r','#')
