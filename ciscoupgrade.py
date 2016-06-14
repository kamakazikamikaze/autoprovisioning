from __future__ import print_function
from __future__ import with_statement # Required in 2.5
import paramiko
import time
import sys
import signal
from contextlib import contextmanager

#import multiprocessing
#from easysnmp import snmp_get, snmp_walk


class TimeoutException(Exception): pass

@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException, "Timed out!"
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


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
			self._sendreceive('enable\r','assword:') #enabled status!!!
			self._sendreceive(enable_password + '\r','#') #
		self._sendreceive('terminal length 0\r','#')
		self._sendreceive('terminal width 0\r','#')
	

	def _sendreceive(self,command, expect, yesno='yes', verbose=False):  #, timeout=60):
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
				self.shell.send(yesno + '\r')
				receive_buffer = ''
		time.sleep(0.1)
		self.log += receive_buffer + '\n'
		if verbose:
			return receive_buffer


	def tftp_setup(self):
		#speed up the TFTP transfer
		self._sendreceive('config t\r', '#')
		self._sendreceive('ip tftp blocksize 8192\r','#')
		self._sendreceive('end\r','#')


	def cleansoftware(self):
		# Clear out old software. We can place this at start of loop if desired
		self._sendreceive('delete  /force /recursive flash:* \r' ,'#')
		self._sendreceive('\r','#')
		
		
	def tftp_getimage(self):
		'''Fetch image via TFTP. Allow no more than 5 failed attempts before moving on.'''

		successful = False
		attempts = 0
		while not successful and attempts < 5:
			#if file exists, a 'Do you want to over write? [confirm]' is displayed
			self._sendreceive('copy tftp://' + self.tftpserver +'/bin/' + self.bin + ' flash:' + self.bin + '\r' ,'?')
			#destination host filename [iosversion]?
			output = self._sendreceive('\r','#',verbose=True)
			if not 'Error' in output:
				successful = True
			else:
				attempts += 1
		if not successful and attempts >= 5:
			raise Exception('Too many failed TFTP attempts')


	def verifyimage(self):
		'''Check image for errors. Allow caller function to dictate number of attempts'''
		output = self._sendreceive('verify flash:' + self.bin + '\r', '#',verbose=True)
		if 'Error' in output:
			raise VerifyException('Bad image')


	def softwareinstall(self):
		self._sendreceive('config t\r', '#')
		out = self._sendreceive('boot system ?\r','#',verbose=True)
		if 'switch' in out:
			self._sendreceive('boot system switch all flash:/' + self.bin + '\r','#',verbose=True)
		else:
			self._sendreceive('boot system flash:' + self.bin + '\r','#',verbose=True)
		self._sendreceive('end\r','#')


	def writemem(self, end=False):
		if end:
			self._sendreceive('end\r','#')
		self._sendreceive('write memory\r','#')


	def sendreload(self, yesno='yes'): # Give the option to not save running config
		# if self.debug:
		# 	print("rebooting")
		try:
			self._sendreceive("reload \r","[confirm]",yesno)
			self._sendreceive('\r','')
			self.shell.keep_this.close()
		except Exception as e:
			if 'Socket is closed' in str(e):
				# 'Rebooted successfully!!'
				pass #??
		# if self.debug:
		# 	print("\n")


	def tftp_getstartup(self,filename):
		# if self.debug:
		# 	print('tftp getting startup config ' + filename)
		self._sendreceive('copy tftp://' + self.tftpserver + filename + ' startup-config\r',']?',verbose=True)
		out = self._sendreceive('\r','#',verbose=True)
		if 'Error' in out:
			raise Exception


	def blastvlan(self):
		self._sendreceive('delete /force flash:vlan.dat\r', '#')


	def tftp_replaceconf(self,timeout=17):
		# if self.debug:
		# 	print('replacing running config with startup')
		try:
			with time_limit(timeout):
				# self._sendreceive('configure replace nvram:startup-config force ignorecase\r','#',verbose=True)		
				self._sendreceive('configure memory\r','#',verbose=True)		
		except TimeoutException:
			# if self.debug:
			# 	print('\nconfigure replace successfully called!(probably)')
			return True
		else:
			raise Exception('configure replace was not successfull.')


	def __exit__(self):
		self.keep_this.close()


class c38XXUpgrade(ciscoUpgrade):
	
	def __init__(self,host,tftpserver,binary_file,username,password,enable_password,debug):
		ciscoUpgrade.__init__(self,host=host,model='C3850',tftpserver=tftpserver,binary_file=binary_file,username=username,password=password,enable_password=enable_password,debug=debug)
	

	def cleansoftware(self):
		# Clear out old software. We can place this at start of loop if desired
		self._sendreceive('delete /force /recursive flash:\r', '#', verbose=False)


	def softwareinstall(self,iOS_TimingFlag = "on-reboot"):		
		''' prepares and tells the switch to upgrade "on-reboot" by default'''
		# For whatever asinine reason, Cisco requires a complete reload of the
		# system if it is operating in BUNDLE mode so you can use the `software
		# install` command. This is unacceptable.
		# self._sendreceive('software install file flash:' + self.bin +" "+ iOS_TimingFlag + '\r','#')
		# SO SCREW IT. I'LL DO IT MY WAY.
		# UNPACK THE FILE. SET THE BOOTVAR. SAVE THE RUNNING CONFIG. HAVE THE
		# tftp_getstartup METHOD OVERWRITE THE STARTUP CONFIG. THEN REBOOT.
		status = self._sendreceive('software expand file flash:' + self.bin + ' to flash:\r', '#', verbose=True)
		if 'error' in status and not 'already installed' in status:
			raise Exception('Unable to expand image for installation!')
		self._sendreceive('config t\r', '#')
		self._sendreceive('boot system flash:packages.conf\r', '#')
		self._sendreceive('end\r', '#')
		self._sendreceive('write mem\r', '#')
		time.sleep(0.5)


class c45xxUpgrade(ciscoUpgrade):
	
	def __init__(self,host,tftpserver,binary_file,username,password,enable_password,debug):
	 	ciscoUpgrade.__init__(self,host=host,model='C4506',tftpserver=tftpserver,binary_file=binary_file,username=username,password=password,enable_password=enable_password,debug=debug)


	def tftp_getimage(self):
		'''Fetch image via TFTP. Allow no more than 5 failed attempts before moving on.'''

		successful = False
		attempts = 0
		while not successful and attempts < 2:
			self._sendreceive('copy tftp://' + self.tftpserver +'/bin/' + self.bin + ' bootflash:' + self.bin + '\r' ,'?')	
			output = self._sendreceive('\r','#',verbose=True)
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
		output = self._sendreceive('verify bootflash:' + self.bin + '\r', '#',verbose=True)
		if 'Error' in output:
			raise VerifyException('Bad image')


	def cleansoftware(self):
		# Clear out old software. We can place this at start of loop if desired
		self._sendreceive('delete /recursive bootflash:*\r','?',verbose=True)
		self._sendreceive('\r','#',verbose=True)
	

	def softwareinstall(self):
		self._sendreceive('config t\r', '#')
		self._sendreceive('boot system flash bootflash:/' + self.bin + ' \r','#',verbose=True)
		self._sendreceive('end\r','#')
		self._sendreceive('write memory\r','#')


	def blastvlan(self):
		# VLAN table is located somewhere else and needs to be removed
		self._sendreceive('erase cat4000_flash:\r', '#')
