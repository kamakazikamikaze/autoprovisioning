#import paramiko
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


def _sendrecieve(Command2Send, ExpectChar, debug, shell, errCheck = False):
	time.sleep(0.5)
	shell.send(Command2Send)
	#create recieve buffer
	receive_buffer = ''
	while not ExpectChar in receive_buffer:
		if shell.recv_ready():
			buf = shell.recv(100)
			if debug and len(buf) > 0:
				sys.stdout.write(buf)
				sys.stdout.flush()
			receive_buffer += buf
		if ('[confirm]' in receive_buffer):
			time.sleep(0.5)
			shell.send('\r')
			receive_buffer = ''
		elif ('[yes/no]:' in receive_buffer):
			time.sleep(0.5)
			shell.send('yes\r')
			receive_buffer = ''
	time.sleep(0.1)
	if errCheck:
		return receive_buffer


def setupTFTP(debug, shell):
	_sendrecieve('terminal length 0\r', '#', debug, shell)
	#speed up the TFTP transfer
	_sendrecieve('config t\r', '#', debug, shell)
	_sendrecieve('ip tftp blocksize 8192\r','#', debug, shell)
	_sendrecieve('end\r','#', debug, shell)


def cleansoftware(debug, shell):
	# Clear out old software. We can place this at start of loop if desired
	_sendrecieve('software clean \r' ,'#', debug, shell)
	_sendrecieve('\r','#',debug, shell)


def getimage(tftpserver, switch,debug, shell):
	'''Fetch image via TFTP. Allow no more than 5 failed attempts before moving on.'''

	successful = False
	attempts = 0
	while not successful and attempts < 5:
		#if file exists, a 'Do you want to over write? [confirm]' is displayed
		if switch['model'].starts('c4'):
			_sendrecieve('copy tftp://' + tftpserver +' /bin/' + switch['ios_binary'] + 'bootflash:' + switch['ios_binary'] + '\r' ,'?', debug, shell)	
		elif switch['model'].starts('c3850'):
			_sendrecieve('copy tftp://' + tftpserver +' /bin/' + switch['ios_binary'] + ' flash:' + switch['ios_binary'] + '\r' ,'?', debug, shell)
		#destination host filename [iosversion]?
		output = _sendrecieve('\r','#', debug, shell, True)
		if not 'Error' in output:
			successful = True
		else:
			attempts += 1
	if not successful and attempts >= 5:
		raise Exception('Too many failed TFTP attempts')

def verifyimage(switch,debug, shell):
	'''Check image for errors. Allow caller function to dictate number of attempts'''
	output = _sendrecieve('verify flash:' + switch['ios_binary'] + '\r', '#', debug, shell, True)
	if 'Error' in output:
		raise VerifyException('Bad image')

def SoftwareInstall(debug, switch, shell, iOS_TimingFlag = "on-reboot"):
	''' prepares and tells the switch to upgrade "on-reboot" by default'''
	_sendrecieve('software install file flash:' + switch['ios_binary'] +" "+ iOS_TimingFlag + '\r','#', debug, shell)
	time.sleep(0.5)
