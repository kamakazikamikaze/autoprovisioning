#!/usr/bin/env python 
from __future__ import print_function
import pexpect
from time import sleep
from getpass import getuser, getpass
if __name__ == '__main__':
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