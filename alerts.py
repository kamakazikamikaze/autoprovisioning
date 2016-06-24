import smtplib
from email.mime.text import MIMEText
from multiprocessing import Manager

class ConnectionException(Exception):
	def __init__(self, value):
		self.value = value


	def __str__(self):
		return repr('(Connection Error): ' + self.value)


class alert(object):
	def __init__(self, endpoint, username=None, password=None, port=None):
		self.endpoint = endpoint
		self.username = username
		self.password = password
		self.port = port


	def auth(self):
		raise NotImplementedError()


	def send(self):
		raise NotImplementedError()


	login = auth


class emailAlert(alert):
	def __init__(self, endpoint='localhost', username=None, password=None, port=None, secure=True, 
					keyfile=None, certfile=None, timeout=3):
		super(emailAlert, self).__init__(endpoint, username, password, port)
		self.secure = secure
		self.keyfile = keyfile
		self.certfile = certfile
		self.timeout = timeout
		self.port = port
		self.mailserv = None
		self.err = Manager().Queue()
		

	def auth(self):
		raise NotImplementedError('This is now a private method. Do not call it directly!')


	def _auth(self):
		# while True:
		# 	try:
		if self.mailserv is None:
			raise TypeError('self.mailserv has not been created! Call .send() ')
		self.mailserv.ehlo_or_helo_if_needed()
		self.mailserv.login(self.username, self.password)
		return
		# self.mailserv.helo()
			# except smtplib.SMTPServerDisconnected as e:
			# 	if 'connect()' in str(e) or 'not connected' in str(e):
			# 		self.mailserv.connect()
			# 	else:
			# 		raise e


	def send(self, recipients, msg, sender, subject='Alert'):
		while True:
			try:
				self.mailserv = smtplib.SMTP(self.endpoint, self.port, timeout=self.timeout)
				self.mailserv.set_debuglevel(1)
				if self.secure:
					self.mailserv.starttls(self.keyfile, self.certfile)
				if self.username is not None:
					self._auth()
				# mail = emailAlert.format(recipient, msg, sender, subject)
				mail = MIMEText(msg)
				mail['Subject'] = subject
				mail['From'] = sender
				mail['To'] = ', '.join(recipients)
				self.mailserv.sendmail(sender, recipients, mail.as_string())
				self.mailserv.quit()
				return True
			# except smtplib.SMTPServerDisconnected as e:
			# 	if 'connect()' in str(e) or 'not connected' in str(e):
			# 		self.mailserv.connect()
			# 	else:
			# 		self.err.put(e)
			# 		return False
			except Exception as e:
				self.err.put(e)
				return False
			finally:
				# SMTP class has some issues with re-opening connections with
				# our servers. Just create a new one each time this is called.
				self.mailserv = None


	@property
	def error(self):
		if not self.err.empty():
			return self.err.get()
		else:
			return None
