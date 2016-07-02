"""
Collection of handlers for sending alerts through
.. module:: alerts
   :platform: Unix, Windows

.. moduleauthor:: Kent Coble
"""

import smtplib
from email.mime.text import MIMEText
from multiprocessing import Manager


class ConnectionException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr('(Connection Error): ' + self.value)


class alert(object):
    r'''
    Template class for handling alerts to send to a target audience.

    With the expection of `__init__`, all methods are merely stubs to be
    implemented in child classes. The intended design is to allow a class to be
    swapped from the caller while eliminating the need to change the names of
    the methods called.
    '''

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
    r'''
    Use email to alert the target audience

    Allows for authentication with any built-in :py:mod:smtplib options

    .. warning:: If you're going to send credentials, you damn well should
                 pass in ``secure=True`` so that an SSL/TLS session is
                 created for the exchange.

    :param endpoint: Mail server's address
    :param username: Credential
    :param password: Credential
    :param port: Mail server's communication port. If `None`, :py:mod:smtplib
                 will use defaults per protocol
    :param bool secure: Use secure communication for credential exchange
    :param keyfile: File name of local keyfile if using for authentication
    :param certfile: File name of local certificate for authentication
    :param timeout: Maximum wait until giving up on server to respond
    '''

    def __init__(self, endpoint='localhost', username=None, password=None,
                 port=None, secure=True, keyfile=None, certfile=None,
                 timeout=3):
        super(emailAlert, self).__init__(endpoint, username, password, port)
        self.secure = secure
        self.keyfile = keyfile
        self.certfile = certfile
        self.timeout = timeout
        self.port = port
        self.mailserv = None
        self.err = Manager().Queue()

    def auth(self):
        r'''
        Does nothing.

        .. warning:: This has been moved to a private method. Attempting to
                     authenticate when a session has expired can cause the
                     client to hang as the SMTP server will **not** respond.
                     Authentication is handled by :py:meth:`send()` in order to
                     prevent an extended wait.
        '''
        pass
        # raise NotImplementedError('This is now a private method.
        # Do not call it directly!')

    def _auth(self):
        r'''
        Sends credentials to server.
        '''
        if self.mailserv is None:
            raise TypeError(
                'self.mailserv has not been created! Call .send() ')
        self.mailserv.ehlo_or_helo_if_needed()
        self.mailserv.login(self.username, self.password)
        return

    def send(self, recipients, msg, sender, subject='Alert'):
        r'''
        Send an email to the mail server for delivery

        Handles SSL/TLS and authentication challenges, if any. If an error
        occurs, it is passed to the :py:attr:`error` queue

        :param list recipients: Target audience for the email. Multiple
                                recipients may be set
        :param msg: Message to send. Plaintext only
        :param sender: Email of the sender
        :param subject: Messages subject to use
        '''
        if not isinstance(recipients, list):
            recipients = [recipients]
        while True:
            try:
                self.mailserv = smtplib.SMTP(
                    self.endpoint, self.port, timeout=self.timeout)
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
        r'''
        Queue of any errors experienced
        '''
        if not self.err.empty():
            return self.err.get()
        else:
            return None
