from __future__ import print_function
from __future__ import with_statement  # Required in 2.5
import paramiko
import pexpect
import time
import sys
import signal
from contextlib import contextmanager

# import multiprocessing
# from easysnmp import snmp_get, snmp_walk


class TimeoutException(Exception):
    pass


@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out!")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


class VerifyException(Exception):
    r'''
    An exception representing that the IOS image was corrupt

    .. warning:: Depricated. This is not used as of version 0.7
    '''

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ciscoUpgrade:
    r'''
    Collection of commands necessary for upgrading Cisco equipment.

    This class is not necessarily tied down to only auto-provisioning. In fact,
    it can still be used for performing various maintenance/management tasks on
    a per-need and on-demand basis.

    A majority of Cisco Layer 2 equipment, such as C2940, C2960, C3560(C|CX|G),
    C3650, and C3750(X), can be administered using this base class. Notably,
    any standard IOS (not IOS-XE or IOS-R) fall under this category

    :param host: Network address for the target device
    :param tftpserver: Network address for the remote TFTP server
    :param binary_file: Target binary image to use (if upgrading)
    :param username: Credential
    :param password: Credential
    :param enable_password: Passphrase needed for entering privileged EXEC
                            mode, if any
    :param debug: Flag for verbosity
    '''

    def __init__(self, host, tftpserver, binary_file=None, username='default',
                 password='l4y3r2', enable_password=None, debug=True):
        self.host = host
        self.bin = binary_file
        self.tftpserver = tftpserver
        self.debug = debug
        self.log = ''
        client = paramiko.SSHClient()
        # I changed the timeout to 60 seconds so we're not waiting too long
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self.host,
            username=username,
            password=password,
            timeout=60,
            allow_agent=False,
            look_for_keys=False)
        self.shell = client.invoke_shell()
        self.shell.keep_this = client
        if enable_password:
            self._sendreceive('enable\r', 'assword:')  # enabled status!!!
            self._sendreceive(enable_password + '\r', '#')
        self._sendreceive('terminal length 0\r', '#')
        self._sendreceive('terminal width 0\r', '#')

    def _sendreceive(self, command, expect, yesno='yes',
                     verbose=False):
        r'''
        Shell handler for sending and receiving data. Acts like an `expect()`
        method.

        All commands sent to the target are completed through this method. It
        does *not* integrate a timer; it will continue to read from the buffer
        indefinitely until the expected character/group is discovered. It
        automatically sends confirmation to any '[confirm]' found in the buffer.
        If a '[yes/no]' statement is received, it will forward the choice passed
        to it through the `yesno` parameter.

        .. note:: You may also set the `expect` paramter to be `[confirm]` or
                  `[yes/no]`. The method will break out of the loop before
                  sending a default response

        :param command: String to send to the target
        :param expect: The string to break on once received from the target
        :param yesno: Response to send when `[yes/no]` is read
        :param verbose: Flag to indicate if buffer should be returned when done

        :returns: If `verbose` is set to True the buffer is returned, else None
        '''
        time.sleep(0.5)
        self.shell.send(command)
        # create recieve buffer
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
        r'''
        Set the TFTP blocksize to largest possible size
        '''
        self._sendreceive('config t\r', '#')
        self._sendreceive('ip tftp blocksize 8192\r', '#')
        self._sendreceive('end\r', '#')

    def cleansoftware(self):
        r'''
        Clear out **all** software
        '''
        self._sendreceive('delete  /force /recursive flash:* \r', '#')
        self._sendreceive('\r', '#')

    def tftp_getimage(self):
        r'''
        Fetch image via TFTP. Allows for no more than 5 failed attempts before
        moving on.
        '''
        successful = False
        attempts = 0
        while not successful and attempts < 5:
            # if file exists, a 'Do you want to over write? [confirm]' is
            # displayed
            self._sendreceive(
                'copy tftp://' +
                self.tftpserver +
                '/bin/' +
                self.bin +
                ' flash:' +
                self.bin +
                '\r',
                '?')
            # destination host filename [iosversion]?
            output = self._sendreceive('\r', '#', verbose=True)
            if not 'Error' in output:
                successful = self.verifyimage()
            else:
                attempts += 1
        if not successful and attempts >= 5:
            raise Exception('Too many failed TFTP attempts')

    def verifyimage(self):
        '''
        Check image for errors
        '''
        output = self._sendreceive(
            'verify flash:' + self.bin + '\r', '#', verbose=True)
        if 'Error' in output:
            # raise VerifyException('Bad image')
            return False
        return True

    def softwareinstall(self):
        r'''
        Sets the system to use the target image for boot
        '''
        self._sendreceive('config t\r', '#')
        out = self._sendreceive('boot system ?\r', '#', verbose=True)
        if 'switch' in out:
            self._sendreceive(
                'boot system switch all flash:/' +
                self.bin +
                '\r',
                '#',
                verbose=True)
        else:
            self._sendreceive(
                'boot system flash:/' +
                self.bin +
                '\r',
                '#',
                verbose=True)
        self._sendreceive('end\r', '#')

    def writemem(self, end=False):
        r'''
        Write to memory

        :param end: Set to True if the session is in configuration mode
        '''
        if end:
            self._sendreceive('end\r', '#')
        self._sendreceive('write memory\r', '#')

    def sendreload(self, yesno='yes'):
        r'''
        Command the device to reboot

        :param yesno: Set to 'no' if running-config should not be saved before
                      rebooting
        '''
        try:
            self._sendreceive("reload \r", "[confirm]", yesno)
            self._sendreceive('\r', '')
            self.shell.keep_this.close()
        except Exception as e:
            if 'Socket is closed' in str(e):
                # 'Rebooted successfully!!'
                pass  # ??
        # if self.debug:
        #   print("\n")

    def tftp_getstartup(self, filename):
        r'''
        Fetch a startup-config from the remote TFTP server and save it over the
        existing one on the device

        :param filename: Remote file to copy. Include the directory if necessary
        '''
        self._sendreceive(
            'copy tftp://' +
            self.tftpserver +
            filename +
            ' startup-config\r',
            ']?',
            verbose=True)
        out = self._sendreceive('\r', '#', verbose=True)
        if 'Error' in out:
            raise Exception

    def blastvlan(self):
        r'''
        Erase existing VLAN table
        '''
        self._sendreceive('delete /force flash:vlan.dat\r', '#')

    def tftp_replaceconf(self, timeout=17):
        r'''
        Reload the startup-config over the running-config without performing a
        system reboot.

        .. warning:: Not all commands will be applied successfully. It is
                     **not** recommended to use this unless you understand how
                     the possbile side-effects that can take place.
        '''
        try:
            with time_limit(timeout):
                # self._sendreceive('configure replace nvram:startup-config
                # force ignorecase\r','#',verbose=True)
                self._sendreceive('configure memory\r', '#', verbose=True)
        except TimeoutException:
            return True
        else:
            raise Exception('configure replace was not successfull.')

    def __exit__(self):
        self.keep_this.close()


class c38xxUpgrade(ciscoUpgrade):
    r'''
    This class overwrites the parent :py:meth:`softwareinstall` method due to
    differences in the IOS-XE firmware
    '''

    def softwareinstall(self):
        ''' prepares and tells the switch to upgrade "on-reboot" by default'''
        # For whatever asinine reason, Cisco requires a complete reload of the
        # system if it is operating in BUNDLE mode so you can use the `software
        # install` command. This is unacceptable.
        # self._sendreceive('software install file flash:' + self.bin +" "+ iOS_TimingFlag + '\r','#')
        # SO SCREW IT. I'LL DO IT MY WAY.
        # UNPACK THE FILE. SET THE BOOTVAR. SAVE THE RUNNING CONFIG. HAVE THE
        # tftp_getstartup METHOD OVERWRITE THE STARTUP CONFIG. THEN REBOOT.
        status = self._sendreceive(
            'software expand file flash:' +
            self.bin +
            ' to flash:\r',
            '#',
            verbose=True)
        if 'error' in status and not 'already installed' in status:
            raise Exception('Unable to expand image for installation!')
        self._sendreceive('config t\r', '#')
        self._sendreceive('boot system flash:packages.conf\r', '#')
        # self._sendreceive('end\r', '#')
        # self._sendreceive('write mem\r', '#')
        self.writemem(True)
        time.sleep(0.5)


class c45xxUpgrade(ciscoUpgrade):
    r'''
    This class overwrites several methods due to the difference in filesystem
    names.

    'flash:' is changed to 'bootflash:' and the VLAN table is located on
    'cat4000_flash:'
    '''

    def tftp_getimage(self):
        successful = False
        attempts = 0
        while not successful and attempts < 2:
            self._sendreceive(
                'copy tftp://' +
                self.tftpserver +
                '/bin/' +
                self.bin +
                ' bootflash:' +
                self.bin +
                '\r',
                '?')
            output = self._sendreceive('\r', '#', verbose=True)
            if 'Error' not in output:
                successful = True
            else:
                attempts += 1
        if not successful and attempts >= 2:
            if 'No such file or directory' in output:
                'No such file or directory on server!'
            else:
                raise Exception('Too many failed TFTP attempts')

    def verifyimage(self):
        output = self._sendreceive(
            'verify bootflash:' +
            self.bin +
            '\r',
            '#',
            verbose=True)
        if 'Error' in output:
            # raise VerifyException('Bad image')
            return False
        return True

    def cleansoftware(self):
        self._sendreceive('delete /recursive bootflash:\r', '?', verbose=True)
        self._sendreceive('\r', '#', verbose=True)

    def softwareinstall(self):
        self._sendreceive('config t\r', '#')
        self._sendreceive('boot system flash bootflash:/' +
                          self.bin + ' \r', '#', verbose=True)
        self.writemem(True)

    def blastvlan(self):
        self._sendreceive('erase cat4000_flash:\r', '#')


class ciscoInsecureUpgrade:
    r'''
    This class mirrors the :py:class:ciscoUpgrade class, however the
    `pexpect` module is used instead of `paramiko`. Note that the `_sendreceive`
    method is not added since `pexpect` has one built-in.

    All child classes reflect the same changes as their respective doppelganger.

    :param host: Network address for the target device
    :param tftpserver: Network address for the remote TFTP server
    :param binary_file: Target binary image to use (if upgrading)
    :param timeout: Maximum wait time, in seconds, for each `expect` call
    :param logfilename: File to flush the session buffer to
    :param pver3: Boolean; set to True if Python 3 is being used
    :param username: Credential
    :param password: Credential
    :param enable_password: Passphrase needed for entering privileged EXEC
                            mode, if any
    :param debug: Flag for verbosity
    '''
    # REMEMBER: pexpect use regex to search the buffer! Escape special characters
    #           when passing strings to `expect()`

    def __init__(self, host, tftpserver, binary_file, timeout,
                 logfilename, pver3, username='default', password='l4y3r2',
                 enable_password=None, debug=True):
        self.host = host
        if pver3:
            self.shell = pexpect.spawnu('telnet ' + host)
        else:
            self.shell = pexpect.spawn('telnet ' + host)
        self.shell.expect('Username: ')
        self.shell.sendline(username)
        self.shell.expect('Password: ')
        self.shell.sendline(password)
        self.bin = binary_file
        self.tftpserver = tftpserver
        self.debug = debug
        self.shell.logfile = open(logfilename, 'w')
        if enable_password:
            self.shell.expect('>')
            self.shell.sendline('enable')
            self.shell.expect('Password: ')
            self.shell.sendline(enable_password)
        self.shell.expect('#')
        self.shell.sendline('terminal length 0')
        self.shell.expect('#')
        self.shell.sendline('terminal width 0')
        self.shell.expect('#')

    def tftp_setup(self):
        # "Speed up" the TFTP transfer
        self.shell.sendline('config t')
        self.shell.expect('\)#')
        self.shell.sendline('ip tftp blocksize 8192')
        self.shell.expect('#')
        self.shell.sendline('end')
        self.shell.expect('#')

    def cleansoftware(self):
        # Clear out old software. We can place this at start of loop if desired
        self.shell.sendline('delete /force /recursive flash:*')
        self.shell.expect('#')

    def tftp_getimage(self):
        '''Fetch image via TFTP. Allow no more than 5 failed attempts before moving on.'''
        successful = False
        attempts = 0
        while not successful and attempts < 5:
            # if file exists, a 'Do you want to over write? [confirm]' is
            # displayed
            self.shell.sendline(
                'copy tftp://' +
                self.tftpserver +
                '/bin/' +
                self.bin +
                ' flash:' +
                self.bin)
            while True:
                i = self.shell.expect(['\?', '!', '#'], timeout=30)
                if i == 0:
                    self.shell.sendline('')
                elif i == 2:
                    break
            # self.sendline('')
            if not 'Error' in self.shell.before:
                successful = self.verifyimage()
            else:
                attempts += 1
        if not successful and attempts >= 5:
            raise Exception('Too many failed TFTP attempts')

    def verifyimage(self):
        '''Check image for errors. Allow caller function to dictate number of attempts'''
        self.shell.sendline('verify flash:' + self.bin)
        self.shell.expect('#')
        if 'Error' in self.shell.before:
            return False
            # raise VerifyException('Bad image')
        return True

    def softwareinstall(self):
        self.shell.sendline('config t')
        self.shell.expect('#')
        self.shell.sendline('boot system \?')
        self.shell.expect('#')
        if 'switch' in self.shell.before:
            self.shell.sendline('boot system switch all flash:/' + self.bin)
        else:
            self.shell.sendline('boot system flash:' + self.bin)
        self.shell.sendline('config-register 0x2101')
        self.shell.expect('#')
        self.shell.sendline('end')
        self.shell.expect('#')

    def writemem(self, end=False):
        if end:
            self.shell.sendline('end')
            self.shell.expect('#')
        self.shell.sendline('write memory')
        self.shell.expect('#')

    def erasestartup(self):
        self.shell.sendline('erase startup-config')
        self.shell.expect('\[confirm\]')
        self.shell.sendline('')
        self.shell.expect('#')

    def sendreload(self, yesno='yes'):
        # if self.debug:
        #   print("rebooting")
        self.shell.sendline('reload')
        i = self.shell.expect(['\[yes/no\]', '\[confirm\]'])
        if not i:
            self.shell.sendline(yesno)
            self.shell.expect('\[confirm\]')
        self.shell.sendline('')


class ciu3850(ciscoInsecureUpgrade):

    def softwareinstall(self):
        # Timed results:
        #  * 60 seconds to expand binary bundle
        #  * 75 seconds to copy package files
        #  * 10 seconds from 'package files copied' alert to being finished
        # TODO: Use `software install` instead of `software expand` and manual
        #       specification of boot image
        self.shell.sendline(
            'software expand file flash:' +
            self.bin +
            ' to flash:')
        self.shell.expect('Expanding')
        self.shell.expect('Copying', timeout=120)
        self.shell.expect('#', timeout=150)
        self.shell.sendline('config t')
        self.shell.expect('\)#')
        self.shell.sendline('boot system switch all flash:packages.conf')
        self.shell.expect('#')
        self.shell.sendline('config-register 0x2101')
        self.shell.expect('#')
        self.writemem(True)


class ciu4500(ciscoInsecureUpgrade):

    def tftp_getimage(self):
        '''Fetch image via TFTP. Allow no more than 5 failed attempts before moving on.'''
        successful = False
        attempts = 0
        while not successful and attempts < 5:
            # if file exists, a 'Do you want to over write? [confirm]' is
            # displayed
            self.shell.sendline(
                'copy tftp://' +
                self.tftpserver +
                '/bin/' +
                self.bin +
                ' bootflash:' +
                self.bin)
            while True:
                i = self.shell.expect(['\?', '!', '#'], timeout=30)
                if i == 0:
                    self.shell.sendline('')
                elif i == 2:
                    break
            # self.sendline('')
            if not 'Error' in self.shell.before:
                successful = True
            else:
                attempts += 1
        if not successful and attempts >= 5:
            raise Exception('Too many failed TFTP attempts')

    def cleansoftware(self):
        # Clear out old software. We can place this at start of loop if desired
        self.shell.sendline('delete /force /recursive bootflash:')
        self.shell.expect('#')

    def softwareinstall(self):
        self.shell.sendline('config t')
        self.shell.expect('\)#')
        self.shell.sendline('boot system flash bootflash:/' + self.bin)
        self.shell.expect('#')
        self.shell.sendline('config-register 0x2101')
        self.shell.expect('#')
        self.writemem(True)

    def verifyimage(self):
        '''Check image for errors. Allow caller function to dictate number of attempts'''
        self.shell.sendline('verify bootflash:' + self.bin)
        self.shell.expect('#')
        if 'Error' in self.shell.before:
            return False
            # raise VerifyException('Bad image')
        return True
