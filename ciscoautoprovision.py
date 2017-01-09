from __future__ import print_function
from alerts import emailAlert
from easysnmp import snmp_walk, snmp_get, EasySNMPTimeoutError
from socket import gethostbyaddr  # , gethostbyname
import logging
import logging.handlers
from time import sleep
from datetime import datetime as dt
# This is ours! Be sure to install it globally or into your virtualenv
from patheng.utils import load_plugin
import pexpect
import requests
from pprint import pformat
import sys
import json
import os
import re
import mmap
import tftpy
from tempfile import NamedTemporaryFile
from multiprocessing import Process, Manager
import ciscoupgrade as cup
# from recordclass import recordclass
import sqlite3 as sql
from voluptuous import Schema, Required, All, Any, Length, Range, Coerce, Email
from voluptuous import IsDir  # , IsFile, Optional


try:    # Python 3 compatibility
    input = raw_input
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
    r'''
    Generate an example configuration file

    :param String filename: The target file to write to in the 'cfg' folder
    '''
    d = {
        'alerts': {
            'type': 'email',
            'endpoint': 'your.gate.com',
            'secure': 0,
            'sender': 'no_reply@your.domain.com',
            'recipients': ['webmaster@target.domain.com'],
            'threshold': 5
        },
        'target firmware': {
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
        'database': '/srv/autoprovision',
        'debug': '1',
        'debug print': '0',
        'ignore list': 'ignore.txt',
        'log file': 'autoprov.log',
        'output dir': './output/',
        'default rwcommunity': 'private',
        'search': {
            'target': 'http://es-url.com',
            'index': 'autoprovision',
            'extra': []
        },
        'switch username': 'default',
        'switch password': 'l4y3r2',
        'switch enable': 'p4thw4y',
        'tftp server': '10.0.0.254',
        'telnet timeout': 20,
        'production rwcommunity': ''
    }
    with open(os.path.join(os.path.abspath('./cfg/'), filename), 'w') as dc:
        json.dump(d, dc, indent=4, sort_keys=True)
    logging.getLogger('CAP')
    logging.debug('Config generated to %s', filename)


class CiscoAutoProvision:
    r'''
    An auto-provisioning class designed to handle all steps necessary to
    detect, upgrade, and configure equipment for production-ready status.
    It is designed to work in the most simple manner:

    .. code:: python

        import ciscoautoprovision as cap

        if __name__ == "__main__":
            c = cap.CiscoAutoProvision('your_config.txt')
            c.run()

    The class will handle several major steps:

    * Detect unprovisioned equipment by fetching ElasticSearch logs
    * Pairing equipment with its matching production-level configuration file

      * First attempt to match the serial number to a file in the
        autoprovisioning folder on a remote TFTP server
      * If that fails, check the port description on the CDP neighbor in the ES
        logs
        and find a matching config file on the remote TFTP server
      * As a final resort, a model-default config file is then transferred to
        the host

    * Upgrades equipment to the latest approved firmware, as determined by a
      list in the script's configuration file. If the loaded firmware is not
      a crypto version (K9), it is first updated so that SSH/RSA keys may be
      generated before the production configuration is loaded
    * Parse the configuration file for the target device to derive its future
      IP address. After the host is told to reboot so that the startup-config
      may be loaded, it will ping the to-be IP to verify the equipment has
      successfully been provisioned.

    This class also includes an optional feature for sending activity alerts.
    When devices are successfully provisioned, an email or other communication
    message will be sent out to a target audience. Successes give notification
    immediately whereas alerts for unsuccessful attempts will only be sent once
    a threshold has been passed. (These alerts are only sent once as well.)

    :param configfile: The configuration file based off of this module's
                       :py:func:`generate_config` function
    '''

    def __init__(self, configfile):
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
        self._finished = Manager().Queue()

    timestr = '%a %b %d %Y %H:%M:%S'

    def __getstate__(self):
        # When the instance object is being serialized, this method is called.
        # Since the logging library is not multiprocessing.Pool-friendly, it
        # causes the Pool to be terminated immediately. While we may consider
        # spawning processes instead of using pools in the future, it still
        # gives a good example of how to exclude certain values/properties in
        # a "hacky" # kind of way. Here we're creating a dictionary
        # (which is serializable) and removing the saved logger from it.
        # This allows Pool to use our instance and move along.
        d = dict(self.__dict__)
        del d['logger']
        return d

    def __setstate__(self, d):
        self.__dict__.update(d)

    def _setuplogger(self):
        r'''
        Configure the logging module.

        This method is called in :py:meth:`__init__`. The logger is piped to
        two places: the local logging file, as dictated by the initial
        configuration file; STDOUT/console, if the "debug print" variable is
        set to 1 in the config.
        '''
        self.loglevel = logging.DEBUG if self.debug else logging.INFO
        # http://stackoverflow.com/a/9321890/1993468
        # logging.basicConfig(
        #     level=self.loglevel,
        #     filename=os.path.join(
        #         os.path.abspath(
        #             self.output_dir),
        #         self.logfile),
        #     format='%(asctime)s %(name)-4s| %(levelname)-8s| %(message)s',
        #     datefmt='%m-%d %H:%M:%S',
        #     filemode='a')
        logger = logging.getLogger('')
        logger.handlers = []
        formatter = logging.Formatter(
            '%(asctime)s %(name)-4s| %(levelname)-8s | %(message)s',
            datefmt='%m-%d %H:%M:%S')
        # TimedRotatingFileHandler won't work if invoking script via Cron
        # http://stackoverflow.com/q/3496727/1993468
        # fh = logging.handlers.TimedRotatingFileHandler(
        #     os.path.join(
        #         os.path.abspath(
        #             self.output_dir),
        #         self.logfile),
        #     'd',
        #     backupCount=7)
        fh = logging.handlers.RotatingFileHandler(
            os.path.join(
                os.path.abspath(
                    self.output_dir),
                self.logfile),
            maxBytes=256000,
            backupCount=7)
        fh.setLevel(self.loglevel)
        fh.setFormatter(formatter)
        self.logger = logging.getLogger('CAP')
        self.logger.setLevel(self.loglevel)
        self.logger.addHandler(fh)
        tf = NamedTemporaryFile(prefix='autoprovlog')
        tfh = logging.FileHandler(tf.name)
        tfh.setLevel(logging.INFO)
        tfh.setFormatter(formatter)
        self.logger.addHandler(tfh)
        self.log4email = tf
        if self.debug_print:
            cformatter = logging.Formatter(
                '%(name)-4s| %(levelname)-8s | %(message)s')
            console = logging.StreamHandler()
            console.setLevel(self.loglevel)
            console.setFormatter(cformatter)
            # logging.getLogger('').addHandler(console)
            self.logger.addHandler(console)
        else:
            logger.propagate = False
        self.logger.debug('Logger successfully created.')

    def ping(self, host):
        r'''
        Send a single ping to the target host. Timeout period is 1 second.

        :param host: Target to ping
        :returns: 1 if reachable; 0 if unreachable

        .. note:: This function currently will not work on Windows
        '''
        ping_command = "ping -W1 -c 1 " + host + " > /dev/null 2>&1 "
        response = os.system(ping_command)
        # Note:response is 1 for fail; 0 for success;
        return not response

    def _parseconfig(self, filename):
        with open(os.path.join(os.path.abspath('./cfg/'), filename)) as f:
            data = json.load(f)
        try:
            def checkemail(emails):
                emailschema = Schema(Email())
                if isinstance(emails, list):
                    return [e for e in emails if emailschema(e)]
                else:
                    return [emailschema(e)]

            configschema = Schema({
                Required('alerts'): All(dict, Schema({
                    Required('endpoint'): All(Coerce(str), Length(min=1)),
                    Required('recipients'): All(checkemail, Length(min=1)),
                    'secure': Any(int, bool),
                    Required('sender'): All(Email(), Length(min=1)),
                    Required('threshold', default=3): All(
                        Coerce(int),
                        Range(min=1)),
                    Required('type'): All(Coerce(str), Length(min=1)),
                    # SMTP class defaults to 0 in __init__
                    'port': All(Coerce(int), Range(min=0, max=65535)),
                    'timeout': All(Coerce(int), Range(min=-1, max=300)),
                    'debug': Any(str, int, bool),
                    'username': str,
                    'password': str
                })),
                Required('database'): IsDir(),
                Required('debug', default=0): All(Coerce(int),
                                                  Range(min=0, max=1)),
                Required('debug print', default=0): All(Coerce(int),
                                                        Range(min=0, max=1)),
                Required('default rwcommunity'): Coerce(str),
                Required('ignore list', default='ignore.txt'): Coerce(str),
                # IsDir() won't check the base directory,
                # IsFile() will return an error if the file doesn't exist.
                # We want to create the file if it doesn't exist, so...
                # https://github.com/alecthomas/voluptuous/issues/229
                Required('log file', default='autoprov.log'): Coerce(str),
                Required('output dir', default='./output/'): All(Coerce(str),
                                                                 IsDir()),
                Required('production rwcommunity'): Coerce(str),
                Required('rsa pass size', default=32): All(
                    Coerce(int),
                    Range(min=8, max=255)),
                'search': All(dict, Schema({
                    'extra': list,
                    'index': All(Coerce(str), Length(min=1)),
                    'method': Coerce(str),
                    'plugin': All(
                        dict,
                        Schema(
                            {
                                'name': Coerce(str),
                                Required('args', default=()): Any(list, tuple),
                                Required('kwargs', default={}): dict
                            },
                            required=True)),
                    'port': Any(None, All(int, Range(min=1, max=65535))),
                    'target': Coerce(str),
                    'timeperiod': All(Coerce(int), Range(min=1)),
                })),
                Required('switch enable'): Coerce(str),
                Required('switch password'): Coerce(str),
                Required('switch username'): Coerce(str),
                Required('target firmware'): dict,
                Required('telnet timeout', default=30): All(
                    Coerce(int),
                    Range(min=5, max=300)),
                Required('tftp server'): Coerce(str)
            })
            config = configschema(data)
            self.debug = config['debug']
            self.debug_print = config['debug print']
            # Just pass the keys we have. No need to define every field
            # self.elk = recordclass(
            #     'elk_stack',
            #     config['elk'].keys())(
            #     **config['elk'])
            self.elk = config['search']
            self.firmwares = config['target firmware']
            self.logfile = config['log file']
            self.logfile = 'autoprov.log'
            self.database = config['database']
            self.community = config['default rwcommunity']
            self.ignore = config['ignore list']
            self.output_dir = config['output dir']
            self.prodcommunity = config['production rwcommunity']
            self.suser = config['switch username']
            self.spasswd = config['switch password']
            self.senable = config['switch enable']
            self.tftp = config['tftp server']
            self.alerts = config['alerts']
            # self.alerts['username'] = None if 'username' not in config[
            #     'alerts'] else config['alerts']['username']
            # self.alerts['password'] = None if 'password' not in config[
            #     'alerts'] else config['alerts']['password']
            self._rsa_pass_size = config['rsa pass size']
            self.telnettimeout = config['telnet timeout']
        # except Exception as e:
        except Exception as e:
            sys.exit(
                'An error occurred while parsing the config file: {}'.format(e)
            )

    def search(self, target='http://localhost', method='GET', plugin=None,
               index='autoprovision', timeperiod=5, port=9200, extra=[]):
        r'''
        Search and parse logs from an ElasticSearch server.

        This method will pull docs from an ES server and scan them for logs
        about CDP neighbor VLAN mismatches. This is highly dependent upon the
        structure in which the auto-provisioning IOS configuration file is set
        up. If a device does not report VLAN mismatches, it cannot be detected.
        As such, the feeding port \*must* be set to Access mode with a VLAN
        other than 1. It is heavily inferred that CDP must also be enabled on
        the neighboring equipment.

        :param String target: ElasticSearch server base address
        :param String index: The index used for filing logs/docs pertaining to
                      auto-provisioning equipment
        '''
        self.switches = []
        if port is None:
            port = ''
        else:
            port = ':' + str(port) + '/'
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
                                'gte': 'now-' + str(timeperiod) + 'm',
                                'lte': 'now'
                            }
                        }
                    }],
                }
            },
            'size': 10000
        }
        query['filter']['bool']['must'].extend(extra)
        if plugin:
            self.logger.debug('Loading plugin "%s"', plugin['name'])
            requests = load_plugin(
                plugin['name'])(
                *plugin['args'],
                **plugin['kwargs'])
            self.logger.debug('Plugin was successfully loaded and initialized')
        r = requests.request(method, url, data=json.dumps(query))
        r.raise_for_status()
        result_dict = r.json()
        hits = result_dict['hits']['hits']
        results = []
        errs = set()
        for log in hits:
            try:
                host = {}
                host['ip address'] = log['_source']['host']
                neighbors = ''
                for r in re.findall(
                        r'(?<=, with )([\d\w\-\.\/]+ [\d\w\-\.\/]+)',
                        log['_source']['message']):
                    neighbors += r
                host['nei_raw'] = neighbors
                results.append(host)
            except Exception:
                self.logger.error(log['_source']['host'], exc_info=True)
                if log['_source']['host'] not in list(errs):
                    errs.add(log['_source']['host'])
        temp_switches = [dict(t)
                         for t in set([tuple(d.items()) for d in results])]
        sl = {}
        for switch in temp_switches:
            ip = switch['ip address'].encode()
            switch[ip] = ip
            sl[ip] = {}
            sl[ip]['ip address'] = switch['ip address']
            sl[ip].setdefault('hostname', ip)
            sl[ip].setdefault('neighbors', {})
            if switch['nei_raw'].encode().split():
                sl[ip]['neighbors'].setdefault(
                    switch['nei_raw'].encode().split()[0], [])
        for switch in temp_switches:
            try:
                ip = switch['ip address'].encode()
                try:
                    hostname = gethostbyaddr(ip)[0]
                    sl[ip]['hostname'] = hostname
                except:
                    self.logger.error(switch, exc_info=True)
                neighbor = switch['nei_raw'].encode().split()
                if neighbor:
                    n = neighbor.pop(0)
                    sl[ip]['neighbors'].setdefault(n, [])
                    for nei in neighbor:
                        sl[ip]['neighbors'][n].append(nei)
                del switch['nei_raw']
            except:
                self.logger.error(switch, exc_info=True)
                self.logger.debug(
                    'could not find hostname for ' +
                    switch['ip address'])
        for k, v in sl.iteritems():
            self.switches.append(v)
        self.logger.debug('Data found from ElasticSearch: %s',
                          pformat(self.switches))

    def run(self):
        r'''
        Execute the full provisioning process, beginning with discovering
        equipment prepared for installation.

        * In order to prevent multiple instances of the class from
          simultaneously provisioning the equipment, an SQLITE3 database is
          made to \'lock\' the equipment to instruct all other instances to
          back off. (This allows for other instances to pick up any equipment
          that may have surfaced since a the most recent search of a separate
          instance.)
        * The ElasticSearch server will be queried for documents/logs and
          parsed.
        * Based on the list of switches populated in an internal list, each
          device will be added to a multiprocessing Pool for asynchronous
          provisioning.
        * Logs will be generated add output to a file in the 'output' folder,
          using the provided named passed in by the initial configuration file.

        .. note:: In the event that an unforseen error occurs and causes the
                  Pool to exit early while processes are still ongoing, the
                  Pool will be instructed to wait until all processes complete
                  and return. Logs will not appear into the logfile but will
                  still be queued/retained until all processes finish. Once
                  complete, the queued logs will be flushed out to the file.

        * Finally, :py:meth:`sendalerts` is called to message the target
          audience, if any.
        '''
        self.search(**self.elk)
        if not self.switches:
            self.logger.info('No switches require provisioning.')
            return
        # if self.switches:
        self.logger.info('Starting Autoprovision process')
        processes = []
        for switch in self.switches:
            p = Process(target=self.autoupgrade, args=(switch,))
            self.logger.debug('Adding ' + switch['hostname'] + ' to pool.')
            p.start()
            processes.append(p)
        # while any(s.is_alive() for s in processes):
        #     pass
        for p in processes:
            # To prevent zombie/disowned processes, set a timeout
            p.join(3600)
        self.logger.info('Provisioning complete. See log for details.')
        self.sendalerts()

    def autoupgrade(self, switch):
        r'''
        Perform the provisioning process on a single switch.

        .. note:: It is highly recommended that you do not call this directly

        :param switch: A dictionary containing the hostname, IP address, and
                       any CDP neighbors
        '''
        try:
            # Jul 14, 2016: C3850 averages ~8.5mins to reboot (not upgrading)
            # Since spanning-tree must also discover VLAN routes, ~2 minutes
            # should be added for it to finish mapping the network
            self.logger = logging.getLogger('CAP')
            switch['locked'] = False
            timeout = 600
            self.logger.info(
                '[%s] Beginning provisioning process',
                switch['ip address'])
            try:
                self._get_model(switch)
                self._get_serial(switch)
            except EasySNMPTimeoutError:
                raise Exception('Could not retrieve model and/or serial!')
            # Had to move the lock into here. We want the serial to be the
            # table's primary key in the event the device appears with a
            # different IP We don't want to catch the exception; we want to
            # exit ASAP
            # sql.IntegrityError,
            try:
                with open(os.path.join(os.path.abspath('./cfg'), self.ignore),
                          'r+') as f:
                    ignore = False
                    lines = f.readlines()
                    if any(l.strip().upper() in (
                            [switch['ip address']] + switch['serial'])
                           for l in lines):
                        ignore = True
                    if ignore:
                        self.logger.debug(
                            '[%s] Device is to be ignored. Aborting process',
                            switch['ip address'])
                        return
            except IOError as e:
                self.logger.error(
                    '[%s] Error opening ignore file \'%s\'',
                    switch['ip address'], self.ignore, exc_info=True)
            self._lock(switch)
            switch['locked'] = True
            try:
                self._get_new_name(switch)
            except EasySNMPTimeoutError:
                self.logger.debug(
                    '[%s] Could not access neighbor switch',
                    switch['ip address'])
            # Generate RSA keys. Since we're replacing the startup config, and
            # RSA keys require a "write mem" to be saved, it's okay to save the
            # running config to flash
            if not switch['crypto']:
                # raise Exception('Not yet implemented!')
                logfilename = os.path.abspath(
                    os.path.join(
                        self.output_dir,
                        switch['hostname'] +
                        '-to_k9-log.txt'))
                self._upgradefirst(switch, logfilename)
            logfilename = os.path.abspath(
                os.path.join(
                    self.output_dir,
                    switch['hostname'] +
                    'log.txt'))
            self._gen_rsa(switch, logfilename=logfilename)
            # open ssh session
            self._ssh_opensession(switch)
            if switch['ip address'] in self.upgrades:
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
            self.logger.info(
                ('[%s] Configuration finished. Rebooting device to apply '
                    'changes'), switch['ip address'])
            if self._wait(switch['new ip address'], timeout=timeout):
                self.logger.info(
                    '[%s] Host is back online!', switch['ip address'])
                switch['success'] = True
                try:
                    self._finished.put(switch['new name'])
                except KeyError:
                    self._finished.put(switch['ip address'])
            else:
                self.logger.critical(
                    '[%s] Timer expired; cannot reach host! Recovery required',
                    switch['ip address'])
                switch['success'] = False
            # continual ping
        except sql.IntegrityError:
            self.logger.debug(
                '[%s] Already being provisioned by another process',
                switch['ip address'])
        except Exception as e:
            self.logger.error('[%s] Error occurred: %s', switch['ip address'],
                              e, exc_info=True)
            switch['success'] = False
        finally:
            self.logger.debug('[%s] Removing from queue', switch['ip address'])
            self._unlock(switch)

    def _get_model(self, switch):
        r'''
        Retrieve the target's serial number and firmware number

        :param Dict switch: All known data on the target
        '''
        # Boot image: SNMPv2-SMI::enterprises.9.2.1.73.0
        # https://supportforums.cisco.com/discussion/9696971/which-oid-used-get-name-cisco-device-boot-image
        # This doesn't show up in new devices, apparently...
        # CISCO-ENHANCED-IMAGE-MIB
        # IOS-XE: SNMPv2-SMI::enterprises.9.9.249.1.2.1.1.2.1000.1
        #   or CISCO-ENHANCED-IMAGE-MIB::ceImage
        # You can check if IOS-XE under the sysDescr.0 value
        # CISCO-FLASH-MIB::ciscoFlashFileName
        # C3560CG: ? SNMPv2-SMI::enterprises.9.9.10.1.1.4.2.1.1.5.1.1.1
        modeloid = 'entPhysicalModelName'
        imageoid = u'sysDescr.0'  # .1.3.6.1.2.1.16.19.6.0'
        # filesoid = u'CISCO-FLASH-MIB::ciscoFlashFileName'
        bootoid = u'SNMPv2-SMI::enterprises.9.2.1.73.0'
        softimage_raw = snmp_get(
            bootoid,
            hostname=switch['ip address'],
            community=self.community,
            version=2).value
        if len(softimage_raw.split('/')) <= 1:
            softimage = softimage_raw.split(':')[-1].lower()
        else:
            softimage = softimage_raw.split('/')[-1].lower()
        if not softimage_raw or softimage == 'packages.conf':
            softimage_raw = snmp_get(
                imageoid,
                hostname=switch['ip address'],
                community=self.community,
                version=2).value
            # softimage_raw = softimage_raw.split(
            #     "Version")[1].strip().split(" ")[0].split(",")[0]
            # softimage = self.rm_nonalnum(softimage_raw)
            # Is there a ##.#(##)EX in the string?
            if re.findall(r'\d+\(.+?\)[eE][xX]', softimage_raw):
                t = softimage_raw
                t = re.sub(r'\.', '', t)
                t = re.sub(r'\((?=\d)', '-', t)
                softimage_raw = re.sub(r'\)(?=\w+\d+)', '.', t)
                # Also remove the trailing '-m' in the reported image name
            # 03.07.03E is not in
            # cat3k_caa-universalk9.SPA.03.07.03.E.152-3.E3.bin
            elif re.findall(r'\d+\.\d+\.\d+[eE]', softimage_raw):
                softimage_raw = re.sub(
                    r'(?<=\d{2}\.\d{2}\.\d{2})[eE]', '', softimage_raw)
            softimage = [
                re.sub(
                    r'\-m$',
                    '',
                    x.lower()) for x in re.findall(
                    r'(?<=Software \()[\w\d-]+(?=\))|(?<=Version )[\d\.\w-]+',
                    softimage_raw)]
        physical = snmp_walk(
            modeloid,
            hostname=switch['ip address'],
            community=self.community,
            version=2)
        # if len(physical[0].value) == 0:
        #     del physical[0]
        # Remove all indices that do not contain values
        physical = filter(lambda p: p.value, physical)
        model = str(physical[0].value.split('-')[1])
        self.logger.debug(
            '[%s] IOS image: %s',
            switch['ip address'],
            softimage)
        if model not in self.firmwares:
            raise Exception('model' + model + 'not found in firmware list!')
            # TODO: make a way to add firmware if not found in listing
        elif isinstance(softimage, unicode) and softimage in self.firmwares[
                model].lower() and (
                    self._k9(softimage) and '296' not in model):
            switch['crypto'] = True
            switch['model'] = model
            switch['bin'] = self.firmwares[model]
            switch['softimage'] = softimage
            self.logger.debug(
                '[%s] No upgrade needed. Target IOS: %s', switch['ip address'],
                switch['bin'])
        elif isinstance(softimage, list) and all(
                x in self.firmwares[model].lower() for x in softimage) and (
                self._k9(softimage) and '296' not in model):
            switch['crypto'] = True
            switch['model'] = model
            switch['bin'] = self.firmwares[model]
            switch['softimage'] = softimage
            self.logger.debug('[%s] No upgrade needed. Target IOS: %s',
                              switch['ip address'], switch['bin'])
        else:
            switch['crypto'] = self._k9(softimage)
            switch['model'] = model
            switch['bin'] = self.firmwares[model]
            switch['softimage'] = softimage
            self.upgrades.append(switch['ip address'])
            self.logger.debug('[%s] Upgrade needed. Target IOS: %s',
                              switch['ip address'], switch['bin'])

    def _k9(self, image):
        '''
        Verify that the supplied IOS image supports Cryptography
        '''
        if isinstance(image, list):
            return any(x for x in image if 'k9' in x.lower())
        else:
            return 'k9' in image.lower()

    def _upgradefirst(self, switch, logfilename):
        r'''
        Upgrade to a K9 image before performing provisioning process

        Since non-K9 IOS images do not include encryption capabilities, the
        target must be upgraded prior to regular provisioning since RSA keys
        need to be generated to enable SSH. This method mirrors the layout of
        :py:meth:`autoupgrade` but uses Pexpect in order to perform the upgrade
        over Telnet instead.

        :param Dict switch: All known information of the target device
        :param String logfilename: File to flush Telnet buffer to
        '''
        self.logger.debug('[%s] Attempting to upgrade to K9 binary first',
                          switch['ip address'])
        # logger.debug('Opening telnet session...')
        # self.logger.debug('[%s] Opening telnet session...',
        # switch['ip address'])
        self.logger.debug('[%s] K9: Opening telnet session...',
                          switch['ip address'])
        d = dict(host=switch['ip address'], tftpserver=self.tftp,
                 username=self.suser, password=self.spasswd,
                 logfilename=logfilename, pver3=self.pver3,
                 binary_file=switch['bin'], timeout=self.telnettimeout,
                 enable_password=self.senable, debug=self.debug,
                 )
        sess = None
        if not self.ping(switch['ip address']):
            raise Exception('host not reachable')
        if switch['model'].startswith('C38'):
            sess = cup.ciu3850(**d)
        elif switch['model'].startswith('C45'):
            sess = cup.ciu4500(**d)
        else:
            self.logger.debug('[%s] K9: Using default upgrade profile',
                              switch['ip address'])
            sess = cup.ciscoUpgrade(**d)
        # I won't try to catch errors. Let the autoupgrade method handle it
        self.logger.debug('[%s] K9: Setting up TFTP...'. switch['ip address'])
        sess.tftp_setup()
        self.logger.debug(
            '[%s] K9: Clearing out old software...',
            switch['ip address'])
        sess.cleansoftware()
        self.logger.debug(
            '[%s] K9: Fetching and verifying image...',
            switch['ip address'])
        sess.tftp_getimage()
        self.logger.debug(
            '[%s] K9: Installing and setting boot image...',
            switch['ip address'])
        sess.softwareinstall()
        self.logger.debug(
            '[%s] K9: Erasing startup-config...',
            switch['ip address'])
        sess.erasestartup()
        self.logger.debug('[%s] K9: Reloading switch!', switch['ip address'])
        sess.sendreload('no')
        self.logger.info(
            ('[%s] K9: Rebooting switch; waiting for graceful shutdown before '
                'sending pings'), switch['ip address'])
        sleep(8)
        if not self._wait(switch['ip address'], timeout=1200):
            raise Exception(
                ('Switch did not come back online after upgrading it to a '
                    'crypto version!'))
        self.upgrades.remove(switch['ip address'])
        self.logger.debug(
            '[%s] K9: Validating upgrade...',
            switch['ip address'])
        try:
            self._get_model(switch)
        except EasySNMPTimeoutError:
            sleep(8)  # Because, ya know, 8 is the optimal number, right?
            self._get_model(switch)
        if not self._k9(switch['softimage']):
            raise Exception('Switch did not upgrade properly to crypto image!')
        else:
            self.logger.debug(
                ('[%s] K9: Upgrade verified. Resuming normal provisioning '
                    'procedure.'), switch['ip address'])

    def _get_new_name(self, switch):
        r'''
        Derive the target's expected hostname from a CDP neighbor's port

        :param Dict switch: All known data of the target device
        '''
        # logger = logging.getLogger('CAP.(' + switch['ip address'] + ')')
        oid_index = []
        for neighbor, ports in switch['neighbors'].iteritems():
            alias = snmp_walk(
                hostname=neighbor,
                version=2,
                community=self.prodcommunity,
                oids='IF-MIB::ifAlias')
            descr = snmp_walk(
                hostname=neighbor,
                version=2,
                community=self.prodcommunity,
                oids='IF-MIB::ifDescr')
            oid_index += [x.oid_index for x in descr if x.value in ports]
        newname = ''
        for i in oid_index:
            try:
                newname = alias[int(i) - 1].value.split()[0]
                if newname:
                    switch['new name'] = newname
                    self.logger.info(
                        ('[%s] New hostname found from neighbor\'s port '
                            'description. To-be: %s'), switch['ip address'],
                        switch['new name'])
                    pass  # TODO
            except IndexError:
                self.logger.warning(
                    ('[%s] Target hostname was not found on a neighboring '
                     'switch!'), switch['ip address'])

    def _get_serial(self, switch):
        r'''
        Retrieve target's serial number via SNMP

        :param Dict switch: All known data of the target device
        '''
        # logger = logging.getLogger('CAP.(' + switch['ip address'] + ')')
        serialnum = self.getoids[switch['model']](
            switch['ip address'], self.community)
        if serialnum:
            switch['serial'] = serialnum
            self.logger.info('[%s] Serial number: %s', switch['ip address'],
                             serialnum)

    def _ssh_opensession(self, switch):
        r'''
        Initiate an SSH session with the target device.

        Creates an instance of the upgrade class based on device's model

        :param Dict switch: All known data of the target device
        '''
        d = dict(host=switch['ip address'], tftpserver=self.tftp,
                 binary_file=switch['bin'],
                 username=self.suser, password=self.spasswd,
                 enable_password=self.senable, debug=self.debug)
        self.logger.debug('[%s] Preparing SSH session', switch['ip address'])
        if not self.ping(switch['ip address']):
            raise Exception('host not reachable')
        if switch['model'].startswith('C38'):
            switch['session'] = cup.c38xxUpgrade(**d)
        elif switch['model'].startswith('C45'):
            switch['session'] = cup.c45xxUpgrade(**d)
        else:
            self.logger.debug(
                '[%s] Using default upgrade profile',
                switch['ip address'])
            switch['session'] = cup.ciscoUpgrade(**d)

    def _prepupgrade(self, switch):
        r'''
        Run all TFTP commands and set the bootimage

        :param Dict switch: All known data of the target device
        '''
        self.logger.info(
            '[%s] Preparing upgrade process...',
            switch['ip address'])
        switch['session'].tftp_setup()
        self.logger.debug(
            '[%s] Clearing out old images...',
            switch['ip address'])
        switch['session'].cleansoftware()
        self.logger.debug('[%s] Retrieving IOS image...', switch['ip address'])
        switch['session'].tftp_getimage()
        self.logger.debug('[%s] Installing software...', switch['ip address'])
        switch['session'].softwareinstall()

    def _tftp_replace(self, switch, time):
        r'''
        Transfer the device's production-level configuration file and save it
        over the startup-config

        :param Dict switch: All known data of the target device
        :param Int time: Timeout period, in seconds, before giving up
        '''
        if 'new ip address' in switch.keys():
            switch['session'].tftp_replaceconf(timeout=time)
            self.logger.info(
                '[%s] Startup-config successfully transferred',
                switch['ip address'])
        else:
            self.logger.warning(
                '[%s] Unable to find a configuration file on TFTP server!',
                switch['ip address'])
        del switch['session']

    def _tftp_startup(self, switch):
        r'''
        Search for and retrieve the production-level configuration file for the
        target device

        :param Dict switch: All known data of the target device
        '''
        switch['session'].blastvlan()
        found_config = False
        if not found_config and 'serial' in switch.keys():
            for serial in switch['serial']:
                dir_prefix = '/autoprov'
                filename = '/' + serial + '-confg'
                found_config = self._startupcfg(
                    switch=switch, remotefilename=dir_prefix + filename)
                if found_config:
                    self.logger.info(
                        '[%s] Using config that matches the serial number!',
                        switch['ip address'])
                    # switch['serial'] = [serial]
                    break
        if not found_config and 'new name' in switch.keys():
            self.logger.info(
                ('[%s] No config matches serial number. Searching for one '
                 'based on CDP neighbor\'s port description'),
                switch['ip address'])
            filename = '/' + switch['new name'].lower() + '-confg'
            found_config = self._startupcfg(
                switch=switch, remotefilename=filename)
            if found_config:
                self.logger.info(
                    '[%s] Found a config file based on hostname: "%s"',
                    switch['ip address'], filename)
        if not found_config:
            self.logger.warning(
                ('[%s] Unable to find target config file. Resorting to model '
                 'default!'), switch['ip address'])
            dir_prefix = '/autoprov'
            filename = '/cap' + switch['model'].lower() + '-confg'
            found_config = self._startupcfg(
                switch=switch, remotefilename=filename)
        if not found_config:
            raise Exception(
                'not able to find any config files for switch ' +
                switch['ip address'])

    def _startupcfg(self, switch, remotefilename):
        r'''
        Fetch and save a local copy of the target device's production-level
        configuration file for examination.

        This method will parse the file to determine the host's expected IP
        address once it loads it as the startup-config

        :param Dict switch: All known data of the target device
        :param String remotefilename: Target file to fetch
        '''
        outputfile = NamedTemporaryFile()
        success = Helper(
            self.tftp).tftp_getconf(
            remotefilename=remotefilename,
            outputfile=outputfile.name)
        if success:
            with open(outputfile.name, 'r+b') as f:
                log = mmap.mmap(f.fileno(), 0)
            # Perhaps this isn't necessary, but I wanted to ensure the file
            # would be closed in the event of an interrupt
            try:
                results = re.findall(
                    (r'\s(ip\saddress\s((?:\d{1,3}\.){3}\d{1,3})\s'
                        r'(?:\d{1,3}\.){3}\d{1,3})'), log)
                switch['new ip address'] = map(lambda g0_g1: g0_g1[1], results)
                results = re.findall(r'hostname\s([\S]+)', log)
                if results:
                    switch['hew name'] = results[0]
            except Exception as e:
                raise e
            finally:
                log.close()
            self.logger.debug(
                '[%s] New ip address: %s',
                switch['ip address'],
                switch['new ip address'])
            switch['session'].tftp_getstartup(remotefilename)
        return success

    def _gen_rsa(self, switch, logfilename):
        r'''
        Connect to the remote host and generate RSA keys so that SSH can be
        enabled.

        The RSA keys will be saved to the private-config. This allows
        persistence and the keys can be used between reboots. (This also
        reduces redundancy and time wasted from having to generate keys every
        time the target reboots because they were not saved.)

        .. note:: Some models, such as C3750X, can generate keys with a modulus
                  size of 4096 bits. Unlike the C3850 and C4500 series, this
                  will take a significant amount of time to do. The method
                  defaults to the largest modulus size possible, which may be
                  either 2048 or 4096. Take this into consideration when
                  waiting for provisioning to complete.

        :param Dict switch: All known data of the target device
        :param String remotefilename: Target file to fetch
        '''
        self.logger.debug(
            '[%s] Attempting to setup RSA keys',
            switch['ip address'])
        if self.pver3:
            s = pexpect.spawnu('telnet ' + switch['ip address'])
        else:
            s = pexpect.spawn('telnet ' + switch['ip address'])
        s.timeout = self.telnettimeout
        s.logfile = open(logfilename, 'w')
        self.logger.debug(
            '[%s] Opening telnet session...',
            switch['ip address'])
        s.expect('Username: ')
        s.sendline(self.suser)
        s.expect('Password: ')
        s.sendline(self.spasswd)
        s.expect('>')
        s.sendline('enable')
        s.expect('Password: ')
        s.sendline(self.senable)
        s.expect('#')
        self.logger.debug(
            '[%s] Setting up environment...',
            switch['ip address'])
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
        s.expect('\)#')
        if 'name' in keyout:
            self.logger.debug(
                '[%s] Erasing all existing keys...',
                switch['ip address'])
            s.sendline('crypto key zeroize rsa')
            s.expect('\]: ')
            s.sendline('yes')
            s.expect('#')
        s.sendline('crypto key storage nvram:')
        s.expect('#')
        s.sendline('crypto key generate rsa storage nvram:')
        s.expect('\]: ')
        if 'yes' in s.before:
            s.sendline('yes')
            s.expect('\]: ')
        # Extract largest possible keysize
        s.sendline('?')
        s.expect('\]: ')
        keysize = s.before.split('.')[0].split()[-1]
        if not keysize.isdigit():
            keysize = '2048'  # Default if didn't split the output correctly
        s.sendline(keysize)
        if '3750' in switch['model'] and int(keysize) > 2048:
            self.logger.info(
                ('[%s] Switch is a 3750X. Generating a 4096-bit key will take '
                 'a while.'),
                switch['ip address'])
            s.expect('#', timeout=600)
        else:
            self.logger.info(
                '[%s] Generating a %s-bit RSA keypair.',
                switch['ip address'],
                keysize)
            s.expect('#', timeout=300)
        successful = True if '[OK]' in s.before else False
        s.sendline('ip ssh version 2')
        s.expect('#')
        # Change boot register since this is always run
        s.sendline('config-register 0x2101')
        s.expect('#')
        s.sendline('exit')
        s.expect('#')
        self.logger.debug(
            '[%s] Saving RSA keys (and running-config)...',
            switch['ip address'])
        s.sendline('write mem')
        s.send('')
        s.expect('#')
        s.logfile.close()
        s.close()
        if not successful:
            self.logger.debug('[%s] :: %s', switch['ip address'], s.before)
            # self.logger.debug('%s', s.before)
            raise Exception('RSA key was not generated successfully!')
        else:
            # logger.info('RSA key was imported successfully!')
            self.logger.info('[%s] RSA key was imported successfully!',
                             switch['ip address'])
            # self.logger.info('RSA key was generated successfully!')

    def _lock(self, switch):
        r'''
        Place a 'lock' on an unprovisioned device to prevent race conditions
        using an SQLITE3 DB. The DB name is specified in the initial config
        file

        .. note:: This should only be called from within :py:meth:`autoupgrade`

        .. warning:: In order for all processes to sync, every instance of the
                     script must point to the same DB location. If two users
                     have their 'database' config value set differently,
                     locking will **not** work correctly!

        This method will ensure that the appropriate tables exist in the
        database before attempting to insert any values. If the table is locked
        by another provisioning process, the method simply restarts the loop so
        it can ensure that the device is properly locked. However, if it finds
        that the locktable already has a row with the serial that matches its
        device, it exits immediately under the assumption that a different
        process is currently handling the provisioning. Both tables, named
        'devices' and 'locked', use the following schema:

        +------+------+-------+-------------+------+
        | name | ip   | model | serial TEXT | date |
        | TEXT | TEXT | TEXT  | PRIMARY KEY | TEXT |
        +------+------+-------+-------------+------+

        Any devices that have passed the threshold of allowed provisioning will
        be ignored.

        :param Dict switch: All known data on the target device. This **must**
                            contain the hostname, IP, model, and serial no.
        '''
        while True:
            try:
                device = (
                    switch['hostname'],
                    switch['ip address'],
                    switch['model'],
                    switch['serial'][0],
                    dt.now().strftime(self.timestr))
                db = os.path.join(self.database, 'lockfile.db')
                conn = sql.connect(db)
                c = conn.cursor()
                # Initialize tables, if not already existant
                # When tables are created, the DB immediately commits them.
                # Another process may, however, lock the table between CREATEs
                c.execute(('CREATE TABLE IF NOT EXISTS failure (name text, '
                           'ip text, model text, serial text primary key, '
                           'date text, attempts integer, notify text)'))
                c.execute('SELECT * FROM failure WHERE serial = ?',
                          [switch['serial'][0]])
                d = c.fetchone()
                if d and d[5] >= self.alerts['threshold']:
                    raise sql.OperationalError(
                        ('Device has failed provisioning too many times! '
                         'Will not attempt again until device is removed from '
                         'the database.'))
                c.execute(
                    ('CREATE TABLE IF NOT EXISTS devices (name text, '
                     'ip text, model text, serial text primary key, '
                     'date text)'))
                c.execute(
                    ('CREATE TABLE IF NOT EXISTS locked (name text, ip text, '
                     'model text, serial text primary key, date text)'))
                # Lock device first; this will abort the provisioning process
                # if another one is already working on it
                c.execute('INSERT INTO locked VALUES (?,?,?,?,?)', device)
                # Update the date info
                c.execute(
                    'INSERT OR REPLACE INTO devices VALUES (?,?,?,?,?)',
                    device)
                self.logger.debug(
                    '[%s] Placed lock on device',
                    switch['ip address'])
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
                try:
                    conn.close()
                except UnboundLocalError:
                    pass

    def _unlock(self, switch):
        r'''
        Release the lock placed on the target device and log if the
        provisioning process ended in success or failure.

        .. note:: This should only be called from within :py:meth:`autoupgrade`

        If the caller is responsible for having locked the device, the method
        will allow it to make changes to the database. If provisioning was
        successful, any existing failure entries are dropped and a row is
        inserted into the 'success' table. If a success is already recorded, it
        is overwritten. (This is to prevent the table from growing unchecked.)
        Failures are logged with an incrementing counter whose purpose is for
        indicating that too many attempts to provision have occurred and the
        target recepients of the alerts should be notified at once as there
        may be a security or topology concern.

        The 'success' table uses the same schema as 'devices' and 'locked' from
        the :py:meth:`_lock` method, however the 'failures' table uses the
        following:

        +------+------+-------+-------------+------+----------+---------+
        | name | ip   | model | serial TEXT | date | attempts | notify  |
        | TEXT | TEXT | TEXT  | PRIMARY KEY | TEXT | INTEGER  | INTEGER |
        +------+------+-------+-------------+------+----------+---------+

        :param Dict switch: All known data on the target device. This **must**
                            contain the hostname, IP, model, and serial no.
        :returns: True if this process is the owner of the lock
        '''
        # If the switch wasn't locked by *this* process, ignore it
        if not all(x in switch.keys() for x in ['serial', 'model', 'locked']):
            return False
        while switch['locked']:
            try:
                db = os.path.join(self.database, 'lockfile.db')
                conn = sql.connect(db)
                c = conn.cursor()
                c.execute((
                    'CREATE TABLE IF NOT EXISTS success (name text, ip text, '
                    'model text, serial text primary key, date text)'))
                # Even if it's not in the table for some reason, this won't
                # raise an error
                c.execute(
                    'DELETE FROM locked WHERE serial = ?', [
                        switch['serial'][0]])
                self.logger.debug(
                    '[%s] Removed lock on device',
                    switch['ip address'])
                if switch['success']:
                    # TODO: Notification of success/failure
                    device = (
                        switch['hostname'],
                        switch['ip address'],
                        switch['model'],
                        switch['serial'][0],
                        dt.now().strftime(self.timestr))
                    c.execute(
                        'INSERT OR REPLACE INTO success VALUES (?,?,?,?,?)',
                        device)
                    c.execute(
                        'DELETE FROM failure WHERE serial = ?', [
                            switch['serial'][0]])
                    self.logger.debug(
                        '[%s] Recorded success into database',
                        switch['ip address'])
                else:
                    c.execute('SELECT * FROM failure WHERE serial = ?',
                              [switch['serial'][0]])
                    d = c.fetchone()
                    if d:
                        c.execute(
                            ('UPDATE failure SET attempts = attempts + 1, '
                                'date = ? WHERE serial = ?'),
                            (dt.now().strftime(self.timestr),
                                switch['serial'][0]))
                        self.logger.debug(
                            ('[%s] Updated provisioning failure count in '
                             'database'), switch['ip address'])
                    else:
                        c.execute(
                            'INSERT INTO failure VALUES (?,?,?,?,?,?,?)',
                            (switch['hostname'],
                             switch['ip address'],
                                switch['model'],
                                switch['serial'][0],
                                dt.now().strftime(self.timestr),
                                1,
                                'FALSE'))
                        self.logger.debug(
                            '[%s] Recorded provisioning failure into database',
                            switch['ip address'])
                conn.commit()
                conn.close()
                return True
            except sql.OperationalError as e:
                if 'locked' in str(e).lower():
                    pass
                else:
                    raise e
            finally:
                try:
                    conn.close()
                except UnboundLocalError:
                    pass

    def _wait(self, target, cycle=5, timeout=300):
        r'''
        Wait until the target is back online. Sends a periodic ping to the
        target.

        :param target: device hostname or IP address
        :param cycle: how long to wait between each ping, in seconds. Minimum
                      is (and defaults to) 5
        :param timeout: total wait time, in seconds, before returning to the
                        caller. Minimum is 30, defaults to 300
        :returns: True if successful
        '''
        # TODO: Allow simultaneous ping attempts
        if isinstance(target, list):
            target = target[0]
        self.logger.info('[%s] Waiting for device to come back online', target)
        attempts = 1
        cycle = cycle if cycle > 5 else 5
        timeout = timeout if timeout >= 30 else 300
        retries = timeout / cycle
        while timeout > 0:
            if self.debug:
                # self.logger.debug('%s: sending ping %i of %i', target,
                # attempts, retries)
                self.logger.debug('[%s] Sending ping %i of %i',
                                  target, attempts, retries)
            if self.ping(target):
                self.logger.info('[%s] Responded to ping!', target)
                return True
            sleep(cycle - 1)
            # Timeout is 1, so remove that from the overall wait
            timeout -= cycle
            attempts += 1
        # self.logger.warning('%s did not respond to pings!', target)
        self.logger.warning('[%s] Timed out!', target)
        return False

    def sendalerts(self):
        r'''
        Send a report via email to the target recipients.

        .. note:: This is automatically invoked when :py:meth:`run` finishes

        Reports on all successful provisioning attempts from this session. If
        any devices have failed to be provisioned more times than the threshold
        set in the initial config file, they are added to the email and their
        database entry is updated to denote this. (This alert only occurs
        once.)
        '''
        devices = []
        success = ''
        failure = ''
        self.logger.debug('Preparing email alert for provisioning activity...')
        if not self._finished.empty():
            while not self._finished.empty():
                devices.append(self._finished.get())
            success = ('The following device(s) were successfully provisioned:'
                       '\n\t{0}\n').format(
                '\n\t'.join(devices))
            self.logger.debug(
                'Generated list of successfully provisioned devices')
        try:
            db = os.path.join(self.database, 'lockfile.db')
            conn = sql.connect(db)
            c = conn.cursor()
            c.execute(
                ('SELECT ip FROM failure WHERE attempts >= ? AND notify == '
                    '\'FALSE\''), [self.alerts['threshold']])
            devices = c.fetchall()
            if devices:
                failure = ('The following device(s) could not be provisioned:'
                           '\n\t{0}\n').format(
                    '\n\t'.join([d[0] for d in devices]))
                c.executemany(
                    'UPDATE failure SET notify = \'TRUE\' WHERE ip = ?',
                    devices)
                conn.commit()
                self.logger.debug(
                    ('Generated list of devices that failed to be provisioned '
                     'over ' + str(self.alerts['threshold']) + ' attempts.'))
        except Exception:
            self.logger.error('Error generating email alert!', exc_info=True)
        finally:
            conn.close()
        message = ''
        if success:
            message += success
        if failure:
            message += failure
        a = dict(**self.alerts)
        del a['sender'], a['recipients'], a['type'], a['threshold']
        email = emailAlert(**a)
        if message:
            try:
                if self.log4email:
                    self.logger.debug('Attaching {} to email as a log.'.format(
                        self.log4email.name.split('/')[-1]))
                message += '\n\nThis alert was generated at {0}\n'.format(
                    dt.now().strftime(self.timestr))
                success = email.send(
                    self.alerts['recipients'],
                    message,
                    self.alerts['sender'],
                    subject='Provisioning Activity',
                    attachments=[self.log4email.name])
                if success:
                    self.logger.info('An email has been sent.')
                else:
                    self.logger.critical('Error generating email alert!')
                while True:
                    e = email.error
                    if not e:
                        break
                    else:
                        self.logger.error(e)
            except:
                self.logger.error(
                    'An error occurred while trying to generate an email',
                    exc_info=True)
        if not message:
            self.logger.debug('No email was sent.')

    def flushfailures(self):
        '''
        Clear database of old entries

        Removes rows that currently or could potentially prevent reuse of
        switches that previously failed to provision properly. Eliminates the
        need of users having to memorize SQL queries for DB management.

        By default, entries older than 30 days or those that have
        reached/passed the threshold of failures before abandoning (also having
        triggered alerts to admins) will be removed.
        '''
        while True:
            try:
                db = os.path.join(self.database, 'lockfile.db')
                conn = sql.connect(db)
                c = conn.cursor()
                c.execute(('CREATE TABLE IF NOT EXISTS failure (name text, '
                           'ip text, model text, serial text primary key, '
                           'date text, attempts integer, notify text)'))
                c.execute('SELECT * FROM failure')
                rows = c.fetchall()
                if rows:
                    c.executemany('DELETE FROM failure WHERE serial = ?',
                                  [(row[3],) for row in rows if (
                                      row[5] >= self.alerts['threshold'] or (
                                          dt.now() - dt.strptime(
                                              row[4], self.timestr)
                                      ).days >= 30)]
                                  )
                conn.commit()
                self.logger.info('Flushed stale failure logs from database')
                return
            except sql.OperationalError as e:
                if 'locked' in str(e).lower():
                    pass
                else:
                    self.logger.error(
                        'Error flushing records from DB failures table!',
                        exc_info=True)
                    raise e
            except Exception as e:
                self.logger.error(
                    'Error flushing records from DB failures table!',
                    exc_info=True)
                raise e
            finally:
                try:
                    conn.close()
                except UnboundLocalError:
                    pass

    getoids = {
        'C4506': lambda hostname, community: [
            snmp_get(hostname=hostname, version=2, community=community,
                     oids='.1.3.6.1.2.1.47.1.1.1.1.11.1').value],
        'C4506R': lambda hostname, community: [
            snmp_get(hostname=hostname, version=2, community=community,
                     oids='.1.3.6.1.2.1.47.1.1.1.1.11.1').value],
        'C4507': lambda hostname, community: [
            snmp_get(hostname=hostname, version=2, community=community,
                     oids='.1.3.6.1.2.1.47.1.1.1.1.11.1').value],
        'C3850': lambda hostname, community: [x.value for x in snmp_walk(
            hostname=hostname, version=2, community=community,
            oids='.1.3.6.1.2.1.47.1.1.1.1.11') if x.oid_index in [
                '1', '1000', '2000', '3000', '4000', '5000', '6000', '7000',
                '8000', '9000']],
        'C3750X': lambda hostname, community: [x.value for x in snmp_walk(
            hostname=hostname, version=2, community=community,
            oids='.1.3.6.1.2.1.47.1.1.1.1.11') if x.oid_index in [
                '1001', '2001', '3001', '4001', '5001', '6001', '7001',
                '8001', '9001']],
        'C3750V2': lambda hostname, community: [x.value for x in snmp_walk(
            hostname=hostname, version=2, community=community,
            oids='.1.3.6.1.2.1.47.1.1.1.1.11') if x.oid_index in [
                '1001', '2001', '3001', '4001', '5001', '6001', '7001', '8001',
                '9001']],
        'C3750': lambda hostname, community: [x.value for x in snmp_walk(
            hostname=hostname, version=2, community=community,
            oids='.1.3.6.1.2.1.47.1.1.1.1.11') if x.oid_index in [
                '1001', '2001', '3001', '4001', '5001', '6001', '7001', '8001',
                '9001']],
        'C3560': lambda hostname, community: [
            snmp_get(hostname=hostname, version=2, community=community,
                     oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value],
        'C3560X': lambda hostname, community: [
            snmp_get(hostname=hostname, version=2, community=community,
                     oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value],
        'C3560CG': lambda hostname, community: [
            snmp_get(hostname=hostname, version=2, community=community,
                     oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value],
        'C3560CX': lambda hostname, community: [
            snmp_get(hostname=hostname, version=2, community=community,
                     oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value],
        'C2940': lambda hostname, community: [
            snmp_get(hostname=hostname, version=2, community=community,
                     oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value],
        'C2960': lambda hostname, community: [
            snmp_get(hostname=hostname, version=2, community=community,
                     oids='.1.3.6.1.2.1.47.1.1.1.1.11.1001').value]
    }


class Helper:
    r'''
    An agent for handling TFTP activity, most notably checking the existence
    of production-level configuration files.

    :param tftp_server: IP address of the remote TFTP server to use
    '''

    def __init__(self, tftp_server='10.0.0.254'):
        if self._ping_(tftp_server):
            self.server = tftp_server
        else:
            raise Exception('no response from server!')
        self.client = tftpy.TftpClient(host=self.server, port=69)

    def _ping_(self, host):
        r'''
        Send a single ping to the target host. Timeout period is 1 second.

        :param host: Target to ping
        :returns: 1 if reachable; 0 if unreachable

        .. note:: This function currently will not work on Windows
        '''
        ping_command = "ping -W1 -c 1 " + host + " > /dev/null 2>&1 "
        response = os.system(ping_command)
        # Note:response is 1 for fail; 0 for success;
        return not response

    def tftp_putconf(self, inputfile, remotefilename):
        r'''
        Send a file to the TFTP server

        :param inputfile: Local file name
        :param remotefilename: Name to give file on remote host
        '''
        self.client.upload(filename=remotefilename, input=inputfile)

    def tftp_getconf(self, remotefilename, outputfile='./output/temp_config'):
        r'''
        Fetch the given file

        :param remotefilename: Target file. Include the directory tree if
                               necessary. Ex: `bin/cisco_ios.bin`

        :returns: True if TFTP was able to GET the target file
        '''
        try:
            self.client.download(
                filename=str(remotefilename),
                output=outputfile)
            return True
        except tftpy.TftpShared.TftpException:  # as t:
            # if 'File not found' in t.message:
                # pass
            return False


class CapTest(CiscoAutoProvision):
    r'''
    This is a wrapper over the main class to be used for testing purposes only
    '''

    def run(self):
        '''
        Full provisioning process
        '''
        self.logger.info('Starting Autoprovision process')
        self._remaining = []
        for switch in self.switches:
            self._remaining.append(switch['ip address'])
            self.logger.debug(
                'Creating a process for ' +
                switch['hostname'] +
                '.')
            # , callback=self._decr)  # Python 3 has an error_callback. Nice...
            p = Process(target=self.autoupgrade, args=(switch,))
            p.start()
            while p.is_alive() or not self.logger.empty():
                if not self.logger.empty():
                    log = self.logger.get()
                    if isinstance(log[-1], dict):  # Contains `exc_info=True`
                        self.logger.log(*log[0], **log[1])
                    else:
                        self.logger.log(*log)
            p.join()
            self._rem(switch['ip address'])
        # Extra safety net, just in case an error kills the pool prematurely.
        # The pool closed on me early last night and finished the script,
        # however a worker was still TFTP'ing (and printing out) in the
        # background
        while not self.logger.empty():
            if not self.logger.empty():
                log = self.logger.get()
                if isinstance(log[-1], dict):  # Contains `exc_info=True`
                    self.logger.log(*log[0], **log[1])
                else:
                    self.logger.log(*log)
        self.logger.info('Provisioning complete. See log for details.')

    def editswitchlist(self):
        for index, switch in enumerate(self.switches):
            print(str(index) + ': ' +
                  switch['ip address'] + '\t' + switch['hostname'])
            r = -69
        while r not in [''] + map(lambda x_y: str(x_y[0]),
                                  enumerate(self.switches)):
            r = raw_input(
                'Enter switch number to pop. leave empty to stop editing.')
        if r and r.isdigit():
            print(self.switches[int(r)]['ip address'] + ' was removed')
            self.switches.pop(int(r))

    def get_information(self):
        to_pop = []
        for switch in self.switches:
            try:
                self.logger.debug(
                    'IP for %s:\t%s',
                    switch['hostname'],
                    switch['ip address'])
                try:
                    self._get_model(switch)
                    self._get_serial(switch)
                except EasySNMPTimeoutError:
                    self.logger.debug(
                        '%s timed out', switch['ip address'], exc_info=True)
                    to_pop.append(switch)
                    continue
                try:
                    self._get_new_name(switch)
                except EasySNMPTimeoutError:
                    print('could not access neighbor switch')
            except Exception:
                self.logger.error(
                    'Failed to retrieve information from %s',
                    switch['ip address'],
                    exc_info=True)
        for s in to_pop:
            self.logger.info(
                'Removing %s from switch list',
                switch['ip address'])
            self.switches.pop(self.switches.index(s))

    def upgradeall(self):
        for switch in self.switches:
            self.autoupgrade(switch)

    def get_model(self):
        for switch in self.switches:
            try:
                self.logger.debug(
                    'Fetching model for %s',
                    switch['ip address'])
                self._get_model(switch)
            except Exception as e:
                self.logger.warning(
                    '%s timed out. (%s)', switch['ip address'], e)

    def get_new_name(self):
        for switch in self.switches:
            try:
                self._get_new_name(switch)
            except:
                self.logger.warning(
                    'Could not get new name for %s',
                    switch['ip address'],
                    exc_info=True)

    def get_serial(self):
        for switch in self.switches:
            try:
                switch['serial'] = self.getoids[switch['model']](
                    switch['ip address'], self.community)
                self.logger.debug(
                    'Serial no. for %s is %s',
                    switch['ip address'],
                    switch['serial'])
            except Exception:
                self.logger.error(
                    'Failed to get serial for %s',
                    switch['ip address'],
                    exc_info=True)

    def ssh_opensession(self):
        for switch in self.switches:
            try:
                self._ssh_opensession(switch)
            except Exception as e:
                self.logger.warning(
                    'Failed to open SSH session for %s!',
                    switch['ip address'])
                self.logger.error('%s', e, exc_info=True)

    def prepupgrade(self):
        for switch in self.switches:
            if switch['ip address'] in self.upgrades:
                try:
                    self._prepupgrade(switch)
                except Exception as e:
                    self.logger.warning(
                        'Failed to upgrade %s!', switch['ip address'])
                    self.logger.error('%s', e, exc_info=True)

    def tftp_replace(self):
        for switch in self.switches:
            if switch['ip address'] not in self.upgrades:
                try:
                    self._tftp_replace(switch, time=17)
                except Exception as e:
                    self.logger.warning(
                        'Could not transfer config file for %s!',
                        switch['ip address'])
                    self.logger.error('%s', e, exc_info=True)

    def tftp_startup(self):
        '''
        Trys to pull a configuration from the given tftp server. the
        tftp_startup will first try and get a config based on the serial
        number in a serialnum-conf format in the tftpboot/autoprov/ folder if
        that fails then it checks in the base /tftpboot/ folder for a config
        that is the same as the feedport description and in the event that
        fails it will look in the /tftpboot/ folder for a model specific base
        config.
         '''
        for switch in self.switches:
            try:
                self._tftp_startup(switch)
            except Exception as e:
                self.logger.error(
                    '%s: %s', switch['ip address'], e, exc_info=True)

    def reboot_save(self):
        for switch in self.switches:
            try:
                switch['session'].sendreload('no')
            except Exception as e:
                self.logger.warning(
                    '%s: %s', switch['ip address'], e, exc_info=True)

    def generate_rsa(self):
        for switch in self.switches:
            try:
                logfilename = os.path.abspath(
                    os.path.join(
                        self.output_dir,
                        switch['ip address'] +
                        'log.txt'))
                self._gen_rsa(switch, logfilename=logfilename)
            except Exception as e:
                self.logger.error('%s: %s', switch['ip address'], e)
                # print(e)
                if self.debug:
                    with open(logfilename, "r") as f:
                        print(f.read())
