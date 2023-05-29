from configparser import ConfigParser
from asyncio import new_event_loop, wait, FIRST_COMPLETED
import copy
from urllib import parse
import re

class ConfigurationError(Exception):
    def __init__(self, value):
        super(ConfigurationError, self).__init__(value)
        self.error_message = value

    def __str__(self):
        return self.value.__str__


class Context(object):

    netloc_re = re.compile('(?P<host>[^:]+)(:(?P<port>\d+))?')

    # The settings that store boolean values
    boolean_options = {'connection': frozenset(['debug', 'kerberos']), 'logging': {}, 'kerberos': {}, 'ssl': frozenset(['verify_certs']), 'pycurl': {}}

    # The settings that store integer values
    integer_options = {'connection': frozenset(['timeout', 'max_active']), 'logging': {}, 'kerberos': {}, 'ssl': {}, 'pycurl': {}}

    # mapping from command line options to configuration options:
    arg_options = {'debug': ['connection', 'debug'],
                   'username': ['connection', 'username'],
                   'passwordfile': ['connection', 'passwordfile'],
                   'kerberos': ['connection', 'kerberos'],
                   'url': ['connection', 'url'],
                   'timeout': ['connection', 'timeout']}

    # default values for connection
    default_settings = {
        'connection': {
            'url': None,
            'username': None,
            'password': None,
            'passwordfile': None,
            'kerberos': False,
            'debug': False,
            'log': None,
            'user_agent': 'nexusupload/pycurl',
            'max_active': 10,
            'timeout': 10,
            'scheme': 'http',
            'http_version': None,
            'host': 'localhost',
            'port': 80,
        },
        'logging': {
            'filters': 'header,data,text',
        },
        'kerberos': {
            'ccache': None,
            'keytab': None,
            'principal': None,
        },
        'ssl': {
            'ca_certs_directory': None,
            'ca_certs_file': None,
            'verify_certs': True,
            'cert_file': None,
            'cert_type': None,
            'key_file': None,
            'key_type': None,
            'key_password': None,
        },
        'pycurl': {
            'libcurl_path': None,
            'pycurl_path': None
        }
    }

    def __init__(self, config_file=None, **kwargs):
        super().__init__()
        self.connected = False

        # Check consistency of authentication setup
        explicit_user = 'password' in kwargs or 'passwordfile' in kwargs or 'username' in kwargs
        explicit_kerberos = 'kerberos' in kwargs and kwargs.get('kerberos')
        if explicit_user and explicit_kerberos:
            raise ConfigurationError('both kerberos and login/password authentication requested')

        config = ConfigParser()
        if config_file is not None:
            config.read(config_file, encoding='utf-8')

        # Prepare the configuration with default settings
        self.current_config = copy.deepcopy(Context.default_settings)

        # Read the configuration
        for section in config.sections():
            for k,v in config.items(section):
                if k in Context.boolean_options[section]:
                    self.current_config[section][k] = config.getboolean(section, k)
                elif k in Context.integer_options[section]:
                    self.current_config[section][k] = config.getint(section, k)
                else:
                    self.current_config[section][k] = v

        # extract values from explicit arguments or else from config file
        for arg_name, arg_destination in Context.arg_options.items():
            if arg_name in kwargs:
                self.current_config[arg_destination[0]][arg_destination[1]] = kwargs.pop(arg_name)

        passwordfilename = self.current_config['connection'].pop('passwordfile')
        if passwordfilename is not None:
            with open(passwordfilename,'r') as passwordfile:
                self.current_config['connection']['password'] = passwordfile.read()

        if explicit_user:
            self.current_config['connection']['kerberos'] = False
        elif explicit_kerberos:
            self.current_config['connection']['username'] = None
            self.current_config['connection']['password'] = None

        if self.current_config['connection']['kerberos'] and self.current_config['kerberos'].get('keytab', None) is not None:
            import gssapi
            import os

            ccache = self.current_config['kerberos']['ccache']
            keytab = self.current_config['kerberos']['keytab']
            kname = self.current_config['kerberos']['principal']
            if kname is not None:
                kname = gssapi.Name(kname)

            gssapi.creds.Credentials(name=kname, usage='initiate', store={'ccache': ccache, 'client_keytab': keytab})
            os.environ['KRB5CCNAME'] = ccache
            self.current_config['connection']['kerberos'] = True

        if self.current_config['connection']['url'] == None:
            raise ConfigurationError('incomplete configuration, Nexus url not found')
        if self.current_config['connection']['username'] is None and self.current_config['connection']['kerberos'] is None:
            raise ConfigurationError('not enough authentication informations')

        self.check_pycurl(**self.current_config['pycurl'])

        from nexuslib.pycurlconnection import CurlDebugType, http_versions

        if self.current_config['logging']['filters'] is not None and self.current_config['connection']['debug']:
            self.filter = 0
            filters = [x.strip() for x in self.current_config['logging']['filters'].split(',')]
            for f in filters:
                self.filter |= CurlDebugType[f.upper()]

        connect_url = parse.urlparse(self.current_config['connection']['url'])
        scheme = connect_url.scheme
        if scheme == 'http':
            self.current_config.pop('ssl')
        elif scheme == 'https':
            # Default file format for x509 identity is PEM
            if self.current_config['ssl'].get('cert_file', None) is not None and self.current_config['ssl'].get('cert_type', None) is None:
                self.current_config['ssl']['cert_type'] = 'PEM'
            if self.current_config['ssl'].get('key_file', None) is not None and self.current_config['ssl'].get('key_type', None) is None:
                self.current_config['ssl']['key_type'] = 'PEM'
        else:
            raise ConfigurationError('invalid URL scheme "%s"' % scheme)
        self.current_config['connection']['scheme'] = scheme
        if self.current_config['connection']['http_version'] is not None \
                and self.current_config['connection']['http_version'] not in http_versions:
            raise ConfigurationError('Unknown http version')
        netloc = connect_url.netloc
        netloc_match = Context.netloc_re.fullmatch(netloc)
        if netloc_match is None:
            raise ConfigurationError('invalid URL netloc "%s"' % netloc)
        (host, port) = netloc_match.group('host', 'port')
        if port is None:
            port = 80 if scheme == 'http' else 443
        self.current_config['connection']['host'] = host
        self.current_config['connection']['port'] = port
        self.current_config['connection']['url_prefix'] = connect_url.path

    def check_pycurl(self, libcurl_path=None, pycurl_path=None):
        # Some distributions provides really old curl and pycurl
        # So a custom definition can be provided
        if libcurl_path is not None:
            from ctypes import cdll
            cdll.LoadLibrary(libcurl_path)

        if pycurl_path is not None:
            import importlib.util
            import sys
            pycurlspec = importlib.util.spec_from_file_location('pycurl', pycurl_path)
            sys.modules[pycurlspec.name] = pycurlspec.loader.load_module()

    def connect(self, parent=None):
        from nexuslib.pycurlconnection import PyCyrlConnection
        if parent is not None:
            self.multi_handle = parent.multi_handle
            self.curl_perform_task = parent.curl_perform_task
            self.loop = parent.loop
            max_active = None
        else:
            self.loop = new_event_loop()
            self.multi_handle = None
            self.curl_perform_task = None
            max_active = self.current_config['connection']['max_active']

        cnxprops={'timeout': self.current_config['connection']['timeout'],
                  'host': self.current_config['connection']['host'],
                  'port': self.current_config['connection']['port'],
                  'url_prefix': self.current_config['connection']['url_prefix'],}
        if self.current_config['connection']['debug']:
            cnxprops.update({
                'debug': self.current_config['connection']['debug'],
                'debug_filter': self.filter
            })

        if self.current_config['connection']['user_agent'] is not None:
            cnxprops.update({
                'user_agent': self.current_config['connection']['user_agent'],
            })

        if self.current_config['connection']['http_version'] is not None:
            cnxprops.update({
                'http_version': self.current_config['connection']['http_version'],
            })

        if self.current_config['connection']['username'] is not None and self.current_config['connection']['password'] is not None:
            http_auth = (self.current_config['connection']['username'], self.current_config['connection']['password'])
            with_kerberos = False
        elif self.current_config['connection']['kerberos']:
            http_auth = None
            with_kerberos = True
        else:
            http_auth = None
            with_kerberos = False

        if 'ssl' in self.current_config:
            ssl_opts = self.current_config['ssl']
            use_ssl = True
            verify_certs = self.current_config['ssl']['verify_certs']
            scheme='https'
        else:
            ssl_opts = None
            use_ssl = False
            verify_certs = False
            scheme='http'

        self.nexuscnx = PyCyrlConnection(
            scheme=scheme,
            loop=self.loop, multi_handle=self.multi_handle, max_active=max_active, curl_perform_task=self.curl_perform_task,
            use_ssl=use_ssl, verify_certs=verify_certs, ssl_opts=ssl_opts,
            kerberos=with_kerberos, http_auth=http_auth,
            **cnxprops
        )
        if self.curl_perform_task is None:
            self.curl_perform_task = self.nexuscnx.curl_perform_task
        if parent is None:
            self.multi_handle = self.nexuscnx.multi_handle
        if parent is None:
            return self.perform_query(self.nexuscnx.perform_request('GET', '/'))
        else:
            return True

    def perform_query(self, query):
        async def looper():
            done, pending = await wait((query, self.curl_perform_task), loop=self.loop, return_when=FIRST_COMPLETED)
            return done, pending

        done, pending = self.loop.run_until_complete(looper())
        # done contain either a result/exception from run_phrase or an exception from multi_handle.perform()
        # In both case, the first result is sufficient
        for i in done:
            running = i.result()
            # If running is None, run_phrase excited with sys.exit, because of argparse
            if running is not None:
                return running

    def disconnect(self):
        if self.loop is not None:
            if self.multi_handle is not None:
                self.multi_handle.running = False
            self.loop.run_until_complete(self.curl_perform_task)
            self.loop.stop()
            self.loop.close()
            self.loop = None
        self.nexuscnx = None
        self.connected = False
