import pycurl
from io import BytesIO
import re
import sys
from enum import IntEnum
import time
from logging import Logger
from asyncio import Queue, QueueEmpty, get_event_loop, wait_for, TimeoutError, wait
import logging
from asyncio import Future, ensure_future
from urllib.parse import urlencode
from nexuslib.exceptions import NexusException


logger = logging.getLogger('nexuslib.pycurlconnection')


status_line_re = re.compile(r'HTTP\/\S+\s+\d+(\s+(?P<status>.*?))?$')


def version_tuple(version):
    if isinstance(version, str):
        return tuple(map(int, (version.split("."))))
    else:
        return version


def set_version_info():
    version_info = lambda x: False
    version_info_vector = list(pycurl.version_info())
    version_info_vector.reverse()
    versions = set(['libz_version', 'libidn', 'version'])
    for i in ('age', 'version', 'version_num', 'host', 'features', 'ssl_version', 'ssl_version_num', 'libz_version', 'protocols',
              'ares', 'ares_num',
              'libidn',
              'iconv_ver_num', 'libssh_version',
              'brotli_ver_num', 'brotli_version'):
        # When walking of the version_info_vector is done, no more values
        if len(version_info_vector) == 0:
            break
        value = version_info_vector.pop()
        if i in versions:
            setattr(version_info, i, version_tuple(value))
        else:
            setattr(version_info, i, value)
    features = set()
    features_mapping = {'VERSION_ASYNCHDNS': 'AsynchDNS',
                        'VERSION_GSSNEGOTIATE': 'GSS-Negotiate',
                        'VERSION_IDN': 'IDN',
                        'VERSION_IPV6': 'IPv6',
                        'VERSION_LARGEFILE': 'Largefile',
                        'VERSION_NTLM': 'NTLM',
                        'VERSION_NTLM_WB': 'NTLM_WB',
                        'VERSION_SSL': 'SSL',
                        'VERSION_LIBZ': 'libz',
                        'VERSION_UNIX_SOCKETS': 'unix-sockets',
                        'VERSION_KERBEROS5': 'Kerberos',
                        'VERSION_SPNEGO': 'SPNEGO',
                        'VERSION_HTTP2': 'HTTP2',
                        'VERSION_GSSAPI': 'GSS-API',
                        'VERSION_TLSAUTH_SRP': 'TLS-SRP'}
    for i in ('VERSION_IPV6', 'VERSION_KERBEROS4', 'VERSION_KERBEROS5', 'VERSION_SSL', 'VERSION_LIBZ', 'VERSION_NTLM',
              'VERSION_GSSNEGOTIATE', 'VERSION_DEBUG', 'VERSION_CURLDEBUG', 'VERSION_ASYNCHDNS', 'VERSION_SPNEGO',
              'VERSION_LARGEFILE',
              'VERSION_IDN', 'VERSION_SSPI', 'VERSION_GSSAPI', 'VERSION_CONV', 'VERSION_TLSAUTH_SRP', 'VERSION_NTLM_WB',
              'VERSION_HTTP2',
              'VERSION_UNIX_SOCKETS', 'VERSION_PSL', 'VERSION_HTTPS_PROXY', 'VERSION_MULTI_SSL', 'VERSION_BROTLI'):
        if hasattr(pycurl, i):
            if version_info.features & getattr(pycurl, i) != 0:
                features.add(features_mapping.get(i, i))
    version_info.features = features
    return version_info


version_info = set_version_info()


http_versions = {
    '0.9': None,
    '1.0': pycurl.CURL_HTTP_VERSION_1_0,
    '1.1': pycurl.CURL_HTTP_VERSION_1_1,
    '2':   3 # pycurl.CURL_HTTP_VERSION_2
}


def get_header_function(headers):

    # Current header are store in a different dict
    # It will be flushed to real dict headers when an empty line is found
    # Needs because of redirect following, we just keep the last headers seen
    headers_buffer = {}

    def header_function(header_line):
        # HTTP standard specifies that headers are encoded in iso-8859-1.
        header_line = header_line.decode('iso-8859-1').strip()

        # Reached the end-of-headers line, flush the headers buffer
        if len(header_line.strip()) == 0:
            headers.clear()
            headers.update(headers_buffer)
            headers_buffer.clear()
            return

        #Catch the status line, it's the first one
        if not '__STATUS__' in headers_buffer:
            m = status_line_re.fullmatch(header_line.strip())
            if m is not None:
                headers_buffer['__STATUS__'] = m.group('status')
            return

        # Header lines include the first status line (HTTP/1.x ...).
        # We are going to ignore all lines that don't have a colon in them.
        # This will botch headers that are split on multiple lines...
        if ':' not in header_line:
            return

        # Break the header line into header name and value.
        name, value = header_line.split(':', 1)

        # Remove whitespace that may be present.
        # Header lines include the trailing newline, and there may be whitespace
        # around the colon.
        name = name.strip()
        value = value.strip()

        # Header names are case insensitive.
        # Lowercase name here.
        name = name.lower()

        # Now we can actually record the header name and value.
        headers_buffer[name] = value

    return header_function


content_type_re = re.compile("(?P<content_type>.*?); (?:charset=(?P<charset>.*))")


def decode_body(handler):
    encoding = 'UTF-8'
    content_type = None
    if 'content-type' in handler.headers:
        content_type_header = handler.headers['content-type']
    else:
        try:
            content_type_header = handler.get_info(pycurl.CONTENT_TYPE)
        except AttributeError:
            content_type_header = None
    if content_type_header is not None:
        result = content_type_re.match(content_type_header)
        if result is not None:
            encoding = result.group('charset')
            content_type = result.group('content_type')
    if content_type is not None and (content_type.startswith('text') or 'json' in content_type):
        body = handler.buffer.getvalue().decode(encoding, 'replace')
    else:
        body = handler.buffer.getvalue()
    return (content_type, body)


class CurlDebugType(IntEnum):
    TEXT = 1
    HEADER = 2
    DATA = 4
    SSL = 8


def get_curl_debug(debug_filter, logger):
    def _curl_debug(debug_type, data):
        """
        This is the implementation of the cURL debug callback.
        :param debug_type:  what kind of data to debug.
        :param data: the data to debug.
        """

        prefix = {pycurl.INFOTYPE_TEXT: '   ' if CurlDebugType.TEXT & debug_filter else False,
                  pycurl.INFOTYPE_HEADER_IN: '<  ' if CurlDebugType.HEADER & debug_filter else False,
                  pycurl.INFOTYPE_HEADER_OUT: '>  ' if CurlDebugType.HEADER & debug_filter else False,
                  pycurl.INFOTYPE_DATA_IN: '<< ' if CurlDebugType.DATA & debug_filter else False,
                  pycurl.INFOTYPE_DATA_OUT: '>> ' if CurlDebugType.DATA & debug_filter else False,
                  pycurl.INFOTYPE_SSL_DATA_IN: '<S ' if CurlDebugType.SSL & debug_filter else False,
                  pycurl.INFOTYPE_SSL_DATA_OUT: '>S ' if CurlDebugType.SSL & debug_filter else False
                  }[debug_type]
        if prefix is False:
            return

        # Some versions of PycURL provide the debug data as strings, and
        # some as arrays of bytes, so we need to check the type of the
        # provided data and convert it to strings before trying to
        # manipulate it with the "replace", "strip" and "split" methods:
        if not debug_type == pycurl.INFOTYPE_SSL_DATA_IN and not pycurl.INFOTYPE_SSL_DATA_OUT:
            text = data.decode('utf-8', 'replace') if type(data) == bytes else data
        else:
            text = data.decode('unicode_escape', 'replace') if type(data) == bytes else data

        # Split the debug data into lines and send a debug message for
        # each line:
        lines = [x for x in text.replace('\r\n', '\n').split('\n') if len(x) > 0]
        for line in lines:
            if isinstance(logger, Logger):
                logger.debug("%s%s" % (prefix, line))
            else:
                print("%s%s" % (prefix, line), file=logger)
    return _curl_debug


class PyCurlMultiHander(object):

    def __init__(self, max_query=10, loop=get_event_loop()):
        self.loop = loop
        self.multi = pycurl.CurlMulti()
        self.share = pycurl.CurlShare()

        self.share.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_COOKIE)
        self.share.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_COOKIE)
        self.share.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_DNS)
        self.share.setopt(pycurl.SH_SHARE, pycurl.LOCK_DATA_SSL_SESSION)

        self.handles = set()
        self.waiting_handles = Queue(loop=self.loop)
        self.running = True
        self.max_active = max_query

    async def query(self, handle, future):
        def manage_callback(status, headers, data):
            handle.close()
            future.set_result((status, headers, data))

        def failed_callback(ex):
            handle.close()
            future.set_exception(ex)

        handle.cb = manage_callback
        handle.f_cb = failed_callback

        # put the query in the waiting queue, that launch it if possible
        # and wait for the processing to be finished
        await wait((future, self.waiting_handles.put(handle)), loop=self.loop)
        return future

    def close(self):
        self.multi.close()
        self.share.close()

    def _perform_loop(self):
        ret, num_handles = self.multi.perform()
        # libcurl < 6.20 needed this loop (see https://curl.haxx.se/libcurl/c/libcurl-errors.html#CURLMCALLMULTIPERFORM)
        while ret == pycurl.E_CALL_MULTI_PERFORM:
            ret, num_handles = self.multi.perform()
        return ret, num_handles

    async def _try_load_queries(self, wait=True, timeout=1.0):
        added = 0
        while len(self.handles) < self.max_active:
            try:
                if wait:
                    handler = await wait_for(self.waiting_handles.get(), timeout, loop=self.loop)
                else:
                    handler = self.waiting_handles.get_nowait()
                # only wait once
                wait = False
                # needed to keep reference count
                self.handles.add(handler)
                self.multi.add_handle(handler)
                added += 1
            except QueueEmpty:
                break
            except TimeoutError:
                break

        if added > 0:
            ret, num_handles = self._perform_loop()
            if ret > 0:
                raise ConnectionError("pycurl failed", ret)

    async def perform(self, timeout=0.1):
        """
        Loop on waiting handles to process them until they are no more waiting one and all send are finished.
        It's never finished until closed for end of all processing, don't wait for it on loop
        :param timeout: the timeout for the loop
        :return: Nothing
        """
        while self.running:
            if len(self.handles) == 0:
                # no activity, just sleep, for new queries
                await self._try_load_queries(True, timeout)
            else:
                await self._try_load_queries(False)
            if len(self.handles) == 0:
                continue
            # wait for something to happen
            selected = self.multi.select(timeout)
            if selected < 0:
                continue
            # it was not a select time out, something to do
            ret, num_handles = self._perform_loop()
            if ret > 0:
                raise ConnectionError("pycurl failed", ret)
            if len(self.handles) == 0:
                continue
            else:
                # some handles to process
                (waiting, succeded, failed) = self.multi.info_read()
                for handle in succeded:
                    self.handles.remove(handle)
                    self.multi.remove_handle(handle)
                    status = handle.getinfo(pycurl.RESPONSE_CODE)
                    content_type, decoded = decode_body(handle)
                    if not self.running:
                        # is stopped, just swallow content
                        continue
                    elif status >= 200 and status < 300:
                        handle.cb(status, handle.headers, decoded)
                    elif status >= 300:
                        handle.f_cb(NexusException(status, decoded, content_type, http_message=handle.headers.pop('__STATUS__'), url=handle.getinfo(pycurl.EFFECTIVE_URL)))
                for handle, code, message in failed:
                    self.handles.remove(handle)
                    self.multi.remove_handle(handle)
                    ex = ConnectionError(code, message)
                    ex.url = pycurl.EFFECTIVE_URL
                    ex.code = code
                    handle.f_cb(ex)


class PyCurlConnection(object):
    """
     :arg scheme: url scheme to use (default: http)
     :arg host: hostname of the node (default: localhost)
     :arg port: port to use (integer, default: 9200)
     :arg url_prefix: optional url prefix for nexus
     :arg timeout: default timeout in seconds (float, default: 10)
     :arg max_retries:  number of retry in case of non-permanent failures (int, default: 1)
     :arg http_auth: optional http auth information as either ':' separated
          string or a tuple
     :arg kerberos: can use kerberos ticket for authentication
     :arg user_agent: user_agent to use, needed because CAS is picky about that (default: pycurl/nexuslib)
     :arg use_ssl: use ssl for the connection if `True`
     :arg verify_certs: whether to verify SSL certificates
     :arg ssl_opts: a set of options that will be resolved
     :arg debug: activate curl debuging
     :arg debug_filter: sum of curl filters, for debuging
     :arg logger: debug output, can be a file or a logging.Logger (default: stderr)
     """
    ssl_opts_mapping = {
        'ca_certs_directory': pycurl.CAPATH,
        'ca_certs_file': pycurl.CAINFO,
        'cert_file': pycurl.SSLCERT,
        'cert_type': pycurl.SSLCERTTYPE,
        'key_file': pycurl.SSLKEY,
        'key_type': pycurl.SSLKEYTYPE,
        'key_password': pycurl.KEYPASSWD,
    }

    def __init__(self,
                 scheme='http', host='localhost', port=443, url_prefix='', timeout=10, max_retries=1,
                 multi_handle=None, loop=None, max_active=1, curl_perform_task=None,
                 http_auth=None, http_version=None, kerberos=False, user_agent="pycurl/nexuslib",
                 use_ssl=False, verify_certs=False, ssl_opts={},
                 debug=False, debug_filter=CurlDebugType.HEADER + CurlDebugType.DATA, logger=sys.stderr):
        self.retry_on_status = (502, 503, 504,)
        self.loop = loop
        if multi_handle is None:
            self.multi_handle = PyCurlMultiHander(max_active, loop=self.loop)
            self.curl_perform_task = ensure_future(self.multi_handle.perform(), loop=self.loop)
        else:
            self.multi_handle = multi_handle
            self.curl_perform_task = curl_perform_task
        self.max_retries = max_retries

        self.verify_certs = verify_certs
        self.ssl_opts = {}
        # Ensure consistenty of use_ssl and scheme
        if use_ssl or scheme == 'https':
            scheme = 'https'
            self.use_ssl = True
            for k, v in ssl_opts.items():
                if k in PyCurlConnection.ssl_opts_mapping and v is not None:
                    self.ssl_opts[PyCurlConnection.ssl_opts_mapping[k]] = v
        else:
            scheme = 'http'
            self.use_ssl = False
        self.host = '%s://%s:%s' % (scheme, host, port)
        self.url_prefix = '/' + url_prefix.strip('/')
        self.timeout = timeout
        self.kerberos = kerberos
        if isinstance(http_auth, tuple):
            self.http_auth = ':'.join(http_auth)
        else:
            self.http_auth = http_auth
        self.user_agent = user_agent
        if http_version is not None and http_version in http_versions:
            self.http_version = http_versions[http_version]
        else:
            self.http_version = None
        if debug:
            self.debug = True
            self.debug_filter = get_curl_debug(debug_filter, logger)
        else:
            self.debug = False

    def _get_curl_handler(self, headers):
        handle = pycurl.Curl()

        settings = {
            pycurl.USERAGENT: self.user_agent,
            pycurl.ACCEPT_ENCODING: None if self.debug else "",
            pycurl.TIMEOUT: self.timeout,
            #pycurl.NOSIGNAL: True,
            # We manage ourself our buffer, Help from Nagle is not needed
            pycurl.TCP_NODELAY: 1,
            pycurl.TCP_KEEPALIVE: 1,
            # Don't keep persistent data
            pycurl.COOKIEFILE: '/dev/null',
            pycurl.COOKIEJAR: '/dev/null',
            pycurl.SHARE: self.multi_handle.share,

            # Follow redirect but not too much, it's needed for CAS
            pycurl.FOLLOWLOCATION: True,
            pycurl.MAXREDIRS: 5,

            # Needed for CAS login
            pycurl.UNRESTRICTED_AUTH: True,
            pycurl.POSTREDIR: pycurl.REDIR_POST_ALL,
        }

        if self.use_ssl:
            # Strict TLS check
            if self.verify_certs:
                settings.update({
                    pycurl.SSL_VERIFYPEER: 1,
                    pycurl.SSL_VERIFYHOST: 2,
                })
                # If security is wanted, nothing less that TLS v1.2 is accepted, but only for curl  > 7.34.0
                if version_info.version_num >= 0x072200:
                    settings[pycurl.SSLVERSION] = pycurl.SSLVERSION_TLSv1_2
            else:
                settings.update({
                    pycurl.SSL_VERIFYPEER: 0,
                    pycurl.SSL_VERIFYHOST: 0,
                })
            settings.update(self.ssl_opts)

        if self.kerberos and 'GSS-API' in version_info.features:
            settings.update({
                pycurl.HTTPAUTH: pycurl.HTTPAUTH_NEGOTIATE,
                pycurl.USERPWD: ':'
            })
        elif self.http_auth is not None:
            settings[pycurl.USERPWD] = self.http_auth

        if self.http_version is not None:
            settings[pycurl.HTTP_VERSION] = self.http_version

        # Debug setup
        if self.debug:
            settings.update({
                pycurl.VERBOSE: self.debug,
                pycurl.DEBUGFUNCTION: self.debug_filter
            })

        for key, value in settings.items():
            try:
                handle.setopt(key, value)
            except TypeError as e:
                print(e, key, value)

        # Prepare headers:
        default_headers = {
            'Connection': 'Keep-Alive',
            'Expect': '',
            'Accept': '',
        }
        if headers is not None:
            default_headers.update(headers)
        header_lines = ["%s: %s" % (k, v) for (k, v) in default_headers.items()]
        handle.setopt(pycurl.HTTPHEADER, header_lines)

        return handle

    def _perform_request(self, method, url, params=None, body=None, headers={}, ignore=(), future=None):
        url = self.url_prefix + url
        if params is not None:
            url = '%s?%s' % (url, urlencode(params))
        full_url = self.host + url
        curl_handle = self._get_curl_handler(headers)
        curl_handle.setopt(pycurl.URL, full_url)

        if method == 'HEAD':
            curl_handle.setopt(pycurl.NOBODY, True)

        # Prepare the headers callback
        curl_handle.headers = {}
        curl_handle.setopt(pycurl.HEADERFUNCTION, get_header_function(curl_handle.headers))

        # Prepare the body buffer
        curl_handle.buffer = BytesIO()
        curl_handle.setopt(pycurl.WRITEDATA, curl_handle.buffer)

        # The possible body of a request
        if body is not None:
            curl_handle.setopt(pycurl.UPLOAD, 1)
            curl_handle.setopt(pycurl.READDATA, body)

        # Set after pycurl.POSTFIELDS to ensure that the request is the wanted one
        curl_handle.setopt(pycurl.CUSTOMREQUEST, method)
        if future is not None:
            curl_handle.connection = self
            return self.multi_handle.query(curl_handle, future)
        else:
            start = time.time()
            curl_handle.perform()
            duration = time.time() - start

            status = curl_handle.getinfo(pycurl.RESPONSE_CODE)
            curl_handle.close()

            (content_type, body) = decode_body(curl_handle)
            if not (200 <= status < 300) and status not in ignore:
                self.log_request_fail(method, full_url, url, body, duration, status)
                http_message = curl_handle.headers.pop('__STATUS__')
                raise NexusException(status, body, content_type, http_message)

            self.log_request_success(method, full_url, url, curl_handle.buffer.getvalue(), status,
                                     body, duration)

            return status, curl_handle.headers, body

    def __repr__(self):
        return '<%s: %s:%d>' % (self.__class__.__name__, self.host, self.port)

    def perform_async_request(self, future, method, url, headers=None, params=None, body=None):
        """
        Perform the actual request. Retrieve a connection from the connection
        pool, pass all the information to it's perform_request method and
        return the data.

        If an exception was raised, mark the connection as failed and retry (up
        to `max_retries` times).

        If the operation was succesful and the connection used was previously
        marked as dead, mark it as live, resetting it's failure count.

        :arg future: a async future that will store the request result
        :arg method: HTTP method to use
        :arg url: absolute url (without host) to target
        :arg headers: dictionary of headers, will be handed over to the
            underlying :class:`~elasticsearch.Connection` class
        :arg params: dictionary of query parameters, will be handed over to the
            underlying :class:`~elasticsearch.Connection` class for serialization
        :arg body: body of the request, will be serializes using serializer and
            passed to the connection
        """
        ignore = ()
        if params:
            ignore = params.pop('ignore', ())
            if isinstance(ignore, int):
                ignore = (ignore, )

        for attempt in range(self.max_retries + 1):
            future_result = yield (method, url, params, body, headers, ignore)
            # The first yield used to return params return with no future_result, so skip it
            if future_result is None:
                continue

            try:
                status, headers_out, data = future_result()
            except Exception as e:
                if method == 'HEAD' and e.status_code == 404:
                    future.set_result((False, e.status_code))
                    break
                retry = False
                if isinstance(e, ConnectionError):
                    retry = True
                elif e.status_code in self.retry_on_status:
                    retry = True

                if retry:
                    # raise exception on last retry
                    if attempt == self.max_retries:
                        future.set_exception(e)
                        break
                else:
                    future.set_exception(e)
                    break
            else:
                if method == 'HEAD':
                    future.set_result((200 <= status < 300, status))
                else:
                    try:
                        #if data:
                        #    data = self.deserializer.loads(data, headers_out.get('content-type'))
                        future.set_result((data, status))
                    except Exception as e:
                        future.set_exception(e)
                break

    async def perform_request(self, method, uri, headers=None, params=None, body=None):
        futur_result = Future(loop=self.loop)
        query_iterator = self.perform_async_request(futur_result, method, uri, headers, params, body)
        (next_method,
         next_url,
         next_params,
         next_body,
         next_headers,
         ignore) = query_iterator.send(None)
        while True:
            curl_future = Future(loop=self.loop)
            await self._perform_request(method, next_url, next_params, next_body,
                                                       headers=next_headers,
                                                       ignore=ignore, future=curl_future)
            try:
                (next_method,
                 next_url,
                 next_params,
                 next_body,
                 next_headers,
                 ignore) = query_iterator.send(curl_future.result)
            except StopIteration:
                break
        return futur_result.result()


