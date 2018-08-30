#  nexusupload
  
nexusupload is a tool that allows rpm upload to [Sonatype's Nexus 3](https://www.sonatype.com/nexus-repository-oss).

Sonatype provides a cool API for that, but I needed to add a few features:

 - Autogenerate the path, by resolving the type of RPM (source, debuginfo, architecture...)
 - I'm using SSO that mix [CAS](https://www.apereo.org/projects/cas) and kerberos that make the use of a simple curl command quite complexe.

So this tools is made to solve that problems. It also uses asyncio that allows parallel uploads of RPMS.

The usage is:

```
Usage: nexusupload [options] rpmfiles*

Options:
-h, --help        show this help message and exit
-c CONFIG_FILE, --config=CONFIG_FILE
                   An alternative config file
-d, --debug        The debug level
--passwordfile=PASSWORDFILE
                   Read the password from that file
-u USERNAME, --user=USERNAME, --username=USERNAME
                   User to authenticate
-k, --kerberos     Uses kerberos authentication
-U URL, --url=URL  URL to connect to
-n, --noop          Check, don't upload
```

If the config file is not specified, nexusupload will look it in the NEXUSCONFIG environment variable.

If missing it will uses default values, but of course the URL must be explicitely given.

The config file is a ini file, with default values being:

```
[connection]
url=None
username=None
password=None
debug=False
kerberos=False
user_agent=nexusupload/pycurl
max_active=10      # The maximum number of parallel uploads
timeout=10

[logging]
# pycurl logging
filters = header,data,text

[kerberos]
it can use a keytab
ccache=None
keytab=None
principal=None

[ssl]
# All this value are given to curl if defined
ca_certs_directory=None
ca_certs_file=None
verify_certs=True
cert_file=None
cert_type=None
key_file=None
key_type=None
key_password=None

[pycurl]
# Used to override curl and pycurl default dynamic libraries
libcurl_path=None
pycurl_path=None
```

## CURL and PyCurl libraries

Some distribution provides quite old curl and pycurl with missing features, like TLSv1.2 and 
SPNEGO. nexusupload provides a simple mecanism to override that and use custom version.

This works because they are both dynamic libraries and preloading them prevents python to use 
the defaults one.

For example, the pycurl section can be written as:
```
[pycurl]
libcurl_path=/opt/local/lib64/libcurl.so.4
pycurl_path=/opt/local/lib64/python3.4/site-packages/pycurl.cpython-34m.so
```

The python code doing the trick is a very simple:
```
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
```

## TODO

The pattern for the paths is hard coded and they are at this time:
 - `/SRPMS/$MAJOR/file` for source RPMS
 - `/Packages/$MAJOR/$arch/file` for packages RPMS
 - `/debug/$MAJOR/file` for debuginfo RPMS
 
There is no delete support. It's still need to be done using the web interface.
 
The pycurlconnection.py is overcomplicated, it should be simplified.
