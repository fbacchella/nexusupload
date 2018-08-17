#!/usr/bin/env python

import os
import sys
import re
from os.path import basename
from optparse import OptionParser
from nexuslib.context import Context, ConfigurationError
import rpmfile

rpm_re = re.compile("""^.*-([\.\d]+)(\.(rh)?el(?P<version>\d)(u\d)?)?\.(?P<arch>[^\.]+)\.rpm$""")
def main():

    default_config = None
    if 'NEXUSCONFIG' in os.environ:
        default_config = os.environ['NEXUSCONFIG']

    usage_common = "usage: %prog [options] files*"
    #The first level parser
    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config_file", help="an alternative config file", default=default_config)
    parser.add_option("-d", "--debug", dest="debug", help="The debug level", action="store_true")
    parser.add_option("--passwordfile", dest="passwordfile", help="Read the password from that file")
    parser.add_option("-u", "--user", "--username", dest="username", help="User to authenticate")
    parser.add_option("-k", "--kerberos", dest="kerberos", help="Uses kerberos authentication", action='store_true')
    parser.add_option("-U", "--url", dest="url", help="URL to connect to", default=None)
    parser.add_option("-n", "--noop", dest="doop", help="Check, don't upload", default=True, action='store_false')

    (options, args) = parser.parse_args()

    #Extract the context options from the first level arguments
    context_args = {k: v for k, v in list(vars(options).items()) if v is not None}
    context = None
    valid_archs=set(['src', 'x86_64', 'noarch', 'i686', 'i586', 'i386'])
    print(valid_archs)
    try:
        context = Context(**context_args)
        context.connect()
        for f in args:
            splited = f.split(';')
            file = splited[0]
            if len(splited) == 2:
                rpm_name = basename(splited[1])
            else:
                rpm_name = basename(file)
            try:
                with rpmfile.open(file) as rpm:
                    # Inspect the RPM headers print rpm.headers.keys()
                    arch = rpm.headers.pop('arch', None).decode('us-ascii')
                    name = rpm.headers.pop('name', None).decode('us-ascii')
                    version = rpm.headers.pop('version', None).decode('us-ascii')
                    release = rpm.headers.pop('release', None).decode('us-ascii')
                    # Extract a fileobject from the archive fd = rpm.extractfile(‘./usr/bin/script’) print fd.read()
                    debuginfo = False
                    source = False
                    for i in rpm.headers.pop('provides', []):
                        if '-debuginfo' in i.decode('us-ascii'):
                            debuginfo = True
                            break
                    if 'source' in rpm.headers:
                        source = True
                    #for k,v in rpm.headers.items():
                    #    print(k, v)
                    print("%s %s %s %s.%s.rpm %s %s"% (file, name, version, release, arch, debuginfo, source))
            except Exception as e:
                print(file, e)
            continue
            rpm_matcher = rpm_re.fullmatch(rpm_name, file=sys.stderr)
            if rpm_matcher is None:
                print('not a matching rpm: "%s", not matching' % rpm_name, file=sys.stderr)
                continue
            (version, arch) = rpm_matcher.group('version', 'arch')
            if arch is None or arch not in valid_archs:
                print('not a matching rpm: "%s", invalid architecture %s' % (rpm_name, arch), file=sys.stderr)
            if arch == 'src':
                rpm_type ='sources'
                arch=''
            elif '-debuginfo-' in rpm_name:
                rpm_type = 'debug'
                arch = "/%s" % arch
            else:
                rpm_type = 'packages'
                arch = "/%s" % arch
            if version is None:
                versions=(5,6,7)
            else:
                versions =(version)
            for v in versions:
                dest = '/%s/%s%s/%s' % (rpm_type, v, arch, rpm_name)
                print(file, dest)
                if options.doop:
                    with open(file, 'rb') as rpm_file:
                        context.perform_query(context.nexuscnx.perform_request('PUT', dest, body=rpm_file))
    except ConfigurationError as e:
        print(e.error_message, file=sys.stderr)
        return 253
    finally:
        if context is not None:
            context.disconnect()