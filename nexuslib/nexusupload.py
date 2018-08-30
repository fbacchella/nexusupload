#!/usr/bin/env python

import os
import sys
import re
from os.path import basename
from optparse import OptionParser
from nexuslib.context import Context, ConfigurationError
from nexuslib.exceptions import NexusException
import rpmfile
import asyncio


def get_done_cb(dest, rpm_file):
    def done_cb(f):
        ex = f.exception()
        if ex is None:
            print(dest, 'uploaded')
        else:
            print(dest, 'failed with', ex)
        try:
            rpm_file.close()
        except Exception as ex2:
            print(dest, ex2)
    return done_cb

def upload(*args, context=None, doop=False):
    valid_archs=set(['x86_64', 'noarch', 'i686', 'i586', 'i386'])
    release_re = re.compile(""".*(\.|_)(rh)?el(?P<version>\d)(u\d)?.*""")

    tasks = set()
    for rpm_file_name in args:
        try:
            with rpmfile.open(rpm_file_name) as rpm:
                # Returned as bytes, ensure it' a str
                for key in ('arch', 'release'):
                    if key in rpm.headers:
                        rpm.headers[key] = rpm.headers[key].decode('us-ascii')
                    else:
                        rpm.headers[key] = None
                arch = rpm.headers.pop('arch')
                release = rpm.headers.pop('release')
                release_match = release_re.fullmatch(release)
                if release_match is not None:
                    centos_version = release_match.group('version')
                else:
                    centos_version = ''
                debuginfo = False
                for i in rpm.headers.pop('provides', []):
                    if '-debuginfo' in i.decode('us-ascii'):
                        debuginfo = True
                        break
                if 'source' in rpm.headers:
                    source = True
                else:
                    source = False
        except Exception as e:
            print('invalid rpm "%s' % rpm_file_name, type(e), file=sys.stderr)
            continue
        if not source and (arch is None or arch not in valid_archs):
            print('not a matching rpm: "%s", invalid architecture %s' % (rpm_file_name, arch), file=sys.stderr)
        if source:
            rpm_type = 'SRPMS'
            arch = ''
        elif debuginfo:
            rpm_type = 'debug'
            arch = "/%s" % arch
        else:
            rpm_type = 'Packages'
            arch = "/%s" % arch
        if centos_version is None or len(centos_version) == 0:
            versions = (5, 6, 7)
        else:
            versions = (centos_version)
        for v in versions:
            dest = '/%s/%s%s/%s' % (rpm_type, v, arch, basename(rpm_file_name))
            if doop:
                rpm_file = open(rpm_file_name, 'rb')
                request = context.nexuscnx.perform_request('PUT', dest,
                                                           body=rpm_file, headers={'Content-Type': 'application/x-rpm'})
                op_future = asyncio.ensure_future(request, loop=context.loop)
                op_future.add_done_callback(get_done_cb(dest, rpm_file))
                tasks.add(op_future)
                if len(tasks) > 10:
                    timeout = None
                else:
                    timeout = 0
                done, tasks = yield from asyncio.wait(tasks, timeout=timeout, loop=context.loop,
                                                        return_when=asyncio.FIRST_COMPLETED)
                for i in done:
                    try:
                        i.result()
                    except NexusException:
                        pass
            else:
                print(rpm_file_name, '->', dest)
    if len(tasks) != 0:
        done, tasks = yield from asyncio.wait(tasks, timeout=None, loop=context.loop,
                                              return_when=asyncio.ALL_COMPLETED)
        for i in done:
            try:
                i.result()
            except NexusException:
                pass


def main():

    default_config = None
    if 'NEXUSCONFIG' in os.environ:
        default_config = os.environ['NEXUSCONFIG']

    parser = OptionParser(usage="usage: %prog [options] rpmfiles*")
    parser.add_option("-c", "--config", dest="config_file", help="An alternative config file", default=default_config)
    parser.add_option("-d", "--debug", dest="debug", help="The debug level", action="store_true")
    parser.add_option("--passwordfile", dest="passwordfile", help="Read the password from that file")
    parser.add_option("-u", "--user", "--username", dest="username", help="User to authenticate")
    parser.add_option("-k", "--kerberos", dest="kerberos", help="Uses kerberos authentication", action='store_true')
    parser.add_option("-U", "--url", dest="url", help="URL to connect to", default=None)
    parser.add_option("-n", "--noop", dest="doop", help="Check, don't upload", default=True, action='store_false')

    (options, args) = parser.parse_args()

    #Extract the context options from the options
    context_args = {k: v for k, v in list(vars(options).items()) if v is not None}
    context = None
    try:
        context = Context(**context_args)
        context.connect()
        context.loop.run_until_complete(upload(*args, context=context, doop=options.doop))
    except ConfigurationError as e:
        print(e.error_message, file=sys.stderr)
        return 253
    finally:
        if context is not None:
            context.disconnect()