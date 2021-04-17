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
            if rpm_file is not None:
                rpm_file.close()
        except Exception as ex2:
            print(dest, ex2)
    return done_cb


def get_check_cb(rpm_file_name, dest):
    def done_cb(f):
        ex = f.exception()
        if ex is None:
            result = f.result()
            # try with HEAD mean 200 -> already exists
            if result:
                print(rpm_file_name, '->', dest, 'already exists')
            else:
                print(rpm_file_name, '->', dest, 'to be uploaded')
        else:
            print(dest, 'failed with', ex)
    return done_cb


def upload(*args, context=None, doop=False):
    valid_archs=set(['x86_64', 'noarch', 'i686', 'i586', 'i386'])
    major_re = re.compile(""".*(\.|_|-)(rh)?el(?P<version>\d)(u\d)?.*""")
    filename_re = re.compile(""".*?((\.|_|-)(rh)?el(?P<osmajor>\d)(u\d+)?)?(\.centos)?\.(?P<filearch>[_0-9a-z]+)\.rpm""")
    rpm_info_re = re.compile("""(?P<version>\d+)|debuginfo|(?P<arch>[_0-9a-z]+)""")
    tasks = set()
    for rpm_file_info in args:
        rpm_file_infos = rpm_file_info.split(';')
        rpm_file_name = rpm_file_infos[0]
        rpm_good_file_infos = True
        centos_version = []
        filearch = None
        debuginfo = False
        for i in rpm_file_infos[1:]:
            rpm_info_match = rpm_info_re.fullmatch(i)
            if rpm_info_match is None:
                print('invalid rpm info "%s"' % rpm_file_info, file=sys.stderr)
                rpm_good_file_infos = False
                break
            else:
                add_version = rpm_info_match.group('version')
                new_filearch = rpm_info_match.group('arch')
                if add_version is not None:
                    centos_version.append(add_version)
                elif new_filearch is not None:
                    filearch = new_filearch
                elif i == 'debuginfo':
                    debuginfo = True

        if not rpm_good_file_infos:
            continue
        try:
            with rpmfile.open(rpm_file_name) as rpm:
                filename_match = filename_re.fullmatch(basename(rpm_file_name))

                # Returned as bytes, ensure it' a str or None
                for key in ('arch', 'release', 'version', 'release'):
                    if key in rpm.headers:
                        if isinstance(rpm.headers[key], bytes):
                            rpm.headers[key] = rpm.headers[key].decode('us-ascii', 'replace')
                    else:
                        rpm.headers[key] = None
                # the explicit filearch given in the command line wins
                if filearch is None and filename_match is not None:
                    filearch = filename_match.group('filearch')
                arch = rpm.headers['arch']
                # If the centos_version was not explicit, try to resolve from version or release
                if len(centos_version) == 0:
                    for try_major in ('version', 'release'):
                        major_match = major_re.fullmatch(rpm.headers[try_major])
                        if major_match is not None:
                            centos_version = (major_match.group('version'), )
                            break
                # The rhel version is not always in the release or the version name
                # Sometimes, it's in the file name
                if len(centos_version) == 0 and filename_match is not None and filename_match.group('osmajor') is not None:
                    centos_version = (filename_match.group('osmajor'), )
                for i in map(lambda x: x.decode('us-ascii', 'replace'), rpm.headers.get('provides', [])):
                    if i is not None and '-debuginfo' in i:
                        debuginfo = True
                        break
                for i in map(lambda x: x.decode('us-ascii', 'replace'), rpm.headers.get(1118, [])):
                    if i == '/usr/lib/debug/.build-id/':
                        debuginfo = True
                        break
                if 'source' in rpm.headers or filearch == 'src':
                    source = True
                else:
                    source = False
        except IsADirectoryError as e:
            continue
        except AssertionError as e:
            print('invalid rpm "%s"' % rpm_file_name, file=sys.stderr)
            continue
        except Exception as e:
            print('invalid rpm "%s"' % rpm_file_name, e, file=sys.stderr)
            continue
        if source and debuginfo:
            print('can\'t be both a source and a debuginfo rpm')
            continue
        if not source and (arch is None or arch not in valid_archs):
            print('not a matching rpm: "%s", invalid architecture %s' % (rpm_file_name, arch), file=sys.stderr)
            continue
        if source:
            rpm_type = 'SRPMS'
            arch = ''
        elif debuginfo:
            rpm_type = 'debug'
            arch = "/%s" % arch
        else:
            rpm_type = 'Packages'
            arch = "/%s" % arch
        if centos_version == None:
            print('invalid rpm "%s"' % rpm_file_name, file=sys.stderr)
            continue
        if len(centos_version) == 0:
            centos_version = (5, 6, 7, 8)
        for v in centos_version:
            dest = '/%s/%s%s/%s' % (rpm_type, v, arch, basename(rpm_file_name))
            if doop:
                rpm_file = open(rpm_file_name, 'rb')
                request = context.nexuscnx.perform_request('PUT', dest,
                                                           body=rpm_file, headers={'Content-Type': 'application/x-rpm'})
                done_cb = get_done_cb(dest, rpm_file)
            else:
                request = context.nexuscnx.perform_request('HEAD', dest)
                done_cb = get_check_cb(rpm_file_name, dest)
            op_future = asyncio.ensure_future(request, loop=context.loop)
            op_future.add_done_callback(done_cb)
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