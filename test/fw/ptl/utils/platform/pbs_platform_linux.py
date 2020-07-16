# coding: utf-8

# Copyright (C) 1994-2020 Altair Engineering, Inc.
# For more information, contact Altair at www.altair.com.
#
# This file is part of both the OpenPBS software ("OpenPBS")
# and the PBS Professional ("PBS Pro") software.
#
# Open Source License Information:
#
# OpenPBS is free software. You can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# OpenPBS is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
# License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Commercial License Information:
#
# PBS Pro is commercially licensed software that shares a common core with
# the OpenPBS software.  For a copy of the commercial license terms and
# conditions, go to: (http://www.pbspro.com/agreement.html) or contact the
# Altair Legal Department.
#
# Altair's dual-license business model allows companies, individuals, and
# organizations to create proprietary derivative works of OpenPBS and
# distribute them - whether embedded or bundled with other software -
# under a commercial license agreement.
#
# Use of Altair's trademarks, including but not limited to "PBS™",
# "OpenPBS®", "PBS Professional®", and "PBS Pro™" and Altair's logos is
# subject to Altair's trademark licensing policies.

import copy
import grp
import logging
import os
import platform
import pwd
import re
import socket
import stat
import sys
import tempfile
import traceback
from subprocess import PIPE, Popen


class PBSPlatform(object):

    _h2osinfo = {}  # host to OS info cache
    _h2p = {}  # host to platform cache
    _h2pu = {}  # host to uname cache
    _h2c = {}  # host to pbs_conf file cache
    _h2l = {}  # host to islocal cache
    _h2which = {}  # host to which cache

    def get_dflt_pbs_conf(self, hostname=None):
        return '/etc/pbs.conf'

    def get_dflt_python(self, hostname=None):
        return '/opt/pbs/python/bin/python'

    def get_environment_file(self, hostname=None):
        """
        Initialize pbs_conf dictionary by parsing pbs config file
        """
        return '/var/spool/pbs/pbs_environment'

    def get_default_tempdir(self, hostname=None):
        """
        :returns: The temporary directory on the given host
                  Default host is localhost.
        """
        return '/tmp'

    def run_cmd(self, hostname, cmd, sudo, stdin,
                stdout, stderr, input, cwd, env,
                runas, logerr, as_script, wait_on_script,
                level, port, platform, dshutilObject, timoutObject,
                user, runas_user):

        rshcmd = []
        sudocmd = []
        ret = {'out': '', 'err': '', 'rc': 0}

        if (platform == "shasta") and runas_user:
            hostname = runas_user.host if runas_user.host else hostname
            port = runas_user.port
        islocal = dshutilObject.is_localhost(hostname)
        if islocal is None:
            # an error occurred processing that name, move on
            # the error is logged in is_localhost.
            ret['err'] = 'error getting host by name in run_cmd'
            ret['rc'] = 1
            return ret
        if not islocal:
            if port and platform == "shasta":
                if runas is None:
                    user = user
                else:
                    user = runas_user.name
                rshcmd = dshutilObject.rsh_cmd + \
                    ['-p', port, user + '@' + hostname]
            else:
                rshcmd = dshutilObject.rsh_cmd + [hostname]
        if platform != "shasta":
            if sudo or ((runas is not None) and (runas != user)):
                sudocmd = copy.copy(dshutilObject.sudo_cmd)
                if runas is not None:
                    sudocmd += ['-u', runas]

        # Initialize information to return
        ret = {'out': None, 'err': None, 'rc': None}
        rc = rshcmd + sudocmd + cmd
        if as_script:
            _script = dshutilObject.create_temp_file()
            script_body = ['#!/bin/bash']
            if cwd is not None:
                script_body += ['cd "%s"' % (cwd)]
                cwd = None
            if isinstance(cmd, str):
                script_body += [cmd]
            elif isinstance(cmd, list):
                script_body += [" ".join(cmd)]
            with open(_script, 'w') as f:
                f.write('\n'.join(script_body))
            os.chmod(_script, 0o755)
            if not islocal:
                # TODO: get a valid remote temporary file rather than
                # assume that the remote host has a similar file
                # system layout
                dshutilObject.run_copy(hostname, src=_script, dest=_script,
                                       runas=runas, level=level)
                os.remove(_script)
            runcmd = rshcmd + sudocmd + [_script]
        else:
            runcmd = rc

        _msg = hostname.split('.')[0] + ': '
        _runcmd = ['\'\'' if x == '' else str(x) for x in runcmd]
        _msg += ' '.join(_runcmd)
        _msg = [_msg]

        if as_script:
            _msg += ['Contents of ' + _script + ':']
            _msg += ['-' * 40, '\n'.join(script_body), '-' * 40]
        dshutilObject.logger.log(level, '\n'.join(_msg))
        if input:
            dshutilObject.logger.log(level, input)

        try:
            p = Popen(runcmd, bufsize=-1, stdin=stdin, stdout=stdout,
                      stderr=stderr, cwd=cwd, env=env)
        except Exception as e:
            dshutilObject.logger.error("Error running command " + str(runcmd))
            if as_script:
                dshutilObject.logger.error('Script contents: \n' +
                                           '\n'.join(script_body))
            dshutilObject.logger.debug(str(e))
            raise

        if as_script and not wait_on_script:
            o = p.stdout.readline()
            e = p.stderr.readline()
            ret['rc'] = 0
        else:
            try:
                (o, e) = p.communicate(input)
            except timoutObject:
                dshutilObject.logger.error("TimeOut Exception, cmd:%s" %
                                           str(runcmd))
                raise
            ret['rc'] = p.returncode

        if as_script:
            # must pass as_script=False otherwise it will loop infinite
            if platform == 'shasta' and runas:
                dshutilObject.rm(hostname, path=_script, as_script=False,
                                 level=level, runas=runas)
            else:
                dshutilObject.rm(hostname, path=_script, as_script=False,
                                 level=level)

        # handle the case where stdout is not a PIPE
        if o is not None:
            ret['out'] = [i.decode("utf-8", 'backslashreplace')
                          for i in o.splitlines()]
        else:
            ret['out'] = []
        # Some output can be very verbose, for example listing many lines
        # of a log file, those messages are typically channeled through
        # at level DEBUG2, since we don't to pollute the output with too
        # verbose an information, we log at most at level DEBUG
        if level < logging.DEBUG:
            dshutilObject.logger.log(level, 'out: ' + str(ret['out']))
        else:
            dshutilObject.logger.debug('out: ' + str(ret['out']))
        if e is not None:
            ret['err'] = [i.decode("utf-8", 'backslashreplace')
                          for i in e.splitlines()]
        else:
            ret['err'] = []
        if ret['err'] and logerr:
            dshutilObject.logger.error('err: ' + str(ret['err']))
        else:
            dshutilObject.logger.debug('err: ' + str(ret['err']))
        dshutilObject.logger.debug('rc: ' + str(ret['rc']))

        return ret

    def get_local_copy_cmd(self, hostname, preserve_permission, recursive):

        cmd = ['cp']
        if preserve_permission:
            cmd += ['-p']
        if recursive:
            cmd += ['-r']
        return cmd

    def get_remote_copy_cmd(self, hostname, copy_cmd,
                            preserve_permission, recursive):

        if not copy_cmd:
            cmd = ['scp', '-p']
        else:
            cmd = copy_cmd

    def list_file_dir_cmd(self, hostname=None):
        cmd = ['ls', '-l']
        return cmd

    def get_wrappers_dir(self, hostname=None):
        return '/opt/tools/wrappers'

    def get_executable_path_cmd(self, hostname=None):
        return 'which'

    def get_delete_cmd(self, hostname=None, recursive=False, force=False):
        cmd = ['rm']
        if recursive:
            cmd += ['-r']
        if force:
            cmd += ['-f']
        return cmd

    def get_cat_cmd(self, hostname=None, option=None):
        cmd = ['cat']
        if option:
            cmd += [option]
        return cmd

    def get_compare_cmd(self, hostname=None):
        return 'cmp'
