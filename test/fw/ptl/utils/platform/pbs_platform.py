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

import os
import importlib
import copy
import sys
import socket
from subprocess import PIPE, Popen


class PlatformSwitch():

    _p2o = {}  # platform to object cache
    _h2p = {}

    def get_platform_object(self, hostname=None, platform=None):
        if platform is not None:
            plat = platform
        else:
            plat = self.get_platform(hostname)

        # print("PLATFORM: "+str(plat))
        # print("HOSTNAME: "+str(hostname))

        if plat in self._p2o:
            return self._p2o[plat]

        dir_path = os.path.dirname(os.path.realpath(__file__))

        for f in os.listdir(dir_path):  # change file
            if f.startswith("_") or not f.endswith(".py"):
                continue
            if f == __file__:
                continue
            file_platform = f.split("_")[-1].split(".")[0]

            if file_platform != plat:
                continue

            p = f.rsplit(".", 1)[0]  # replace
            mod = importlib.import_module('ptl.utils.platform.' + p)
            self._p2o[file_platform] = getattr(mod, "PBSPlatform")()
            return self._p2o[file_platform]

        print("No platform file found")
        print("h2p")
        print(self._h2p)
        print("pto")
        print(self._p2o)
        print("HOSTNAME: "+str(hostname))
        print("PLATFORM: "+str(plat))

    def get_platform(self, host=None):

        if host is None:
            host = socket.gethostname()

        if host in self._h2p:
            return self._h2p[host]

        if socket.getfqdn(host) in self._h2p:
            return self._h2p[socket.getfqdn(host)]

        is_localhost = False
        try:
            (hostname, aliaslist, iplist) = socket.gethostbyname_ex(host)
        except BaseException:
            self.logger.error('error getting host by name: ' + host)
            print((traceback.print_stack()))
            return None

        localhost = socket.gethostname()
        if localhost == hostname or localhost in aliaslist:
            is_localhost = True

        try:
            ipaddr = socket.gethostbyname(localhost)
        except BaseException:
            self.logger.error('could not resolve local host name')
            is_localhost = False
        if ipaddr in iplist:
            is_localhost = True

        if is_localhost is True:
            self._h2p[host] = sys.platform
            return self._h2p[host]
        else:
            cmd = ['python3', '-c', '"import sys; print(sys.platform)"']
            rshcmd = ['ssh', host]
            sudocmd = ['sudo', '-H']
            ret = {'out': None, 'err': None, 'rc': None}
            rc = rshcmd + sudocmd + cmd

            try:
                p = Popen(rc, bufsize=-1, stdin=PIPE, stdout=PIPE,
                          stderr=PIPE, cwd=None, env=None)
            except Exception as e:
                # self.logger.error("Error running command " + str(runcmd))
                # self.logger.debug(str(e))
                raise

            try:
                (o, e) = p.communicate()
            except TimeOut:
                # self.logger.error("TimeOut Exception, cmd:%s" %
                #                  str(runcmd))
                raise
            ret['rc'] = p.returncode

            if o is not None:
                ret['out'] = [i.decode("utf-8", 'backslashreplace')
                              for i in o.splitlines()]
                self._h2p[host] = ret['out'][0]
                return self._h2p[host]
            else:
                ret['out'] = []

            if e is not None:
                ret['err'] = [i.decode("utf-8", 'backslashreplace')
                              for i in e.splitlines()]
            else:
                ret['err'] = []

            # need to implement for remote hosts

        return None

    def get_dflt_pbs_conf(self, hostname=None):

        return self.get_platform_object(hostname).get_dflt_pbs_conf(hostname)

    def get_dflt_python(self, hostname=None):

        return self.get_platform_object(hostname).get_dflt_python(hostname)

    def get_pbs_conf_file(self, hostname=None, is_localhost=True):
        """
        Get the path of the pbs conf file. Defaults back to
        ``/etc/pbs.conf`` if unsuccessful

        :param hostname: Hostname of the machine
        :type hostname: str or None
        :returns: Path to pbs conf file
        """
        return self.get_platform_object(
            hostname).get_pbs_conf_file(hostname, is_localhost)

    def get_environment_file(self, hostname=None):
        """
        Initialize pbs_conf dictionary by parsing pbs config file
        """
        return self.get_platform_object(
            hostname).get_environment_file(hostname)

    def get_default_tempdir(self, hostname=None):
        """
        :returns: The temporary directory on the given host
                  Default host is localhost.
        """
        return self.get_platform_object(hostname).get_default_tempdir(hostname)

    def run_cmd(self, hosts, cmd, sudo, stdin,
                stdout, stderr, input, cwd, env,
                runas, logerr, as_script, wait_on_script,
                level, port, dshutilObject, timoutObject,
                user, runas_user):

        for hostname in hosts:
            platform = self.get_platform(hostname)
            ret = self.get_platform_object(hostname).run_cmd(
                hostname, cmd, sudo, stdin, stdout, stderr, input, cwd, env,
                runas, logerr, as_script, wait_on_script, level, port,
                platform, dshutilObject, timoutObject, user, runas_user)
        return ret

    def get_local_copy_cmd(
            self, hostname, preserve_permission=None, recursive=None):
        return self.get_platform_object(hostname).get_local_copy_cmd(
            hostname, preserve_permission, recursive)

    def get_remote_copy_cmd(self, hostname, copy_cmd,
                            preserve_permission, recursive):
        return self.get_platform_object(hostname).get_remote_copy_cmd(hostname)

    def list_file_dir_cmd(self, hostname, long_format):
        return self.get_platform_object(hostname).list_file_dir_cmd(long_format)

    def get_wrappers_dir(self, hostname=None):
        return self.get_platform_object(hostname).get_wrappers_dir(hostname)

    def get_executable_path_cmd(self, hostname=None):
        return self.get_platform_object(
            hostname).get_executable_path_cmd(hostname)

    def get_delete_cmd(self, hostname=None, recursive=False, force=False):
        return self.get_platform_object(hostname).get_delete_cmd(recursive, force)

    def get_cat_cmd(self, hostname, option=None):
        return self.get_platform_object(hostname).get_cat_cmd(hostname, option)

    def get_compare_cmd(self, hostname=None):
        return self.get_platform_object(hostname).get_compare_cmd(hostname)

    def get_process_command(self, hostname, process_param, platform=None):
        return self.get_platform_object(hostname, platform).get_process_command(process_param)

    def get_ps_cmd_attrs(self, hostname, ps_cmd):
        return self.get_platform_object(hostname).get_ps_cmd_attrs(ps_cmd)

    def get_pbs_mom_option(self, hostname):
        return self.get_platform_object(hostname).get_pbs_mom_option()
