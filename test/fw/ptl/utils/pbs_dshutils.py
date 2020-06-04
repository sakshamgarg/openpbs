# coding: utf-8

# Copyright (C) 1994-2020 Altair Engineering, Inc.
# For more information, contact Altair at www.altair.com.
#
# This file is part of the PBS Professional ("PBS Pro") software.
#
# Open Source License Information:
#
# PBS Pro is free software. You can redistribute it and/or modify it under the
# terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# PBS Pro is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Commercial License Information:
#
# For a copy of the commercial license terms and conditions,
# go to: (http://www.pbspro.com/UserArea/agreement.html)
# or contact the Altair Legal Department.
#
# Altair’s dual-license business model allows companies, individuals, and
# organizations to create proprietary derivative works of PBS Pro and
# distribute them - whether embedded or bundled with other software -
# under a commercial license agreement.
#
# Use of Altair’s trademarks, including but not limited to "PBS™",
# "PBS Professional®", and "PBS Pro™" and Altair’s logos is subject to Altair's
# trademark licensing policies.

import copy
import logging
import os
import platform
import re
import socket
import stat
import sys
import tempfile
import traceback
#import winpwd as pwd
from subprocess import PIPE, Popen

from ptl.utils.pbs_testusers import *

DFLT_RSYNC_CMD = ['rsync', '-e', 'ssh', '--progress', '--partial', '-ravz']
DFLT_COPY_CMD = ['scp', '-p']
DFLT_RSH_CMD = ['ssh']
DFLT_SUDO_CMD = ['sudo', '-H']

logging.DEBUG2 = logging.DEBUG - 1
logging.INFOCLI = logging.INFO - 1
logging.INFOCLI2 = logging.INFOCLI - 1


class TimeOut(Exception):

    """
    Raise this exception to mark a test as timed out.
    """
    pass


class PbsConfigError(Exception):
    """
    Initialize PBS configuration error
    """

    def __init__(self, message=None, rv=None, rc=None, msg=None):
        self.message = message
        self.rv = rv
        self.rc = rc
        self.msg = msg

    def __str__(self):
        return ('rc=' + str(self.rc) + ', rv=' + str(self.rv) +
                ',msg=' + str(self.msg))

    def __repr__(self):
        return (self.__class__.__name__ + '(rc=' + str(self.rc) + ', rv=' +
                str(self.rv) + ', msg=' + str(self.msg) + ')')


class PtlUtilError(Exception):
    """
    Initialize PTL Util error
    """

    def __init__(self, message=None, rv=None, rc=None, msg=None):
        self.message = message
        self.rv = rv
        self.rc = rc
        self.msg = msg

    def __str__(self):
        return ('rc=' + str(self.rc) + ', rv=' + str(self.rv) +
                ',msg=' + str(self.msg))

    def __repr__(self):
        return (self.__class__.__name__ + '(rc=' + str(self.rc) + ', rv=' +
                str(self.rv) + ', msg=' + str(self.msg) + ')')


class DshUtils(object):

    """
    PBS shell utilities

    A set of tools to run commands, copy files, get process
    information and parse a PBS configuration on an arbitrary host
    """

    logger = logging.getLogger(__name__)
    _h2osinfo = {}  # host to OS info cache
    _h2p = {}  # host to platform cache
    _h2pu = {}  # host to uname cache
    _h2c = {}  # host to pbs_conf file cache
    _h2l = {}  # host to islocal cache
    _h2which = {}  # host to which cache
    rsh_cmd = DFLT_RSH_CMD
    sudo_cmd = DFLT_SUDO_CMD
    copy_cmd = DFLT_COPY_CMD
    tmpfilelist = []
    tmpdirlist = []

    def __init__(self):

        self._current_user = None

        logging.addLevelName('INFOCLI', logging.INFOCLI)
        setattr(self.logger, 'infocli',
                lambda *args: self.logger.log(logging.INFOCLI, *args))

        logging.addLevelName('DEBUG2', logging.DEBUG2)
        setattr(self.logger, 'debug2',
                lambda *args: self.logger.log(logging.DEBUG2, *args))

        logging.addLevelName('INFOCLI2', logging.INFOCLI2)
        setattr(self.logger, 'infocli2',
                lambda *args: self.logger.log(logging.INFOCLI2, *args))

        self.mom_conf_map = {'PBS_MOM_SERVICE_PORT': '-M',
                             'PBS_MANAGER_SERVICE_PORT': '-R',
                             'PBS_HOME': '-d',
                             'PBS_BATCH_SERVICE_PORT': '-S',
                             }
        self.server_conf_map = {'PBS_MOM_SERVICE_PORT': '-M',
                                'PBS_MANAGER_SERVICE_PORT': '-R',
                                'PBS_HOME': '-d',
                                'PBS_BATCH_SERVICE_PORT': '-p',
                                'PBS_SCHEDULER_SERVICE_PORT': '-S',
                                }
        self.sched_conf_map = {'PBS_HOME': '-d',
                               'PBS_BATCH_SERVICE_PORT': '-p',
                               'PBS_SCHEDULER_SERVICE_PORT': '-S',
                               }
        self._tempdir = {}
        self.platform = sys.platform
        self.is_linux = self.platform.startswith('linux')
        self.is_windows = self.platform.startswith('win32')
        self.is_64bit = platform.architecture()[0] == '64bit'
        self.pconf_file = {}

    def get_platform(self, hostname=None, pyexec=None):
        """
        Get a local or remote platform info, essentially the value of
        Python's sys.platform, in case of Cray it will return a string
        as "cray" or "shasta" for actual Cray cluster and "craysim"
        for Cray ALPS simulator

        :param hostname: The hostname to query for platform info
        :type hostname: str or None
        :param pyexec: A path to a Python interpreter to use to query
                       a remote host for platform info
        :type pyexec: str or None
        For efficiency the value is cached and retrieved from the
        cache upon subsequent request
        """
        splatform = sys.platform
        found_already = False
        if hostname is None:
            hostname = socket.gethostname()
        if hostname in self._h2p:
            return self._h2p[hostname]
        if self.isfile(hostname=hostname, path='/etc/xthostname',
                       level=logging.DEBUG2):
            if self.isfile(hostname=hostname, path='/proc/cray_xt/cname',
                           level=logging.DEBUG2):
                splatform = 'cray'
            else:
                splatform = 'craysim'
            found_already = True
        if self.isfile(hostname=hostname, path='/etc/cray/xname',
                       level=logging.DEBUG2):
            splatform = 'shasta'
            found_already = True
        if not self.is_localhost(hostname) and not found_already:
            if pyexec is None:
                pyexec = self.which(hostname, exe='python3', level=logging.DEBUG2)
            cmd = [pyexec, '-c', '"import sys; print(sys.platform)"']
            ret = self.run_cmd(hostname, cmd=cmd)
            if ret['rc'] != 0 or len(ret['out']) == 0:
                _msg = 'Unable to retrieve platform info,'
                _msg += 'defaulting to local platform'
                self.logger.warning(_msg)
                splatform = sys.platform
            else:
                splatform = ret['out'][0]
        self._h2p[hostname] = splatform
        print("PLATFORM DETAILS ---------------------------- %s" %self._h2p)
        return splatform

    def get_uname(self, hostname=None, pyexec="python"):
        """
        Get a local or remote platform info in uname format, essentially
        the value of Python's platform.uname
        :param hostname: The hostname to query for platform info
        :type hostname: str or None
        :param pyexec: A path to a Python interpreter to use to query
                       a remote host for platform info
        :type pyexec: str or None
        For efficiency the value is cached and retrieved from the
        cache upon subsequent request
        """
        uplatform = ' '.join(platform.uname())
        if hostname is None:
            hostname = socket.gethostname()
        if hostname in self._h2pu:
            return self._h2pu[hostname]
        if not self.is_localhost(hostname):
            if pyexec is None:
                pyexec = self.which(hostname, exe='python3', level=logging.DEBUG2)
            #pyexec = "python"
            _cmdstr = '"import platform;'
            _cmdstr += 'print(\' \'.join(platform.uname()))"'
            cmd = [pyexec, '-c', _cmdstr]
            ret = self.run_cmd(hostname, cmd=cmd)
            if ret['rc'] != 0 or len(ret['out']) == 0:
                _msg = 'Unable to retrieve platform info,'
                _msg += 'defaulting to local platform'
                self.logger.warning(_msg)
            else:
                uplatform = ret['out'][0]
        self._h2pu[hostname] = uplatform
        return uplatform

    def get_os_info(self, hostname=None, pyexec="python"):
        """
        Get a local or remote OS info

        :param hostname: The hostname to query for platform info
        :type hostname: str or None
        :param pyexec: A path to a Python interpreter to use to query
                       a remote host for platform info
        :type pyexec: str or None

        :returns: a 'str' object containing os info
        """

        local_info = platform.platform()

        if hostname is None or self.is_localhost(hostname):
            return local_info
        if hostname in self._h2osinfo:
            return self._h2osinfo[hostname]

        if pyexec is None:
            pyexec = self.which(hostname, exe='python3', level=logging.DEBUG2)

        cmd = [pyexec, '-c',
               '"import platform; print(platform.platform())"']
        ret = self.run_cmd(hostname, cmd=cmd)
        if ret['rc'] != 0 or len(ret['out']) == 0:
            self.logger.warning("Unable to retrieve OS info, defaulting "
                                "to local")
            ret_info = local_info
        else:
            ret_info = ret['out'][0]

        self._h2osinfo[hostname] = ret_info
        return ret_info

    def _parse_file(self, hostname, file, platform='linux'):
        """
         helper function to parse a file containing entries of the
         form ``<key>=<value>`` into a Python dictionary format
        """
        if hostname is None:
            hostname = socket.gethostname()
        platform = platform.lower()
        #print("HOSTNAME ------------ %s" %hostname)
        #print("FILE ----------------- %s" %file)
        #print("PARSE_FILE platform ------------------- %s" %platform)
        try:
            if "linux" in platform:
                #print("Before linux cat --------------")
                rv = self.cat(hostname, file, level=logging.DEBUG2, logerr=False)
            elif "win" in platform:
                rv = self.cat(hostname, file, platform="win32", level=logging.DEBUG2, logerr=False)
            #cmd = ["type", file]
            #rv = self.run_cmd(hostname, cmd)
            if rv['rc'] != 0:
                return {}

            props = {}
            for l in rv['out']:
                if l.find('=') != -1 and l[0] != '#':
                    c = l.split('=')
                    props[c[0]] = c[1].strip()
        except BaseException:
            self.logger.error('error parsing file ' + str(file))
            self.logger.error(traceback.print_exc())
            return {}

        return props

    def _set_file(self, hostname, fin, fout, append, variables, sudo=False):
        """
        Create a file out of a set of dictionaries, possibly parsed
        from an input file. @see _parse_file.

        :param hostname: the name of the host on which to operate.
                         Defaults to localhost
        :type hostname: str
        :param fin: the input file to read from
        :type fin: str
        :param fout: the output file to write to
        :type fout: str
        :param append: If true, append to the output file.
        :type append: bool
        :param variables: The ``key/value`` pairs to write to fout
        :type variables: dictionary
        :param sudo: copy file to destination through sudo
        :type sudo: boolean
        :return dictionary of items set
        :raises PbsConfigError:
        """
        print("IN SET FILE ---------------------------------------- ")
        if hostname is None:
            hostname = socket.gethostname()

        if append:
            conf = self._parse_file(hostname, fin)
        else:
            conf = {}
        conf = {**conf, **variables}
        if os.path.isfile(fout):
            fout_stat = os.stat(fout)
            user = fout_stat.st_uid
            group = fout_stat.st_gid
        else:
            user = None
            group = None

        try:
            print("Before create tempfile ------------------------  IN SET FILE")
            fn = self.create_temp_file()
            print("after create temp file ---------------------- IN SET FILE")
            print("FN ------------------------------ %s" %fn)
            self.chmod(path=fn, mode=0o644)
            with open(fn, 'w') as fd:
                for k, v in conf.items():
                    fd.write(str(k) + '=' + str(v) + '\n')
            rv = self.run_copy(hostname, src=fn, dest=fout, uid=user,
                               gid=group, level=logging.DEBUG2, sudo=sudo)
            if rv['rc'] != 0:
                raise PbsConfigError
        except BaseException:
            raise PbsConfigError(rc=1, rv=None,
                                 msg='error writing to file ' + str(fout))
        finally:
            if os.path.isfile(fn):
                self.rm(path=fn)

        return conf

    def get_pbs_conf_file(self, hostname=None, platform="Linux"):
        """
        Get the path of the pbs conf file. Defaults back to
        ``/etc/pbs.conf`` if unsuccessful

        :param hostname: Hostname of the machine
        :type hostname: str or None
        :returns: Path to pbs conf file
        """
        #print("Get PBS conf file ----------------------------- ")
        if hostname in self._h2c:
            return self._h2c[hostname]
        if platform == 'Linux':
            dflt_conf = '/etc/pbs.conf'
            dflt_python = '/opt/pbs/python/bin/python'
        elif platform == 'win32':
            dflt_conf = "C:\Program Files (x86)\PBS\pbs.conf"
            dflt_python = "C:\Program Files (x86)\PBS\exec\python\python.exe"

        if hostname is None:
            hostname = socket.gethostname()

        if hostname in self._h2c:
            return self._h2c[hostname]

        if self.is_localhost(hostname):
            if 'PBS_CONF_FILE' in os.environ:
                dflt_conf = os.environ['PBS_CONF_FILE']
        else:
            pc = ('"import os;print([False, os.environ[\'PBS_CONF_FILE\']]'
                  '[\'PBS_CONF_FILE\' in os.environ])"')
            """
            cmd = ['ls', '-1', dflt_python]
            ret = self.run_cmd(hostname, cmd, host_platform="win32", logerr=False)
            if ret['rc'] == 0:
                pyexec = dflt_python
            else:
                pyexec = 'python'
            """
            pyexec = "python"
            cmd = [pyexec, '-c', pc]
            ret = self.run_cmd(hostname, cmd, logerr=False)
            if ((ret['rc'] != 0) and (len(ret['out']) > 0) and
                    (ret['out'][0] != 'False')):
                dflt_conf = ret['out'][0]

        self._h2c[hostname] = dflt_conf
        return dflt_conf

    def parse_pbs_config(self, hostname=None, file=None, platform="Linux"):
        """
        initialize ``pbs_conf`` dictionary by parsing pbs config file

        :param file: PBS conf file
        :type file: str or None
        """
        if file is None:
            file = self.get_pbs_conf_file(hostname, platform)
        return self._parse_file(hostname, file, platform)

    def set_pbs_config(self, hostname=None, fin=None, fout=None,
                       append=True, confs=None):
        """
        Set ``environment/configuration`` variables in a
        ``pbs.conf`` file

        :param hostname: the name of the host on which to operate
        :type hostname: str or None
        :param fin: the input pbs.conf file
        :type fin: str or None
        :param fout: the name of the output pbs.conf file, defaults
                     to ``/etc/pbs.conf``
        :type fout: str or None
        :param append: whether to append to fout or not, defaults
                       to True
        :type append: boolean
        :param confs: The ``key/value`` pairs to create
        :type confs: Dictionary or None
        """
        print("IN SET PBS CONF ------------------------------- ")
        if fin is None:
            fin = self.get_pbs_conf_file(hostname)
        if fout is None and fin is not None:
            fout = fin
        if confs is not None:
            self.logger.info('Set ' + str(confs) + ' in ' + fout)
        else:
            confs = {}
        return self._set_file(hostname, fin, fout, append, confs, sudo=True)

    def unset_pbs_config(self, hostname=None, fin=None, fout=None,
                         confs=None):
        """
        Unset ``environment/configuration`` variables in a pbs.conf
        file

        :param hostname: the name of the host on which to operate
        :type hostname: str or None
        :param fin: the input pbs.conf file
        :type fin: str or None
        :param fout: the name of the output pbs.conf file, defaults
                     to ``/etc/pbs.conf``
        :type fout: str or None
        :param confs: The configuration keys to unset
        :type confs: List or str or dict or None
        """
        if fin is None:
            fin = self.get_pbs_conf_file(hostname)

        if fout is None and fin is not None:
            fout = fin
        if confs is None:
            confs = []
        elif isinstance(confs, str):
            confs = confs.split(',')
        elif isinstance(confs, dict):
            confs = list(confs.keys())

        tounset = []
        cur_confs = self.parse_pbs_config(hostname, fin)
        for k in confs:
            if k in cur_confs:
                tounset.append(k)
                del cur_confs[k]
        if tounset:
            self.logger.info('Unset ' + ",".join(tounset) + ' from ' + fout)

        return self._set_file(hostname, fin, fout, append=False,
                              variables=cur_confs, sudo=True)

    def get_pbs_server_name(self, pbs_conf=None):
        """
        Return the name of the server which may be different than
        ``PBS_SERVER``,in order, this method looks at
        ``PBS_PRIMARY``, ``PBS_SERVER_HOST_NAME``, and
        ``PBS_LEAF_NAME``, and ``PBS_SERVER``
        """
        if pbs_conf is None:
            pbs_conf = self.parse_pbs_config()

        if 'PBS_PRIMARY' in pbs_conf:
            return pbs_conf['PBS_PRIMARY']
        elif 'PBS_SERVER_HOST_NAME' in pbs_conf:
            return pbs_conf['PBS_SERVER_HOST_NAME']
        elif 'PBS_LEAF_NAME' in pbs_conf:
            return pbs_conf['PBS_LEAF_NAME']

        return pbs_conf['PBS_SERVER']

    def parse_pbs_environment(self, hostname=None,
                              file='/var/spool/pbs/pbs_environment'):
        """
        Initialize pbs_conf dictionary by parsing pbs config file
        """
        return self._parse_file(hostname, file)

    def set_pbs_environment(self, hostname=None,
                            fin='/var/spool/pbs/pbs_environment', fout=None,
                            append=True, environ=None):
        """
        Set the PBS environment

        :param environ: variables to set
        :type environ: dict or None
        :param hostname: Hostname of the machine
        :type hostname: str or None
        :param fin: pbs_environment input file
        :type fin: str
        :param fout: pbs_environment output file
        :type fout: str or None
        :param append: whether to append to fout or not, defaults
                       defaults to true
        :type append: bool
        """
        if fout is None and fin is not None:
            fout = fin
        if environ is None:
            environ = {}
        return self._set_file(hostname, fin, fout, append, environ, sudo=True)

    def unset_pbs_environment(self, hostname=None,
                              fin='/var/spool/pbs/pbs_environment', fout=None,
                              environ=None):
        """
        Unset environment variables in a pbs_environment file

        :param hostname: the name of the host on which to operate
        :type hostname: str or None
        :param fin: the input pbs_environment file
        :type fin: str
        :param fout: the name of the output pbs.conf file, defaults
                     to ``/var/spool/pbs/pbs_environment``
        :type fout: str or None
        :param environ: The environment keys to unset
        :type environ: List or str or dict or None
        """
        if fout is None and fin is not None:
            fout = fin
        if environ is None:
            environ = []
        elif isinstance(environ, str):
            environ = environ.split(',')
        elif isinstance(environ, dict):
            environ = list(environ.keys())

        tounset = []
        cur_environ = self.parse_pbs_environment(hostname, fin)
        for k in environ:
            if k in cur_environ:
                tounset.append(k)
                del cur_environ[k]
        if tounset:
            self.logger.info('Unset ' + ",".join(tounset) + ' from ' + fout)

        return self._set_file(hostname, fin, fout, append=False,
                              variables=cur_environ, sudo=True)

    def parse_rhosts(self, hostname=None, user=None):
        """
        Parse remote host

        :param hostname: Hostname of the machine
        :type hostname: str or None
        :param user: User name
        :type user: str or None
        """
        if hostname is None:
            hostname = socket.gethostname()
        if user is None:
            user = os.getuid()
        try:
            # currently assumes identical file system layout on every host
            if isinstance(user, int):
                home = pwd.getpwuid(user).pw_dir
            else:
                home = pwd.getpwnam(user).pw_dir
            rhost = os.path.join(home, '.rhosts')
            rv = self.cat(hostname, rhost, level=logging.DEBUG2, runas=user,
                          logerr=False)
            if rv['rc'] != 0:
                return {}
            props = {}
            for l in rv['out']:
                if l[0] != '#':
                    k, v = l.split()
                    v = v.strip()
                    if k in self.props:
                        if isinstance(self.props[k], list):
                            self.props[k].append(v)
                        else:
                            self.props[k] = [self.props[k], v]
                    else:
                        self.props[k] = v
        except BaseException:
            self.logger.error('error parsing .rhost')
            self.logger.error(traceback.print_exc())
            return {}
        return props

    def set_rhosts(self, hostname=None, user=None, entry={}, append=True):
        """
        Set the remote host attributes

        :param entry: remote hostname user dictionary
        :type entry: Dictionary
        :param append: If true append key value else not
        :type append: boolean
        """
        if hostname is None:
            hostname = socket.gethostname()
        if user is None:
            user = os.getuid()
        if append:
            conf = self.parse_rhosts(hostname, user)
            for k, v in entry.items():
                if k in conf:
                    if isinstance(conf[k], list):
                        if isinstance(v, list):
                            conf[k].extend(v)
                        else:
                            conf[k].append(v)
                    else:
                        if isinstance(v, list):
                            conf[k] = [conf[k]] + v
                        else:
                            conf[k] = [conf[k], v]
                else:
                    conf[k] = v
        else:
            conf = entry
        try:
            # currently assumes identical file system layout on every host
            if isinstance(user, int):
                _user = pwd.getpwuid(user)
                home = _user.pw_dir
                uid = _user.pw_uid
            else:
                # user might be PbsUser object
                _user = pwd.getpwnam(str(user))
                home = _user.pw_dir
                uid = _user.pw_uid
            rhost = os.path.join(home, '.rhosts')
            fn = self.create_temp_file(hostname)
            self.chmod(hostname, fn, mode=0o755)
            with open(fn, 'w') as fd:
                fd.write('#!/bin/bash\n')
                fd.write('cd %s\n' % (home))
                fd.write('%s -rf %s\n' % (self.which(hostname, exe='rm',
                                                     level=logging.DEBUG2),
                                          rhost))
                fd.write('touch %s\n' % (rhost))
                for k, v in conf.items():
                    if isinstance(v, list):
                        for eachprop in v:
                            l = 'echo "%s %s" >> %s\n' % (str(k),
                                                          str(eachprop),
                                                          rhost)
                            fd.write(l)
                    else:
                        l = 'echo "%s %s" >> %s\n' % (str(k), str(v), rhost)
                        fd.write(l)
                fd.write('%s 0600 %s\n' % (self.which(hostname, exe='chmod',
                                                      level=logging.DEBUG2),
                                           rhost))
            ret = self.run_cmd(hostname, cmd=fn, runas=uid)
            self.rm(hostname, path=fn)
            if ret['rc'] != 0:
                raise Exception(ret['out'] + ret['err'])
        except Exception as e:
            raise PbsConfigError(rc=1, rv=None, msg='error writing .rhosts ' +
                                 str(e))
        return conf

    def map_pbs_conf_to_cmd(self, cmd_map={}, pconf={}):
        """
        Map PBS configuration parameter to command

        :param cmd_map: command mapping
        :type cmd_map: Dictionary
        :param pconf: PBS conf parameter dictionary
        :type pconf: Dictionary
        """
        cmd = []
        for k, v in pconf.items():
            if k in cmd_map:
                cmd += [cmd_map[k], str(v)]
        return cmd

    """
    def get_current_user(self):
     
        if self._current_user is not None:
            return self._current_user
        self._current_user = self.du.get_current_user()
        return self._current_user
    """

    def check_user_exists(self, username=None, hostname=None, port=None):
        """
        Check if user exist  or not

        :param username: Username to check
        :type username: str or None
        :param hostname: Machine hostname
        :type hostname: str or None
        :param port: port used to ssh other host
        :type port: str or None
        :returns: True if exist else return False
        """
        if hostname is None:
            hostname = socket.gethostname()
        if self.get_platform() == "shasta":
            runas = username
        else:
            runas = None
        ret = self.run_cmd(hostname, ['id', username], port=port, runas=runas)
        if ret['rc'] == 0:
            return True
        return False

    def check_group_membership(self, username=None, uid=None, grpname=None,
                               gid=None):
        """
        Checks whether a user, passed in as username or uid, is a
        member of a group, passed in as group name or group id.

        :param username: The username to inquire about
        :type username: str or None
        :param uid: The uid of the user to inquire about (alternative
                    to username)
        :param grpname: The groupname to check for user membership
        :type grpname: str or None
        :param gid: The group id to check for user membership
                    (alternative to grpname)
        """
        if username is None and uid is None:
            self.logger.warning('A username or uid was expected')
            return True
        if grpname is None and gid is None:
            self.logger.warning('A grpname or gid was expected')
            return True
        if grpname:
            try:
                _g = grp.getgrnam(grpname)
                if username and username in _g.gr_mem:
                    return True
                elif uid is not None:
                    _u = pwd.getpwuid(uid)
                    if _u.pwname in _g.gr_mem:
                        return True
            except BaseException:
                self.logger.error('Unknown user')
        return False

    def group_memberships(self, group_list=[]):
        """
        Returns all group memberships as a dictionary of group names
        and associated memberships
        """
        groups = {}
        if not group_list:
            return groups
        users_list = [u.pw_name for u in pwd.getpwall()]
        glist = {}
        for u in users_list:
            info = self.get_id_info(u)
            if not info['pgroup'] in list(glist.keys()):
                glist[info['pgroup']] = [info['name']]
            else:
                glist[info['pgroup']].append(info['name'])
            for g in info['groups']:
                if g not in list(glist.keys()):
                    glist[g] = []
                if not info['name'] in glist[g]:
                    glist[g].append(info['name'])
        for g in group_list:
            if g in list(glist.keys()):
                groups[g] = glist[g]
            else:
                try:
                    i = grp.getgrnam(g)
                    groups[g] = i.gr_mem
                except KeyError:
                    pass
        return groups

    def get_id_info(self, user):
        """
        Return user info in dic format
        obtained by ``"id -a <user>"`` command for given user

        :param user: The username to inquire about
        :type user: str
        :returns: dic format:

                {

                   "uid": <uid of given user>,

                   "gid": <gid of given user's primary group>,

                   "name": <name of given user>,

                   "pgroup": <name of primary group of given user>,

                   "groups": <list of names of groups of given user>

                }
        """
        info = {'uid': None, 'gid': None, 'name': None, 'pgroup': None,
                'groups': None}
        ret = self.run_cmd(cmd=['id', '-a', str(user)], logerr=True)
        if ret['rc'] == 0:
            p = re.compile(r'(?P<uid>\d+)\((?P<name>[\w\s."\'-]+)\)')
            map_list = re.findall(p, ret['out'][0])
            info['uid'] = int(map_list[0][0])
            info['name'] = map_list[0][1].strip()
            info['gid'] = int(map_list[1][0])
            info['pgroup'] = map_list[1][1].strip()
            groups = []
            if len(map_list) > 2:
                for g in map_list[2:]:
                    groups.append(g[1].strip().strip('"').strip("'"))
            info['groups'] = groups
        return info

    def get_tempdir(self, hostname=None):
        """
        :returns: The temporary directory on the given host
                  Default host is localhost.
        """
        # return the cached value whenever possible

        if hostname is None:
            hostname = socket.gethostname()

        if hostname in self._tempdir:
            return self._tempdir[hostname]

        if self.is_localhost(hostname):
            self._tempdir[hostname] = tempfile.gettempdir()
        else:
            #pyexec = self.which(hostname, 'python3', level=logging.DEBUG2)
            pyexec = "python"
            cmd = [pyexec, '-c',
                   '"import tempfile; print(tempfile.gettempdir())"']
            ret = self.run_cmd(hostname, cmd, level=logging.DEBUG)
            if ret['rc'] == 0:
                self._tempdir[hostname] = ret['out'][0].strip()
            else:
                # Optimistically fall back to /tmp.
                self._tempdir[hostname] = '/tmp'
        return self._tempdir[hostname]

    '''def run_cmd(self, hosts=None, cmd=None, host_platform="Linux", sudo=False, stdin=None,
                stdout=PIPE, stderr=PIPE, input=None, cwd=None, env=None,
                runas=None, logerr=True, as_script=False, wait_on_script=True,
                level=logging.INFOCLI2, port=None):
        """
        Run a command on a host or list of hosts.

        :param hosts: the name of hosts on which to run the command,
                      can be a comma-separated string or a list.
                      Defaults to localhost
        :type hosts: str or None
        :param cmd: the command to run
        :type cmd: str or None
        :param sudo: whether to run the command as root or not.
                     Defaults to False.
        :type sudo: boolean
        :param stdin: custom stdin. Defaults to PIPE
        :param stdout: custom stdout. Defaults to PIPE
        :param stderr: custom stderr. Defaults to PIPE
        :param input: input to pass to the pipe on target host,
                      e.g. PBS answer file
        :param cwd: working directory on local host from which
                    command is run
        :param env: environment variables to set on local host
        :param runas: run command as given user. Defaults to calling
                      user
        :param logerr: whether to log error messages or not. Defaults
                       to True
        :type logerr: boolean
        :param as_script: if True, run the command in a script
                          created as a temporary file that gets
                          deleted after being run. This is used
                          mainly to circumvent some implementations
                          of sudo that prevent passing environment
                          variables through sudo.
        :type as_script: boolean
        :param wait_on_script: If True (default) waits on process
                               launched as script to return.
        :type wait_on_script: boolean
        :type port: str
        :param port: port number used with remote host IP address
                     for ssh
        :returns: error, output, return code as a dictionary:
                  ``{'out':...,'err':...,'rc':...}``
        """

        rshcmd = []
        sudocmd = []
        if host_platform == "win32":
            platform = host_platform
        else:
            if hosts in self._h2p:
                platform = self._h2p[hosts]
            else:
                platform = host_platform
        #platform = host_platform
        _runas_user = None
        wait_on_script = False
        as_script = False
        if level is None:
            level = self.logger.level

        _user = self.get_current_user()

        # runas may be a PbsUser object, ensure it is a string for the
        # remainder of the function
        #if runas is not None:
        #    if isinstance(runas, int):
        #        runas = pwd.getpwuid(runas).pw_name
        #    elif not isinstance(runas, str):
                # must be as PbsUser object
        #        runas = str(runas)

        if runas:
            _runas_user = PbsUser.get_user(runas)

        if isinstance(cmd, str):
            cmd = cmd.split()

        if hosts is None:
            hosts = socket.gethostname()

        if isinstance(hosts, str):
            hosts = hosts.split(',')

        if not isinstance(hosts, list):
            err_msg = 'target hostnames must be a comma-separated ' + \
                'string or list'
            self.logger.error(err_msg)
            return {'out': '', 'err': err_msg, 'rc': 1}

        ret = {'out': '', 'err': '', 'rc': 0}
        if platform == "win32":
            hostname = hosts[0]
            #print("HOSTNAME ------------------------ %s" %hostname)
            islocal = self.is_localhost(hostname)
            #print("islocal -------------------- %s" %islocal)
            #if islocal is None:
            #    ret['err'] = 'error getting host by name in run_cmd'
            #    ret['rc'] = 1
            #    continue
            if not islocal:
                ht = "pbsadmin@"+hostname
                rsh = ['ssh', "pbsadmin@"+hostname]
                cmd = rsh + cmd
            print("CMD --------------------------- %s" %cmd)
            import subprocess
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (o, e) = proc.communicate()
            ret['rc'] = proc.returncode
            if o is not None:
                ret['out'] = [i.decode("utf-8") for i in o.splitlines()]
            else:
                ret['out'] = []
            if e is not None:
                ret['err'] = [i.decode("utf-8") for i in e.splitlines()]
            else:
                ret['err'] = []
            print("DSHUTILS return ---------------------------------- %s" %ret)
            return ret
        
        for hostname in hosts:
            if (platform == "shasta") and _runas_user:
                hostname = _runas_user.host if _runas_user.host else hostname
                port = _runas_user.port
            islocal = self.is_localhost(hostname)
            if islocal is None:
                # an error occurred processing that name, move on
                # the error is logged in is_localhost.
                ret['err'] = 'error getting host by name in run_cmd'
                ret['rc'] = 1
                continue
            if not islocal:
                if port and platform == "shasta":
                    if runas is None:
                        user = _user
                    else:
                        user = _runas_user.name
                    rshcmd = self.rsh_cmd + ['-p', port, user + '@' + hostname]
                else:
                    rshcmd = self.rsh_cmd + [hostname]
            if platform != "shasta":
                if sudo or ((runas is not None) and (runas != _user)):
                    sudocmd = copy.copy(self.sudo_cmd)
                    if runas is not None:
                        sudocmd += ['-u', runas]

            # Initialize information to return
            ret = {'out': None, 'err': None, 'rc': None}
            rc = rshcmd + sudocmd + cmd
            if as_script:
                _script = self.create_temp_file()
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
                    self.run_copy(hostname, src=_script, dest=_script,
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
            self.logger.log(level, '\n'.join(_msg))

            if input:
                self.logger.log(level, input)

            try:
                p = Popen(runcmd, bufsize=-1, stdin=stdin, stdout=stdout,
                          stderr=stderr, cwd=cwd, env=env)
            except Exception as e:
                self.logger.error("Error running command " + str(runcmd))
                if as_script:
                    self.logger.error('Script contents: \n' +
                                      '\n'.join(script_body))
                self.logger.debug(str(e))
                raise

            if as_script and not wait_on_script:
                o = p.stdout.readline()
                e = p.stderr.readline()
                ret['rc'] = 0
            else:
                try:
                    (o, e) = p.communicate(input)
                except TimeOut:
                    self.logger.error("TimeOut Exception, cmd:%s" %
                                      str(runcmd))
                    raise
                ret['rc'] = p.returncode

            if as_script:
                # must pass as_script=False otherwise it will loop infinite
                if platform == 'shasta' and runas:
                    self.rm(hostname, path=_script, as_script=False,
                            level=level, runas=runas)
                else:
                    self.rm(hostname, path=_script, as_script=False,
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
                self.logger.log(level, 'out: ' + str(ret['out']))
            else:
                self.logger.debug('out: ' + str(ret['out']))
            if e is not None:
                ret['err'] = [i.decode("utf-8", 'backslashreplace')
                              for i in e.splitlines()]
            else:
                ret['err'] = []
            if ret['err'] and logerr:
                self.logger.error('err: ' + str(ret['err']))
            else:
                self.logger.debug('err: ' + str(ret['err']))
            self.logger.debug('rc: ' + str(ret['rc']))

        return ret'''

    def run_cmd(self, hosts=None, cmd=None, host_platform="Linux", sudo=False, stdin=None,
                stdout=PIPE, stderr=PIPE, input=None, cwd=None, env=None,
                runas=None, logerr=True, as_script=False, wait_on_script=True,
                level=logging.INFOCLI2, port=None):
        """
        Run a command on a host or list of hosts.

        :param hosts: the name of hosts on which to run the command,
                      can be a comma-separated string or a list.
                      Defaults to localhost
        :type hosts: str or None
        :param cmd: the command to run
        :type cmd: str or None
        :param sudo: whether to run the command as root or not.
                     Defaults to False.
        :type sudo: boolean
        :param stdin: custom stdin. Defaults to PIPE
        :param stdout: custom stdout. Defaults to PIPE
        :param stderr: custom stderr. Defaults to PIPE
        :param input: input to pass to the pipe on target host,
                      e.g. PBS answer file
        :param cwd: working directory on local host from which
                    command is run
        :param env: environment variables to set on local host
        :param runas: run command as given user. Defaults to calling
                      user
        :param logerr: whether to log error messages or not. Defaults
                       to True
        :type logerr: boolean
        :param as_script: if True, run the command in a script
                          created as a temporary file that gets
                          deleted after being run. This is used
                          mainly to circumvent some implementations
                          of sudo that prevent passing environment
                          variables through sudo.
        :type as_script: boolean
        :param wait_on_script: If True (default) waits on process
                               launched as script to return.
        :type wait_on_script: boolean
        :type port: str
        :param port: port number used with remote host IP address
                     for ssh
        :returns: error, output, return code as a dictionary:
                  ``{'out':...,'err':...,'rc':...}``
        """

        rshcmd = []
        sudocmd = []
        if hosts in self._h2p:
            platform = self._h2p[hosts]
        else:
            platform = host_platform
        #platform = host_platform
        _runas_user = None
        wait_on_script = False
        as_script = False
        if level is None:
            level = self.logger.level

        _user = self.get_current_user()

        # runas may be a PbsUser object, ensure it is a string for the
        # remainder of the function
        #if runas is not None:
        #    if isinstance(runas, int):
        #        runas = pwd.getpwuid(runas).pw_name
        #    elif not isinstance(runas, str):
                # must be as PbsUser object
        #        runas = str(runas)

        if runas:
            #_runas_user = PbsUser.get_user(runas)
            _runas_user = "saksham"

        if isinstance(cmd, str):
            cmd = cmd.split()

        if hosts is None:
            hosts = socket.gethostname()

        if isinstance(hosts, str):
            hosts = hosts.split(',')

        if not isinstance(hosts, list):
            err_msg = 'target hostnames must be a comma-separated ' + \
                'string or list'
            self.logger.error(err_msg)
            return {'out': '', 'err': err_msg, 'rc': 1}

        ret = {'out': '', 'err': '', 'rc': 0}
        '''
        if platform == "win32":
            hostname = hosts[0]
            #print("HOSTNAME ------------------------ %s" %hostname)
            islocal = self.is_localhost(hostname)
            #print("islocal -------------------- %s" %islocal)
            #if islocal is None:
            #    ret['err'] = 'error getting host by name in run_cmd'
            #    ret['rc'] = 1
            #    continue
            if not islocal:
                ht = "pbsadmin@"+hostname
                rsh = ['ssh', "pbsadmin@"+hostname]
                cmd = rsh + cmd
            print("CMD --------------------------- %s" %cmd)
            import subprocess
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (o, e) = proc.communicate()
            ret['rc'] = proc.returncode
            if o is not None:
                ret['out'] = [i.decode("utf-8") for i in o.splitlines()]
            else:
                ret['out'] = []
            if e is not None:
                ret['err'] = [i.decode("utf-8") for i in e.splitlines()]
            else:
                ret['err'] = []
            print("DSHUTILS return ---------------------------------- %s" %ret)
            return ret
        '''
        for hostname in hosts:
            if (platform == "shasta") and _runas_user:
                hostname = _runas_user.host if _runas_user.host else hostname
                port = _runas_user.port
            islocal = self.is_localhost(hostname)
            #print("islocal -------------------------------- %s"%islocal)
            if islocal is None:
                # an error occurred processing that name, move on
                # the error is logged in is_localhost.
                ret['err'] = 'error getting host by name in run_cmd'
                ret['rc'] = 1
                continue
            if not islocal:
                if port and platform == "shasta":
                    if runas is None:
                        user = _user
                    else:
                        user = _runas_user.name
                    rshcmd = self.rsh_cmd + ['-p', port, user + '@' + hostname]
                elif platform == "win32":
                    rshcmd = self.rsh_cmd + ["saksham@" + hostname]
                    #print("---------RSH_CMD--------------------------- %s" %rshcmd)
                else:
                    rshcmd = self.rsh_cmd + [hostname]
            if platform != "shasta" and platform != "win32":
                if sudo or ((runas is not None) and (runas != _user)):
                    sudocmd = copy.copy(self.sudo_cmd)
                    if runas is not None:
                        #sudocmd += ['-u', runas]
                        sudocmd += ['-u', 'root']

            # Initialize information to return
            ret = {'out': None, 'err': None, 'rc': None}
            rc = rshcmd + sudocmd + cmd
            if as_script or platform == "win32":
                if platform == "win32":
                    _script = self.create_temp_file(suffix=".bat")
                    script_body = ['@echo off']
                    #print("---------WINDOWS CMD--------------------------- %s" %cmd)
                else:
                    _script = self.create_temp_file()
                    script_body = ['#!/bin/bash']
                if cwd is not None:
                    script_body += ['cd "%s"' % (cwd)]
                    cwd = None
                if isinstance(cmd, str):
                    script_body += [cmd]
                elif isinstance(cmd, list):
                    script_body += [" ".join(cmd)]
                print("Script file -------------------------------- %s" %_script)
                print("-------script_body---------")
                print(script_body)
                print("---------------------------------------------------")
                with open(_script, 'w') as f:
                    f.write('\n'.join(script_body))
                #os.chmod(_script, 0o755)
                if not islocal:
                    # TODO: get a valid remote temporary file rather than
                    # assume that the remote host has a similar file
                    # system layout
                    #print("INSIDE run_cmd if or islocal---------------------------")
                    self.run_copy(hostname, src=_script, dest=_script,
                                  runas=runas, level=level)
                    os.remove(_script)
                runcmd = rshcmd + sudocmd + [_script]
                if platform == "win32" and rshcmd:
                    final_file = self.create_temp_file(suffix=".bat")
                    with open(final_file, 'w') as f:
                        f.write("@echo off")
                        f.write('\n')
                        f.write(' '.join(runcmd))
                    runcmd = [final_file]
            else:
                runcmd = rc
            
            #print("FINAL CMD--------------------------- %s" %runcmd)

            _msg = hostname.split('.')[0] + ': '
            _runcmd = ['\'\'' if x == '' else str(x) for x in runcmd]
            _msg += ' '.join(_runcmd)
            _msg = [_msg]
            if as_script:
                _msg += ['Contents of ' + _script + ':']
                _msg += ['-' * 40, '\n'.join(script_body), '-' * 40]
            self.logger.log(level, '\n'.join(_msg))

            if input:
                self.logger.log(level, input)

            try:
                p = Popen(runcmd, bufsize=-1, stdout=stdout,
                          stderr=stderr, cwd=cwd)#, env=env)
            except Exception as e:
                self.logger.error("Error running command " + str(runcmd))
                if as_script:
                    self.logger.error('Script contents: \n' +
                                      '\n'.join(script_body))
                self.logger.debug(str(e))
                raise

            if as_script and not wait_on_script:
                o = p.stdout.readline()
                e = p.stderr.readline()
                ret['rc'] = 0
            else:
                (o, e) = p.communicate(input)
                ret['rc'] = p.returncode

            if as_script:
                # must pass as_script=False otherwise it will loop infinite
                if platform == 'shasta' and runas:
                    self.rm(hostname, path=_script, as_script=False,
                            level=level, runas=runas)
                else:
                    self.rm(hostname, path=_script, as_script=False,
                            level=level)
            #if platform == "win32":
                #print("-----------UNLINK FILE ------------------ %s" %_script)
                #os.unlink(_script)

            # handle the case where stdout is not a PIPE
            if o is not None:
                ret['out'] = [i.decode("utf-8") for i in o.splitlines()]
            else:
                ret['out'] = []
            # Some output can be very verbose, for example listing many lines
            # of a log file, those messages are typically channeled through
            # at level DEBUG2, since we don't to pollute the output with too
            # verbose an information, we log at most at level DEBUG
            if level < logging.DEBUG:
                self.logger.log(level, 'out: ' + str(ret['out']))
            else:
                self.logger.debug('out: ' + str(ret['out']))
            if e is not None:
                ret['err'] = [i.decode("utf-8") for i in e.splitlines()]
            else:
                ret['err'] = []
            if ret['err'] and logerr:
                self.logger.error('err: ' + str(ret['err']))
            else:
                self.logger.debug('err: ' + str(ret['err']))
            self.logger.debug('rc: ' + str(ret['rc']))
        if len(ret['err']) > 0 or ret['rc'] != 0:
            print("DSHUTILS return ---------------------------------- %s" %ret)
            #print((traceback.print_stack()))

        return ret

    '''def run_copy(self, hosts=None, srchost=None, src=None, dest=None,
                 sudo=False, uid=None, gid=None, mode=None, env=None,
                 logerr=True, recursive=False, runas=None,
                 preserve_permission=True, level=logging.INFOCLI2):
        """
        copy a file or directory to specified target hosts.

        :param hosts: the host(s) to which to copy the data. Can be
                      a comma-separated string or a list
        :type hosts: str or None
        :param srchost: the host on which the src file resides.
        :type srchost: str or None
        :param src: the path to the file or directory to copy.
        :type src: str or None
        :param dest: the destination path.
        :type dest: str or None
        :param sudo: whether to copy as root or not. Defaults to
                     False
        :type sudo: boolean
        :param uid: optionally change ownership of dest to the
                    specified user id,referenced by uid number or
                    username
        :param gid: optionally change ownership of dest to the
                    specified group ``name/id``
        :param mode: optinoally set mode bits of dest
        :param env: environment variables to set on the calling host
        :param logerr: whether to log error messages or not.
                       Defaults to True.
        :param recursive: whether to copy a directory (when true) or
                          a file.Defaults to False.
        :type recursive: boolean
        :param runas: run command as user
        :type runas: str or None
        :param preserve_permission: Preserve file permission while
                                    copying file (cp cmd with -p flag)
                                    Defaults to True
        :type preserve_permission:boolean
        :param level: logging level, defaults to DEBUG
        :type level: int
        :returns: {'out':<outdata>, 'err': <errdata>, 'rc':<retcode>}
                  upon and None if no source file specified
        """

        if src is None:
            self.logger.warning('no source file specified')
            return None

        if hosts is None:
            hosts = socket.gethostname()

        if isinstance(hosts, str):
            hosts = hosts.split(',')

        if not isinstance(hosts, list):
            self.logger.error('destination must be a string or a list')
            return 1

        if dest is None:
            dest = src

        # If PTL_SUDO_CMD were to be unset we should assume no sudo
        if sudo is True and not self.sudo_cmd:
            sudo = False

        runas = PbsUser.get_user(runas)
        issrclocal = None
        if srchost:
            issrclocal = self.is_localhost(srchost)
        for targethost in hosts:
            islocal = self.is_localhost(targethost)
            if sudo and not islocal and not issrclocal:
                # to avoid a file copy as root, we copy it as current user
                # and move it remotely to the desired path/name.
                # First, get a remote temporary filename
                pyexec = self.which(targethost, 'python3',
                                    level=logging.DEBUG2)
                cmd = [pyexec, '-c',
                       '"import tempfile;print(' +
                       'tempfile.mkstemp(\'PtlPbstmpcopy\')[1])"']
                # save original destination
                sudo_save_dest = dest
                # Make the target of the copy the temporary file
                dest = self.run_cmd(targethost, cmd,
                                    level=level,
                                    logerr=logerr)['out'][0]
                cmd = []
            else:
                # if not using sudo or target is local, initialize the
                # command to run accordingly
                sudo_save_dest = None
                if sudo:
                    cmd = copy.copy(self.sudo_cmd)
                else:
                    cmd = []

            # Remote copy if target host is remote or if source file/dir is
            # remote.
            if srchost:
                srchost = socket.getfqdn(srchost)
            if ((not islocal) or (srchost)):
                copy_cmd = copy.deepcopy(self.copy_cmd)
                targethost = socket.getfqdn(targethost)
                if (srchost == targethost):
                    cmd += [self.which(targethost, 'cp', level=level)]
                    if preserve_permission:
                        cmd += ['-p']
                    if recursive:
                        cmd += ['-r']
                    cmd += [src]
                    cmd += [dest]
                else:
                    if not preserve_permission:
                        copy_cmd.remove('-p')
                    if copy_cmd[0][0] != '/':
                        copy_cmd[0] = self.which(targethost, copy_cmd[0],
                                                 level=level)
                    cmd += copy_cmd
                    if recursive:
                        cmd += ['-r']
                    if runas and runas.port:
                        cmd += ['-P', runas.port]
                    if srchost:
                        src = srchost + ':' + src
                    cmd += [src]
                    if islocal:
                        cmd += [dest]
                    else:
                        if self.get_platform() == 'shasta' and runas:
                            cmd += [str(runas) + '@' + targethost + ':' + dest]
                        else:
                            cmd += [targethost + ':' + dest]
            else:
                cmd += [self.which(targethost, 'cp', level=level)]
                if preserve_permission:
                    cmd += ['-p']
                if recursive:
                    cmd += ['-r']
                cmd += [src]
                cmd += [dest]

            if srchost == targethost:
                ret = self.run_cmd(targethost, cmd, env=env,
                                   runas=runas, logerr=logerr, level=level)
            elif self.get_platform() == 'shasta':
                ret = self.run_cmd(socket.gethostname(), cmd, env=env,
                                   logerr=logerr, level=level)
            else:
                ret = self.run_cmd(socket.gethostname(), cmd, env=env,
                                   runas=runas, logerr=logerr, level=level)

            if ret['rc'] != 0:
                self.logger.error(ret['err'])
            elif sudo_save_dest:
                cmd = [self.which(targethost, 'cp', level=level)]
                cmd += [dest, sudo_save_dest]
                ret = self.run_cmd(targethost, cmd=cmd, sudo=True, level=level)
                self.rm(targethost, path=dest, level=level)
                dest = sudo_save_dest
                if ret['rc'] != 0:
                    self.logger.error(ret['err'])

            if mode is not None:
                self.chmod(targethost, path=dest, mode=mode, sudo=sudo,
                           recursive=recursive, runas=runas)
            if ((uid is not None and uid != self.get_current_user()) or
                    gid is not None):
                if dest == self.get_pbs_conf_file(targethost):
                    uid = pwd.getpwnam('root')[2]
                    gid = pwd.getpwnam('root')[3]
                self.chown(targethost, path=dest, uid=uid, gid=gid, sudo=True,
                           recursive=False)

        return ret'''

    def run_copy(self, hosts=None, srchost=None, src=None, dest=None,
                 sudo=False, uid=None, gid=None, mode=None, env=None,
                 logerr=True, recursive=False, runas=None,
                 preserve_permission=True, level=logging.INFOCLI2):
        """
        copy a file or directory to specified target hosts.

        :param hosts: the host(s) to which to copy the data. Can be
                      a comma-separated string or a list
        :type hosts: str or None
        :param srchost: the host on which the src file resides.
        :type srchost: str or None
        :param src: the path to the file or directory to copy.
        :type src: str or None
        :param dest: the destination path.
        :type dest: str or None
        :param sudo: whether to copy as root or not. Defaults to
                     False
        :type sudo: boolean
        :param uid: optionally change ownership of dest to the
                    specified user id,referenced by uid number or
                    username
        :param gid: optionally change ownership of dest to the
                    specified group ``name/id``
        :param mode: optinoally set mode bits of dest
        :param env: environment variables to set on the calling host
        :param logerr: whether to log error messages or not.
                       Defaults to True.
        :param recursive: whether to copy a directory (when true) or
                          a file.Defaults to False.
        :type recursive: boolean
        :param runas: run command as user
        :type runas: str or None
        :param preserve_permission: Preserve file permission while
                                    copying file (cp cmd with -p flag)
                                    Defaults to True
        :type preserve_permission:boolean
        :param level: logging level, defaults to DEBUG
        :type level: int
        :param localhost: host from where files to be copied
        :returns: {'out':<outdata>, 'err': <errdata>, 'rc':<retcode>}
                  upon and None if no source file specified
        """

        if src is None:
            self.logger.warning('no source file specified')
            return None

        if hosts is None:
            hosts = socket.gethostname()

        if isinstance(hosts, str):
            hosts = hosts.split(',')

        if not isinstance(hosts, list):
            self.logger.error('destination must be a string or a list')
            return 1

        if dest is None:
            dest = src

        # If PTL_SUDO_CMD were to be unset we should assume no sudo
        if sudo is True and not self.sudo_cmd:
            sudo = False

        #runas = PbsUser.get_user(runas)
        runas = "saksham"
        issrclocal = None
        if srchost:
            issrclocal = self.is_localhost(srchost)
        for targethost in hosts:
            islocal = self.is_localhost(targethost)
            if sudo and not islocal and not issrclocal:
                # to avoid a file copy as root, we copy it as current user
                # and move it remotely to the desired path/name.
                # First, get a remote temporary filename
                pyexec = self.which(targethost, exe='python3',
                                    level=logging.DEBUG2)
                #print("----------------PYEXEC-----------")
                #print(pyexec)
                cmd = [pyexec, '-c',
                       '"import tempfile;print(' +
                       'tempfile.mkstemp(\'PtlPbstmpcopy\')[1])"']
                # save original destination
                sudo_save_dest = dest
                # Make the target of the copy the temporary file
                dest = self.run_cmd(targethost, cmd,
                                    level=level,
                                    logerr=logerr)['out'][0]
                #print("-----------------DEST inside run_copy----------------")
                #print(dest)
                cmd = []
            else:
                # if not using sudo or target is local, initialize the
                # command to run accordingly
                sudo_save_dest = None
                if sudo:
                    cmd = copy.copy(self.sudo_cmd)
                else:
                    cmd = []

            # Remote copy if target host is remote or if source file/dir is
            # remote.
            if srchost:
                srchost = socket.getfqdn(srchost)
            else:
                srchost = socket.gethostname()
            src_platform = self.get_platform(hostname=srchost)
            if ((not islocal) or (srchost)):
                copy_cmd = copy.deepcopy(self.copy_cmd)
                targethost = socket.getfqdn(targethost)
                if (srchost == targethost):
                    if src_platform == "win32":
                        cmd += [self.which(srchost, host_platform=src_platform, exe='xcopy', level=level)]
                        if preserve_permission:
                            cmd += ['/K /O /X ']
                        if recursive:
                            cmd += ['/E ']
                    else:
                        cmd += [self.which(targethost, host_platform=src_platform, exe='cp', level=level)]
                        if preserve_permission:
                            cmd += ['-p']
                        if recursive:
                            cmd += ['-r']
                    cmd += [src]
                    cmd += [dest]
                else:
                    if not preserve_permission:
                        copy_cmd.remove('-p')
                    if src_platform == "win32":
                        if copy_cmd[0][0] != '/':
                            copy_cmd[0] = self.which(hostname=srchost, host_platform="win32", exe=copy_cmd[0],
                                                 level=level)
                        cmd += copy_cmd
                        if recursive:
                            cmd += ['/E']
                    else:
                        if copy_cmd[0][0] != '/':
                            copy_cmd[0] = self.which(hostname=srchost, host_platform="linux", exe=copy_cmd[0],
                                                 level=level)
                        cmd += copy_cmd
                        if recursive:
                            cmd += ['-r']
                    
                    #if runas and runas.port:
                    #    cmd += ['-P', runas.port]
                    # Why do we need to add srchost before the src path ?
                    #if srchost:
                    #    src = srchost + ':' + src
                    cmd += [src]
                    if islocal:
                        cmd += [dest]
                    else:
                        if self.get_platform() == 'shasta' and runas:
                            cmd += [str(runas) + '@' + targethost + ':' + dest]
                        else:
                            cmd += [targethost + ':' + dest]
            else:
                if src_platform == "win32":
                    cmd += [self.which(targethost, host_platform=src_platform, exe='xcopy', level=level)]
                    if preserve_permission:
                        cmd += ['/K /O /X ']
                    if recursive:
                        cmd += ['/E']
                else:
                    cmd += [self.which(targethost, exe='cp', level=level)]
                    if preserve_permission:
                        cmd += ['-p']
                    if recursive:
                        cmd += ['-r']
                cmd += [src]
                cmd += [dest]

            if srchost == targethost:
                ret = self.run_cmd(targethost, cmd, env=env,
                                   runas=runas, logerr=logerr, level=level)
            elif self.get_platform() == 'shasta':
                ret = self.run_cmd(socket.gethostname(), cmd, env=env,
                                   logerr=logerr, level=level)
            else:
                ret = self.run_cmd(socket.gethostname(), cmd, host_platform="win32", env=env,
                                   runas=runas, logerr=logerr, level=level)

            if ret['rc'] != 0:
                self.logger.error(ret['err'])
            elif sudo_save_dest:                
                dest_platform = self._h2p[targethost]
                if dest_platform == "win32":
                    cmd = [self.which(targethost, host_platform=dest_platform, exe='xcopy', level=level)]
                else:
                    cmd = [self.which(targethost, exe='cp', level=level)]
                cmd += [dest, sudo_save_dest]
                ret = self.run_cmd(targethost, cmd=cmd, sudo=True, level=level)
                self.rm(targethost, path=dest, level=level)
                dest = sudo_save_dest
                if ret['rc'] != 0:
                    self.logger.error(ret['err'])

            '''
            if mode is not None:
                self.chmod(targethost, path=dest, mode=mode, sudo=sudo,
                           recursive=recursive, runas=runas)
            if ((uid is not None and uid != self.get_current_user()) or
                    gid is not None):
                if dest == self.get_pbs_conf_file(targethost):
                    uid = pwd.getpwnam('root')[2]
                    gid = pwd.getpwnam('root')[3]
                self.chown(targethost, path=dest, uid=uid, gid=gid, sudo=True,
                           recursive=False)'''

            return ret

    def run_ptl_cmd(self, hostname, cmd, sudo=False, stdin=None, stdout=PIPE,
                    stderr=PIPE, input=None, cwd=None, env=None, runas=None,
                    logerr=True, as_script=False, wait_on_script=True,
                    level=logging.INFOCLI2):
        """
        Wrapper method of run_cmd to run PTL command
        """
        # Add absolute path of command also add log level to command
        self.logger.infocli('running command "%s" on %s' % (' '.join(cmd),
                                                            hostname))
        _cmd = [self.which(exe=cmd[0], level=level)]
        _cmd += ['-l', logging.getLevelName(self.logger.parent.level)]
        _cmd += cmd[1:]
        cmd = _cmd
        self.logger.debug(' '.join(cmd))
        dest = None
        if ('PYTHONPATH' in list(os.environ.keys()) and
                not self.is_localhost(hostname)):
            body = ['#!/bin/bash']
            body += ['PYTHONPATH=%s exec %s' % (os.environ['PYTHONPATH'],
                                                ' '.join(cmd))]
            fn = self.create_temp_file(body='\n'.join(body))
            tmpdir = self.get_tempdir(hostname)
            dest = os.path.join(tmpdir, os.path.basename(fn))
            oldc = self.copy_cmd[:]
            self.set_copy_cmd('scp -p')
            self.run_copy(hostname, src=fn, dest=dest, mode=0o755, level=level)
            self.set_copy_cmd(' '.join(oldc))
            self.rm(None, path=fn, force=True, logerr=False)
            cmd = dest
        ret = self.run_cmd(hostname, cmd, sudo, stdin, stdout, stderr, input,
                           cwd, env, runas, logerr, as_script, wait_on_script,
                           level)
        if dest is not None:
            self.rm(hostname, path=dest, force=True, logerr=False)
        # TODO: check why output is coming to ret['err']
        if ret['rc'] == 0:
            ret['out'] = ret['err']
            ret['err'] = []
        return ret

    @classmethod
    def set_sudo_cmd(cls, cmd):
        """
        set the sudo command
        """
        cls.logger.infocli('setting sudo command to ' + cmd)
        cls.sudo_cmd = cmd.split()

    @classmethod
    def set_copy_cmd(cls, cmd):
        """
        set the copy command
        """
        cls.logger.infocli('setting copy command to ' + cmd)
        cls.copy_cmd = cmd.split()

    @classmethod
    def set_rsh_cmd(cls, cmd):
        """
        set the remote shell command
        """
        cls.logger.infocli('setting remote shell command to ' + cmd)
        cls.rsh_cmd = cmd.split()

    def is_localhost(self, host=None):
        """
        :param host: Hostname of machine
        :type host: str or None
        :returns: true if specified host (by name) is the localhost
                  all aliases matching the hostname are searched
        """
        #print("self._h2l---------------------------------------- %s"%self._h2l)
        if host is None:
            return True

        if host in self._h2l:
            return self._h2l[host]

        try:
            (hostname, aliaslist, iplist) = socket.gethostbyname_ex(host)
        except BaseException:
            self.logger.error('error getting host by name: ' + host)
            print((traceback.print_stack()))
            return None

        localhost = socket.gethostname()
        if localhost == hostname or localhost in aliaslist:
            self._h2l[host] = True
        try:
            ipaddr = socket.gethostbyname(localhost)
        except BaseException:
            self.logger.error('could not resolve local host name')
            return False
        if ipaddr in iplist:
            self._h2l[host] = True
            return True
        # on a shasta machine, the name returned by `hostname` (pbs-host) is
        # different than the one we tell PTL to use (pbs-service-nmn). This
        # causes a name mismatch, so we should just set it to be True
        if (self.get_platform() == 'shasta' and host == 'pbs-service-nmn' and
                localhost == 'pbs-host'):
            self._h2l[host] = True
            return True
        self._h2l[host] = False
        return False

    def isdir(self, hostname=None, path=None, sudo=False, runas=None,
              level=logging.INFOCLI2):
        """
        :param hostname: The name of the host on which to check for
                         directory
        :type hostname: str or None
        :param path: The path to the directory to check
        :type path: str or None
        :param sudo: Whether to run the command as a privileged user
        :type sudo: boolean
        :param runas: run command as user
        :type runas: str or None
        :param level: Logging level
        :returns: True if directory pointed to by path exists and
                  False otherwise
        """
        if path is None:
            return False

        if (self.is_localhost(hostname) and (not sudo) and (runas is None)):
            return os.path.isdir(path)
        else:
            # Constraints on the build system prevent running commands as
            # a privileged user through python, fall back to ls
            dirname = os.path.dirname(path)
            basename = os.path.basename(path)
            platform = self.get_platform(hostname)
            platform = platform.lower()
            if "linux" in platform:
                cmd = ['ls', '-l', dirname]
            else:
                dirname = "\"" + dirname + "\""
                cmd = ["dir", dirname]
            self.logger.log(level, "grep'ing for " + basename + " in " +
                            dirname)
            ret = self.run_cmd(hostname, cmd=cmd, host_platform="win32", sudo=sudo, runas=runas,
                               logerr=True, level=level)
            if ret['rc'] != 0:
                return False
            else:
                if "win" in platform:
                    for l in ret['out']:
                        if basename == l[-len(basename):] and "<DIR>" in l:
                            return True
                else:
                    for l in ret['out']:
                        if basename == l[-len(basename):] and l.startswith('d'):
                            return True

        return False

    def isfile(self, hostname=None, path=None, sudo=False, runas=None,
               level=logging.INFOCLI2):
        """
        :param hostname: The name of the host on which to check for
                         file
        :type hostname: str or None
        :param path: The path to the file to check
        :type path: str or None
        :param sudo: Whether to run the command as a privileged user
        :type sudo: boolean
        :param runas: run command as user
        :type runas: str or None
        :param level: Logging level
        :returns: True if file pointed to by path exists, and False
                  otherwise
        """

        if path is None:
            return False

        if (self.is_localhost(hostname) and (not sudo) and (runas is None)):
            return os.path.isfile(path)
        else:
            # Constraints on the build system prevent running commands as
            # a privileged user through python, fall back to ls
            '''platform = self.get_platform(hostname)
            if platform == "win32":
                cmd = ['dir', path]
            else:'''
            cmd = ['ls', '-l', path]
            ret = self.run_cmd(hostname, cmd=cmd, host_platform=platform, sudo=sudo, runas=runas,
                               logerr=False, level=level)
            if ret['rc'] != 0:
                return False
            elif ret['out']:
                if not ret['out'][0].startswith('d'):
                    return True

        return False

    def getmtime(self, hostname=None, path=None, sudo=False, runas=None,
                 level=logging.INFOCLI2):
        """
        :param hostname: The name of the host on which file exists
        :type hostname: str or None
        :param path: The path to the file to get mtime
        :type path: str or None
        :param sudo: Whether to run the command as a privileged user
        :type sudo: boolean
        :param runas: run command as user
        :type runas: str or None
        :param level: Logging level
        :returns: Modified time of given file
        """

        if path is None:
            return None

        if (self.is_localhost(hostname) and (not sudo) and (runas is None)):
            return os.path.getmtime(path)
        else:
            py_cmd = 'import os; print(os.path.getmtime(\'%s\'))' % (path)
            if not self.is_localhost(hostname):
                py_cmd = '\"' + py_cmd + '\"'
            pyexec = self.which(hostname, exe='python3', level=logging.DEBUG2)
            cmd = [pyexec, '-c', py_cmd]
            ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, runas=runas,
                               logerr=False, level=level)
            if ((ret['rc'] == 0) and (len(ret['out']) == 1) and
                    (isinstance(eval(ret['out'][0].strip()), (int, float)))):
                return eval(ret['out'][0].strip())
        return None

    def listdir(self, hostname=None, path=None, sudo=False, runas=None,
                fullpath=True, level=logging.INFOCLI2):
        """
        :param hostname: The name of the host on which to list for
                         directory
        :type hostname: str or None
        :param path: The path to directory to list
        :type path: str or None
        :param sudo: Whether to chmod as root or not. Defaults to
                     False
        :type sudo: bool
        :param runas: run command as user
        :type runas: str or None
        :param fullpath: Return full paths?
        :type fullpath: bool
        :param level: Logging level.
        :type level: int
        :returns: A list containing the names of the entries in
                  the directory
        """

        if path is None:
            return None

        if (self.is_localhost(hostname) and (not sudo) and (runas is None)):
            try:
                files = os.listdir(path)
            except OSError:
                return None
        else:
            ret = self.run_cmd(hostname, cmd=['dir', path], host_platform="win32")#sudo=sudo,
                               #runas=runas, logerr=False, level=level)
            if ret['rc'] == 0:
                files = ret['out']
            else:
                return None
        if fullpath is True:
            return [os.path.join(path, p.strip()) for p in files]
        else:
            return [p.strip() for p in files]

    def chmod(self, hostname=None, path=None, mode=None, sudo=False,
              runas=None, recursive=False, logerr=True,
              level=logging.INFOCLI2):
        """
        Generic function of chmod with remote host support

        :param hostname: hostname (default current host)
        :type hostname: str or None
        :param path: the path to the file or directory to chmod
        :type path: str or None
        :param mode: mode to apply as octal number like 0777,
                     0666 etc.
        :param sudo: whether to chmod as root or not. Defaults
                     to False
        :type sudo: boolean
        :param runas: run command as user
        :type runas: str or None
        :param recursive: whether to chmod a directory (when true)
                          or a file.Defaults to False.
        :type recursive: boolean
        :param logerr: whether to log error messages or not. Defaults
                       to True.
        :type logerr: boolean
        :param level: logging level, defaults to INFOCLI2
        :returns: True on success otherwise False
        """
        print("IN CHMOD ------------------------------------------------- ")
        if (path is None) or (mode is None):
            return False
        print("after check for path -------------------")
        #cmd = [self.which(hostname, 'chmod', level=level)]
        platform = self.get_platform(hostname)
        if "win" in platform:
            cmd = ["Icacls"]
        else:
            cmd = ['chmod']
        #if recursive:
        #    cmd += ['-R']
        mode = '{:o}'.format(mode)
        cmd += [mode, path]
        print("before run_cmd chmod--------------------")
        ret = self.run_cmd(hostname, cmd=cmd, host_platform="win32",sudo=sudo, logerr=logerr,
                           runas=runas, level=level)
        if ret['rc'] == 0:
            return True
        return False

    def chown(self, hostname=None, path=None, uid=None, gid=None, sudo=False,
              recursive=False, runas=None, logerr=True,
              level=logging.INFOCLI2):
        """
        Generic function of chown with remote host support

        :param hostname: hostname (default current host)
        :type hostname: str or None
        :param path: the path to the file or directory to chown
        :type path: str or None
        :param uid: uid to apply (must be either user name or
                    uid or -1)
        :param gid: gid to apply (must be either group name or
                    gid or -1)
        :param sudo: whether to chown as root or not. Defaults
                     to False
        :type sudo: boolean
        :param recursive: whether to chmod a directory (when true)
                          or a file.Defaults to False.
        :type recursive: boolean
        :param runas: run command as user
        :type runas: str or None
        :param logerr: whether to log error messages or not. Defaults
                       to True.
        :type logerr: boolean
        :param level: logging level, defaults to INFOCLI2
        :returns: True on success otherwise False
        """
        if path is None or (uid is None and gid is None):
            return False
        _u = ''
        if isinstance(uid, int) and uid != -1:
            _u = pwd.getpwuid(uid).pw_name
        elif (isinstance(uid, str) and (uid != '-1')):
            _u = uid
        else:
            # must be as PbsUser object
            if str(uid) != '-1':
                _u = str(uid)
        if _u == '':
            return False
        cmd = [self.which(hostname, exe='chown', level=level)]
        if recursive:
            cmd += ['-R']
        cmd += [_u, path]
        ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                           runas=runas, level=level)
        if ret['rc'] == 0:
            if gid is not None:
                rv = self.chgrp(hostname, path, gid=gid, sudo=sudo,
                                level=level, recursive=recursive, runas=runas,
                                logerr=logerr)
                if not rv:
                    return False
            return True
        return False

    def chgrp(self, hostname=None, path=None, gid=None, sudo=False,
              recursive=False, runas=None, logerr=True,
              level=logging.INFOCLI2):
        """
        Generic function of chgrp with remote host support

        :param hostname: hostname (default current host)
        :type hostname: str or None
        :param path: the path to the file or directory to chown
        :type path: str or None
        :param gid: gid to apply (must be either group name or
                    gid or -1)
        :param sudo: whether to chgrp as root or not. Defaults
                     to False
        :type sudo: boolean
        :param recursive: whether to chmod a directory (when true)
                          or a file.Defaults to False.
        :type recursive: boolean
        :param runas: run command as user
        :type runas: str or None
        :param logerr: whether to log error messages or not. Defaults
                       to True.
        :type logerr: boolean
        :param level: logging level, defaults to INFOCLI2
        :returns: True on success otherwise False
        """
        if path is None or gid is None:
            return False

        _g = ''
        if isinstance(gid, int) and gid != -1:
            _g = grp.getgrgid(gid).gr_name
        elif (isinstance(gid, str) and (gid != '-1')):
            _g = gid
        else:
            # must be as PbsGroup object
            if str(gid) != '-1':
                _g = str(gid)

        if _g == '':
            return False

        cmd = [self.which(hostname, 'chgrp', level=level)]
        if recursive:
            cmd += ['-R']
        cmd += [_g, path]

        ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                           runas=runas, level=level)
        if ret['rc'] == 0:
            return True

        return False

    '''def which(self, hostname=None, exe=None, level=logging.INFOCLI2):
        """
        Generic function of which with remote host support

        :param hostname: hostname (default current host)
        :type hostname: str or None
        :param exe: executable to locate (can be full path also)
                    (if exe is full path then only basename will
                    be used to locate)
        :type exe: str or None
        :param level: logging level, defaults to INFOCLI2
        """
        if exe is None:
            return None

        if hostname is None:
            hostname = socket.gethostname()

        oexe = exe
        exe = os.path.basename(exe)
        if hostname in list(self._h2which.keys()):
            if exe in self._h2which[hostname]:
                return self._h2which[hostname][exe]

        sudo_wrappers_dir = '/opt/tools/wrappers'
        _exe = os.path.join(sudo_wrappers_dir, exe)
        if os.path.isfile(_exe) and os.access(_exe, os.X_OK):
            if hostname not in list(self._h2which.keys()):
                self._h2which.setdefault(hostname, {exe: _exe})
            else:
                self._h2which[hostname].setdefault(exe, _exe)
            return _exe

        # Changes specific to python
        # Use PBS Python if available before looking for system Python
        if exe == 'python3' or exe == 'python':
            py_path = "python"
            return py_path
            pbs_conf = self.parse_pbs_config(hostname)
            print("PBS_CONF ---------------------------------------- %s" %pbs_conf)
            if "PBS_EXEC" in pbs_conf and pbs_conf['PBS_EXEC'].find('\\') > 0:
                py_path = 'python'
                if hostname not in self._h2which.keys():
                    self._h2which.setdefault(hostname, {exe: py_path})
                else:
                    self._h2which[hostname].setdefault(exe, py_path)
                return py_path
            else:
                py_path = pbs_conf['PBS_EXEC'] + '/python/bin/python'
                cmd = ['ls', '-1', py_path]
                ret = self.run_cmd(hostname, cmd, logerr=False)
                if ret['rc'] == 0:
                    if hostname not in self._h2which.keys():
                        self._h2which.setdefault(hostname, {exe: py_path})
                    else:
                        self._h2which[hostname].setdefault(exe, py_path)
                    return py_path

        cmd = ['which', exe]
        ret = self.run_cmd(hostname, cmd=cmd, logerr=False,
                           level=level)
        if ((ret['rc'] == 0) and (len(ret['out']) == 1) and
                os.path.isabs(ret['out'][0].strip())):
            path = ret['out'][0].strip()
            if hostname not in self._h2which.keys():
                self._h2which.setdefault(hostname, {exe: path})
            else:
                self._h2which[hostname].setdefault(exe, path)
            return path
        else:
            return oexe'''
    
    def which(self, hostname=None, host_platform='linux', exe=None, level=logging.INFOCLI2):
        """
        Generic function of which with remote host support

        :param hostname: hostname (default current host)
        :type hostname: str or None
        :param exe: executable to locate (can be full path also)
                    (if exe is full path then only basename will
                    be used to locate)
        :type exe: str or None
        :param level: logging level, defaults to INFOCLI2
        """
        if exe is None:
            return None

        if hostname is None:
            hostname = socket.gethostname()

        oexe = exe
        exe = os.path.basename(exe)
        if hostname in list(self._h2which.keys()):
            if exe in self._h2which[hostname]:
                return self._h2which[hostname][exe]

        sudo_wrappers_dir = '/opt/tools/wrappers'
        _exe = os.path.join(sudo_wrappers_dir, exe)
        if os.path.isfile(_exe) and os.access(_exe, os.X_OK):
            if hostname not in list(self._h2which.keys()):
                self._h2which.setdefault(hostname, {exe: _exe})
            else:
                self._h2which[hostname].setdefault(exe, _exe)
            return _exe

        # Changes specific to python
        # Use PBS Python if available before looking for system Python
        if exe == 'python3' or exe == 'python':
            py_path = "python"
            return py_path
            pbs_conf = self.parse_pbs_config(hostname)
            print("PBS_CONF ---------------------------------------- %s" %pbs_conf)
            if "PBS_EXEC" in pbs_conf and pbs_conf['PBS_EXEC'].find('\\') > 0:
                py_path = 'python'
                if hostname not in self._h2which.keys():
                    self._h2which.setdefault(hostname, {exe: py_path})
                else:
                    self._h2which[hostname].setdefault(exe, py_path)
                return py_path
            else:
                py_path = pbs_conf['PBS_EXEC'] + '/python/bin/python'
                cmd = ['ls', '-1', py_path]
                ret = self.run_cmd(hostname, cmd, logerr=False)
                if ret['rc'] == 0:
                    if hostname not in self._h2which.keys():
                        self._h2which.setdefault(hostname, {exe: py_path})
                    else:
                        self._h2which[hostname].setdefault(exe, py_path)
                    return py_path

        platform = host_platform.lower()
        if platform == "win32":
            cmd = ['where', exe]
        else:
            cmd = ['which', exe]
        ret = self.run_cmd(hostname, cmd=cmd, logerr=False,
                           level=level)
        if ((ret['rc'] == 0) and (len(ret['out']) == 1) and
                os.path.isabs(ret['out'][0].strip())):
            path = ret['out'][0].strip()
            # For windows, while giving the full path in script, it
            # should be quoted. Otherwise gives error, because it
            # doesn't escape special characters like space in the path.
            if platform == "win32":
                path = '"' + path + '"'
            if hostname not in self._h2which.keys():
                self._h2which.setdefault(hostname, {exe: path})
            else:
                self._h2which[hostname].setdefault(exe, path)
            return path
        else:
            return oexe

    '''def rm(self, hostname=None, path=None, sudo=False, runas=None,
           recursive=False, force=False, cwd=None, logerr=True,
           as_script=False, level=logging.INFOCLI2):
        """
        Generic function of rm with remote host support

        :param hostname: hostname (default current host)
        :type hostname: str or None
        :param path: the path to the files or directories to remove
                     for more than one files or directories pass as
                     list
        :type path: str or None
        :param sudo: whether to remove files or directories as root
                     or not.Defaults to False
        :type sudo: boolean
        :param runas: remove files or directories as given user
                      Defaults to calling user
        :param recursive: remove files or directories and their
                          contents recursively
        :type recursive: boolean
        :param force: force remove files or directories
        :type force: boolean
        :param cwd: working directory on local host from which
                    command is run
        :param logerr: whether to log error messages or not.
                       Defaults to True.
        :type logerr: boolean
        :param as_script: if True, run the rm in a script created
                          as a temporary file that gets deleted after
                          being run. This is used mainly to handle
                          wildcard in path list. Defaults to False.
        :type as_script: boolean
        :param level: logging level, defaults to INFOCLI2
        :returns: True on success otherwise False
        """
        if (path is None) or (len(path) == 0):
            return True

        """
        cmd = [self.which(hostname, 'rm', level=level)]
        if recursive and force:
            cmd += ['-rf']
        else:
            if recursive:
                cmd += ['-r']
            if force:
                cmd += ['-f']
        """
        cmd = ['del']
        if isinstance(path, list):
            for p in path:
                if p == '/':
                    msg = 'encountered a dangerous package path ' + p
                    self.logger.error(msg)
                    return False
            cmd += path
        else:
            if path == '/':
                msg = 'encountered a dangerous package path ' + path
                self.logger.error(msg)
                return False
            cmd += [path]

        ret = self.run_cmd(hostname, cmd=cmd, host_platform="win32",sudo=sudo, logerr=logerr,
                           runas=runas, cwd=cwd, level=level,
                           as_script=as_script)
        if ret['rc'] != 0:
            return False
        return True'''

    def rm(self, hostname=None, path=None, platform="linux",sudo=False, runas=None,
           recursive=False, force=False, cwd=None, logerr=True,
           as_script=False, level=logging.INFOCLI2):
        """
        Generic function of rm with remote host support

        :param hostname: hostname (default current host)
        :type hostname: str or None
        :param path: the path to the files or directories to remove
                     for more than one files or directories pass as
                     list
        :type path: str or None
        :param sudo: whether to remove files or directories as root
                     or not.Defaults to False
        :type sudo: boolean
        :param runas: remove files or directories as given user
                      Defaults to calling user
        :param recursive: remove files or directories and their
                          contents recursively
        :type recursive: boolean
        :param force: force remove files or directories
        :type force: boolean
        :param cwd: working directory on local host from which
                    command is run
        :param logerr: whether to log error messages or not.
                       Defaults to True.
        :type logerr: boolean
        :param as_script: if True, run the rm in a script created
                          as a temporary file that gets deleted after
                          being run. This is used mainly to handle
                          wildcard in path list. Defaults to False.
        :type as_script: boolean
        :param level: logging level, defaults to INFOCLI2
        :returns: True on success otherwise False
        """
        if (path is None) or (len(path) == 0):
            return True

        if hostname in list(self._h2p.keys()):
            platform = self._h2p[hostname]

        if platform == "win32":
            cmd = ['del']
            if recursive:
                cmd += ['/S']
            if force:
                cmd += ['/F']
            # Adding quotes to make windows path with special characters work
            path = '"' + path + '"'
            cmd += [path]
            ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo,
                            logerr=logerr, runas=runas, cwd=cwd, level=level)
        else:
            cmd = [self.which(hostname, exe='rm', level=level)]
            if recursive and force:
                cmd += ['-rf']
            else:
                if recursive:
                    cmd += ['-r']
                if force:
                    cmd += ['-f']

            if isinstance(path, list):
                for p in path:
                    if p == '/':
                        msg = 'encountered a dangerous package path ' + p
                        self.logger.error(msg)
                        return False
                cmd += path
            else:
                if path == '/':
                    msg = 'encountered a dangerous package path ' + path
                    self.logger.error(msg)
                    return False
                cmd += [path]

            ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                               runas=runas, cwd=cwd, level=level,
                               as_script=as_script)
        if ret['rc'] != 0:
            return False
        return True

    def mkdir(self, hostname=None, path=None, mode=None, sudo=False,
              runas=None, parents=True, cwd=None, logerr=True,
              as_script=False, level=logging.INFOCLI2):
        """
        Generic function of mkdir with remote host support

        :param hostname: hostname (default current host)
        :type hostname: str or None
        :param path: the path to the directories to create
                     for more than one directories pass as list
        :type path: str or None
        :param mode: mode to use while creating directories
                     (must be octal like 0777)
        :param sudo: whether to create directories as root or not.
                     Defaults to False
        :type sudo: boolean
        :param runas: create directories as given user. Defaults to
                      calling user
        :param parents: create parent directories as needed. Defaults
                        to True
        :type parents: boolean
        :param cwd: working directory on local host from which
                    command is run
        :type cwd: str or None
        :param logerr: whether to log error messages or not. Defaults
                       to True.
        :type logerr: boolean
        :param as_script: if True, run the command in a script
                          created as a temporary file that gets
                          deleted after being run. This is used
                          mainly to handle wildcard in path list.
                          Defaults to False.
        :type as_script: boolean
        :param level: logging level, defaults to INFOCLI2
        :returns: True on success otherwise False
        """
        if (path is None) or (len(path) == 0):
            return True

        cmd = [self.which(hostname, 'mkdir', level=level)]
        if parents:
            cmd += ['-p']
        if mode is not None:
            mode = '{:o}'.format(mode)
            cmd += ['-m', mode]
        if isinstance(path, list):
            cmd += path
        else:
            cmd += [path]
        ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                           runas=runas, cwd=cwd, level=level,
                           as_script=as_script)
        if ret['rc'] != 0:
            return False
        return True

    def cat(self, hostname=None, filename=None, platform="Linux",sudo=False, runas=None,
            logerr=True, level=logging.INFOCLI2):
        """
        Generic function of cat with remote host support

        :param hostname: hostname (default current host)
        :type hostname: str or None
        :param filename: the path to the filename to cat
        :type filename: str or None
        :param sudo: whether to create directories as root or not.
                     Defaults to False
        :type sudo: boolean
        :param runas: create directories as given user. Defaults
                      to calling user
        :type runas: str or None
        :param logerr: whether to log error messages or not. Defaults
                       to True.
        :type logerr: boolean
        :returns: output of run_cmd
        """
        platform = self.get_platform(hostname)
        platform = platform.lower()
        if "linux" in platform:
            cmd = ['cat', filename]
            rv = self.run_cmd(hostname, cmd=cmd, sudo=sudo,
                              runas=runas, logerr=logerr, level=level)
        else:
            filename = '"' + filename + '"'
            cmd = ['type', filename]
            rv = self.run_cmd(hostname, cmd=cmd, host_platform="win32")
        return rv

    def cmp(self, hostname=None, fileA=None, fileB=None, sudo=False,
            runas=None, logerr=True):
        """
        Compare two files and return 0 if they are identical or
        non-zero if not

        :param hostname: the name of the host to operate on
        :type hostname: str or None
        :param fileA: the first file to compare
        :type fileA: str or None
        :param fileB: the file to compare fileA to
        :type fileB: str or None
        :param sudo: run the command as a privileged user
        :type sudo: boolean
        :param runas: run the cmp command as given user
        :type runas: str or None
        :param logerr: whether to log error messages or not.
                       Defaults to True.
        :type logerr: boolean
        """

        if fileA is None and fileB is None:
            return 0

        if fileA is None or fileB is None:
            return 1

        platform = self.get_platform(hostname)
        platform = platform.lower()
        if "win" in platform:
            cmd = ['comp', fileA, fileB]
        else:
            cmd = ['cmp', fileA, fileB]
        ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, runas=runas,
                           logerr=logerr)
        return ret['rc']

    def useradd(self, name, uid=None, gid=None, shell='/bin/bash',
                create_home_dir=True, home_dir=None, groups=None, logerr=True,
                level=logging.INFOCLI2):
        """
        Add the user

        :param name: User name
        :type name: str
        :param shell: shell to use
        :param create_home_dir: If true then create home directory
        :type create_home_dir: boolean
        :param home_dir: path to home directory
        :type home_dir: str or None
        :param groups: User groups
        """
        self.logger.info('adding user ' + str(name))
        cmd = ['useradd']
        cmd += ['-K', 'UMASK=0022']
        if uid is not None:
            cmd += ['-u', str(uid)]
        if shell is not None:
            cmd += ['-s', shell]
        if gid is not None:
            cmd += ['-g', str(gid)]
        if create_home_dir:
            cmd += ['-m']
        if home_dir is not None:
            cmd += ['-d', home_dir]
        if ((groups is not None) and (len(groups) > 0)):
            cmd += ['-G', ','.join([str(g) for g in groups])]
        cmd += [str(name)]
        ret = self.run_cmd(cmd=cmd, logerr=logerr, sudo=True, level=level)
        if ((ret['rc'] != 0) and logerr):
            raise PtlUtilError(rc=ret['rc'], rv=False, msg=ret['err'])

    def userdel(self, name, del_home=True, force=True, logerr=True,
                level=logging.INFOCLI2):
        """
        Delete the user

        :param del_home: If true then delete user home
        :type del_home: boolean
        :param force: If true then delete forcefully
        :type force: boolean
        """
        cmd = ['userdel']
        if del_home:
            cmd += ['-r']
        if force:
            cmd += ['-f']
        cmd += [str(name)]
        self.logger.info('deleting user ' + str(name))
        ret = self.run_cmd(cmd=cmd, sudo=True, logerr=False, level=level)
        if ((ret['rc'] != 0) and logerr):
            raise PtlUtilError(rc=ret['rc'], rv=False, msg=ret['err'])

    def groupadd(self, name, gid=None, logerr=True, level=logging.INFOCLI2):
        """
        Add a group
        """
        self.logger.info('adding group ' + str(name))
        cmd = ['groupadd']
        if gid is not None:
            cmd += ['-g', str(gid)]
        cmd += [str(name)]
        ret = self.run_cmd(cmd=cmd, sudo=True, logerr=False, level=level)
        if ((ret['rc'] != 0) and logerr):
            raise PtlUtilError(rc=ret['rc'], rv=False, msg=ret['err'])

    def groupdel(self, name, logerr=True, level=logging.INFOCLI2):
        self.logger.info('deleting group ' + str(name))
        cmd = ['groupdel', str(name)]
        ret = self.run_cmd(cmd=cmd, sudo=True, logerr=logerr, level=level)
        if ((ret['rc'] != 0) and logerr):
            raise PtlUtilError(rc=ret['rc'], rv=False, msg=ret['err'])

    '''def create_temp_file(self, hostname=None, suffix='', prefix='PtlPbs',
                         dirname=None, text=False, asuser=None, body=None,
                         level=logging.INFOCLI2):
        """
        Create a temp file by calling tempfile.mkstemp

        :param hostname: the hostname on which to query tempdir from
        :type hostname: str or None
        :param suffix: the file name will end with this suffix
        :type suffix: str
        :param prefix: the file name will begin with this prefix
        :type prefix: str
        :param dirname: the file will be created in this directory
        :type dirname: str or None
        :param text: the file is opened in text mode is this is true
                     else in binary mode
        :type text: boolean
        :param asuser: Optional username or uid of temp file owner
        :type asuser: str or None
        :param body: Optional content to write to the temporary file
        :type body: str or None
        :param level: logging level, defaults to INFOCLI2
        :type level: int
        """

        # create a temp file as current user
        (fd, tmpfile) = tempfile.mkstemp(suffix, prefix, dirname, text)

        # write user provided contents to file
        if body is not None:
            if isinstance(body, list):
                os.write(fd, "\n".join(body).encode())
            else:
                os.write(fd, body.encode())
        os.close(fd)

        if not hostname and asuser:
            asuser = PbsUser.get_user(asuser)
            if asuser.host:
                hostname = asuser.host

        # if temp file to be created on remote host
        if not self.is_localhost(hostname):
            if asuser is not None:
                # by default mkstemp creates file with 0600 permission
                # to create file as different user first change the file
                # permission to 0644 so that other user has read permission
                self.chmod(path=tmpfile, mode=0o644)
                # copy temp file created  on local host to remote host
                # as different user
                self.run_copy(hostname, src=tmpfile, dest=tmpfile,
                              runas=asuser, preserve_permission=False,
                              level=level)
            else:
                # copy temp file created on localhost to remote as current user
                self.run_copy(hostname, src=tmpfile, dest=tmpfile,
                              preserve_permission=False, level=level)
                # remove local temp file
                os.unlink(tmpfile)
        if asuser is not None:
            # by default mkstemp creates file with 0600 permission
            # to create file as different user first change the file
            # permission to 0644 so that other user has read permission
            self.chmod(hostname, tmpfile, mode=0o644)
            # since we need to create as differnt user than current user
            # create a temp file just to get temp file name with absolute path
            (_, tmpfile2) = tempfile.mkstemp(suffix, prefix, dirname, text)
            # remove the newly created temp file
            os.unlink(tmpfile2)
            # copy the orginal temp as new temp file
            self.run_copy(hostname, src=tmpfile, dest=tmpfile2, runas=asuser,
                          preserve_permission=False, level=level)
            # remove original temp file
            os.unlink(tmpfile)
            self.tmpfilelist.append(tmpfile2)
            return tmpfile2
        self.tmpfilelist.append(tmpfile)
        return tmpfile'''
    
    def create_temp_file(self, hostname=None, suffix='', prefix='PtlPbs',
                         dirname=None, text=False, asuser=None, body=None,
                         level=logging.INFOCLI2):
        """
        Create a temp file by calling tempfile.mkstemp

        :param hostname: the hostname on which to query tempdir from
        :type hostname: str or None
        :param suffix: the file name will end with this suffix
        :type suffix: str
        :param prefix: the file name will begin with this prefix
        :type prefix: str
        :param dirname: the file will be created in this directory
        :type dirname: str or None
        :param text: the file is opened in text mode is this is true
                     else in binary mode
        :type text: boolean
        :param asuser: Optional username or uid of temp file owner
        :type asuser: str or None
        :param body: Optional content to write to the temporary file
        :type body: str or None
        :param level: logging level, defaults to INFOCLI2
        :type level: int
        """

        # create a temp file as current user
        (fd, tmpfile) = tempfile.mkstemp(suffix, prefix, dirname, text)
        remote_tmpfile = None
        # write user provided contents to file
        if body is not None:
            if isinstance(body, list):
                os.write(fd, "\n".join(body).encode())
            else:
                os.write(fd, body.encode())
        os.close(fd)

        '''
        if not hostname and asuser:
            asuser = PbsUser.get_user(asuser)
            if asuser.host:
                hostname = asuser.host
        '''

        # if temp file to be created on remote host
        if not self.is_localhost(hostname):
            '''
            If file to be created on remote host, then we need to check whether
            remote host is windows or linux and based on that decide the path 
            of the temporary file.
            '''
            local_host = socket.gethostname()
            remote_platform = self.get_platform(hostname)
            local_platform = self.get_platform(local_host)
            if remote_platform != local_platform:
                if remote_platform == "win32":
                    remote_tmpfile = "C:\\Users\\saksham\\AppData\\Local\\Temp\\"
                else:
                    remote_tmpfile = "/tmp/"
                remote_tmpfile += os.path.basename(tmpfile)
            else:
                remote_tmpfile = tmpfile
            print("----------temp file------------")
            print(remote_tmpfile)
            if asuser is not None:
                # by default mkstemp creates file with 0600 permission
                # to create file as different user first change the file
                # permission to 0644 so that other user has read permission
                print("TEMPFILE ---------------------------- %s" %tmpfile)
                self.chmod(hostname=hostname,path=remote_tmpfile, mode=0o644)
                # copy temp file created  on local host to remote host
                # as different user
                print("hostname ------------------ %s"%hostname)
                print("remote_tempfile ------------------------------ %s"%remote_tmpfile)
                self.run_copy(hostname, src=tmpfile, dest=remote_tmpfile, runas=asuser,
                              preserve_permission=False, level=level)
            else:
                # copy temp file created on localhost to remote as current user
                self.run_copy(hostname, src=tmpfile, dest=remote_tmpfile,
                              preserve_permission=False, level=level)
                # remove local temp file
                os.unlink(tmpfile)
        if asuser is not None:
            # by default mkstemp creates file with 0600 permission
            # to create file as different user first change the file
            # permission to 0644 so that other user has read permission
            #  ----- >self.chmod(hostname, tmpfile, mode=0o644)
            # since we need to create as differnt user than current user
            # create a temp file just to get temp file name with absolute path
            (_, tmpfile2) = tempfile.mkstemp(suffix, prefix, dirname, text)
            # remove the newly created temp file
            #os.unlink(tmpfile2)
            # copy the orginal temp as new temp file
            #print("tempfile2 ------------------------------ %s"%tmpfile2)
            #print("hostname ------------------------------- %s"%hostname)
            remote_platform = self.get_platform(hostname)
            if remote_platform == "win32":
                remote_tmpfile2 = "C:\\Users\\saksham\\AppData\\Local\\Temp\\"
            else:
                remote_tmpfile2 = "/tmp/"
            remote_tmpfile2 += os.path.basename(tmpfile2)
            print("----------remote_tempfile2 ------------------------------ %s"%remote_tmpfile2)
            self.run_copy(hostname, src=tmpfile, dest=remote_tmpfile2, runas=asuser,
                          preserve_permission=False, level=level)
            # remove original temp file
            #os.unlink(tmpfile)
            self.tmpfilelist.append(tmpfile2)
            return remote_tmpfile2
        self.tmpfilelist.append(tmpfile)
        #print("returning tempfile ------------------------------------ %s"%tmpfile)
        if remote_tmpfile:
            return remote_tmpfile
        else:
            return tmpfile

    def create_temp_dir(self, hostname=None, suffix='', prefix='PtlPbs',
                        dirname=None, asuser=None, asgroup=None, mode=None,
                        level=logging.INFOCLI2):
        """
        Create a temp dir by calling ``tempfile.mkdtemp``
        :param hostname: the hostname on which to query tempdir from
        :type hostname: str or None
        :param suffix: the directory name will end with this suffix
        :type suffix: str
        :param prefix: the directory name will begin with this prefix
        :type prefix: str
        :param dir: the directory will be created in this directory
        :type dir: str or None
        :param uid: Optional username or uid of temp directory owner
        :param gid: Optional group name or gid of temp directory
                    group owner
        :param mode: Optional mode bits to assign to the temporary
                     directory
        :param level: logging level, defaults to INFOCLI2
        """
        # create a temp dir as current user
        tmpdir = tempfile.mkdtemp(suffix, prefix)
        if dirname is not None:
            dirname = str(dirname)
            self.run_copy(hostname, src=tmpdir, dest=dirname, runas=asuser,
                          recursive=True,
                          preserve_permission=False, level=level)
            tmpdir = dirname + tmpdir[4:]

        # if temp dir to be created on remote host
        if not self.is_localhost(hostname):
            if asuser is not None:
                # by default mkstemp creates dir with 0600 permission
                # to create dir as different user first change the dir
                # permission to 0644 so that other user has read permission
                self.chmod(path=tmpdir, mode=0o755)
                # copy temp dir created on local host to remote host
                # as different user
                self.run_copy(hostname, src=tmpdir, dest=tmpdir, runas=asuser,
                              recursive=True,
                              preserve_permission=False, level=level)
            else:
                # copy temp dir created on localhost to remote as current user
                self.run_copy(hostname, src=tmpdir, dest=tmpdir,
                              preserve_permission=False, level=level)
            # remove local temp dir
            os.rmdir(tmpdir)
        if asuser is not None:
            # by default mkdtemp creates dir with 0600 permission
            # to create dir as different user first change the dir
            # permission to 0644 so that other user has read permission
            self.chmod(path=tmpdir, mode=0o755)
            # since we need to create as differnt user than current user
            # create a temp dir just to get temp dir name with absolute path
            tmpdir2 = tempfile.mkdtemp(suffix, prefix, dirname)
            os.rmdir(tmpdir2)
            # copy the orginal temp as new temp dir
            self.run_copy(hostname, src=tmpdir, dest=tmpdir2, runas=asuser,
                          recursive=True,
                          preserve_permission=False, level=level)
            # remove original temp dir
            os.rmdir(tmpdir)
            self.tmpdirlist.append(tmpdir2)
            return tmpdir2
        self.tmpdirlist.append(tmpdir)
        return tmpdir

    def parse_strace(self, lines):
        """
        strace parsing. Just the regular expressions for now
        """
        timestamp_pat = r'(^(\d{2}:\d{2}:\d{2})(.\d+){0,1} |^(\d+.\d+) ){0,1}'
        exec_pat = r'execve\(("[^"]+"), \[([^]]+)\], [^,]+ = (\d+)$'

        timestamp_exec_re = re.compile(timestamp_pat + exec_pat)

        for line in lines:
            m = timestamp_exec_re.match(line)
            if m:
                print(line)

    def getgrall(self):
        if self.is_linux:
            import grp
            _groups = grp.getgrall()
            groups = []
            for group in _groups:
                _group = PbsGroup(name=group.gr_name, gid=group.gr_gid,
                                  sid=None)
                for mem in group.gr_mem:
                    _mem = self.getpwnam(mem)
                    _mem.pw_groups.append(_group)
                    _group.gr_mem.append(_mem)
                groups.append(_group)
            return groups
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-AllGroup'])
            if ret['rc'] != 0:
                msg = 'Failed to get groups'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _groups = self.__parse_ps_ug(ret['out'])
            groups = []
            for v in _groups.values():
                gid = v['sid'].split('-')[-1]
                _group = PbsGroup(name=v['name'], gid=gid, sid=v['sid'])
                members = v['mem']
                if members == '__NONE__':
                    members = []
                else:
                    members = members.split(',')
                for mem in members:
                    _mem = self.getpwnam(mem)
                    _mem.pw_groups.append(_group)
                    _group.gr_mem.append(_mem)
                groups.append(_group)
            return groups
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getgrgid(self, gid):
        gid = int(gid)
        if self.is_linux:
            import grp
            _group = grp.getgrgid(gid)
            group = PbsGroup(name=_group.gr_name, gid=_group.gr_gid,
                             sid=None)
            for mem in _group.gr_mem:
                _mem = self.getpwnam(mem)
                _mem.pw_groups.append(group)
                group.gr_mem.append(_mem)
            return group
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-GroupById', '-Id', str(gid)])
            if ret['rc'] != 0:
                msg = 'Failed to get group'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _group = self.__parse_ps_ug(ret['out']).values()[0]
            gid = _group['sid'].split('-')[-1]
            group = PbsGroup(name=_group['name'], gid=gid, sid=_group['sid'])
            members = _group['mem']
            if members == '__NONE__':
                members = []
            else:
                members = members.split(',')
            for mem in members:
                _mem = self.getpwnam(mem)
                _mem.pw_groups.append(group)
                group.gr_mem.append(_mem)
            return group
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getgrnam(self, name):
        name = str(name)
        if self.is_linux:
            import grp
            _group = grp.getgrnam(name)
            group = PbsGroup(name=_group.gr_name, gid=_group.gr_gid,
                             sid=None)
            for mem in _group.gr_mem:
                _mem = self.getpwnam(mem)
                _mem.pw_groups.append(group)
                group.gr_mem.append(_mem)
            return group
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-GroupByName', '-Name', name])
            if ret['rc'] != 0:
                msg = 'Failed to get group'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _group = self.__parse_ps_ug(ret['out']).values()[0]
            gid = _group['sid'].split('-')[-1]
            group = PbsGroup(name=_group['name'], gid=gid, sid=_group['sid'])
            members = _group['mem']
            if members == '__NONE__':
                members = []
            else:
                members = members.split(',')
            for mem in members:
                _mem = self.getpwnam(mem)
                _mem.pw_groups.append(group)
                group.gr_mem.append(_mem)
            return group
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def get_current_user(self):
        """
        helper function to return the name of the current user
        """
        if self._current_user is not None:
            return self._current_user
        import getpass
        self._current_user = getpass.getuser()
        return self._current_user
        
    def getuid(self):
        if self.is_linux:
            return os.getuid()
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-CurrentUserId'])
            if ret['rc'] != 0:
                msg = 'Failed to get uid!'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            else:
                return int(ret['out'][0].strip())
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getgid(self):
        if self.is_linux:
            return os.getgid()
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-CurrentGroupId'])
            if ret['rc'] != 0:
                msg = 'Failed to get gid!'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            else:
                return int(ret['out'][0].strip())
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getpwall(self):
        if self.is_linux:
            import pwd
            _users = pwd.getpwall()
            users = []
            for user in _users:
                _user = PbsUser(name=user.pw_name, uid=user.pw_uid,
                                gid=user.pw_gid, gecos=user.pw_gecos,
                                homedir=user.pw_dir, shell=user.pw_shell,
                                sid=None)
                users.append(_user)
            return users
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-AllUser'])
            if ret['rc'] != 0:
                msg = 'Failed to get users!'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _users = self.__parse_ps_ug(ret['out'])
            users = []
            for v in _users.values():
                uid = v['sid'].split('-')[-1]
                _user = PbsUser(name=v['name'], uid=uid, gid=v['gid'],
                                gecos=v['gecos'], homedir=v['dir'],
                                # TODO: find shell
                                shell=None, sid=v['sid'])
                users.append(_user)
            return users
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getpwnam(self, name):
        name = str(name)
        if self.is_linux:
            import pwd
            user = pwd.getpwnam(name)
            return PbsUser(name=user.pw_name, uid=user.pw_uid,
                           gid=user.pw_gid, gecos=user.pw_gecos,
                           homedir=user.pw_dir, shell=user.pw_shell,
                           sid=None)
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-UserByName', '-Name', name])
            if ret['rc'] != 0:
                msg = 'Failed to get user'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _user = self.__parse_ps_ug(ret['out']).values()[0]
            uid = _user['sid'].split('-')[-1]
            return PbsUser(name=_user['name'], uid=uid, gid=_user['gid'],
                           gecos=_user['gecos'], homedir=_user['dir'],
                           # TODO: find shell
                           shell=None, sid=_user['sid'])
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getpwuid(self):
        uid = int(uid)
        if self.is_linux:
            import pwd
            user = pwd.getpwuid(uid)
            return PbsUser(name=user.pw_name, uid=user.pw_uid,
                           gid=user.pw_gid, gecos=user.pw_gecos,
                           homedir=user.pw_dir, shell=user.pw_shell,
                           sid=None)
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-UserById', '-Id', str(uid)])
            if ret['rc'] != 0:
                msg = 'Failed to get user'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _user = self.__parse_ps_ug(ret['out']).values()[0]
            uid = _user['sid'].split('-')[-1]
            return PbsUser(name=_user['name'], uid=uid, gid=_user['gid'],
                           gecos=_user['gecos'], homedir=_user['dir'],
                           # TODO: find shell
                           shell=None, sid=_user['sid'])
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')
                               
