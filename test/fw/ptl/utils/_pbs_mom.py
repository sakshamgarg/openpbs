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

"""
import ast
import base64
import collections
import copy
import datetime
import grp
import json
import os
import pickle
import pwd
import random
import re
import socket
import string
import sys
import tempfile
import threading
import time
import traceback
from collections import OrderedDict
from distutils.version import LooseVersion
from operator import itemgetter

from ptl.lib.pbs_api_to_cli import api_to_cli
from ptl.utils.pbs_cliutils import CliUtils
from ptl.utils.pbs_dshutils import DshUtils, PtlUtilError
from ptl.utils.pbs_procutils import ProcUtils
from ptl.utils.pbs_testusers import (ROOT_USER, TEST_USER, PbsUser,
                                     DAEMON_SERVICE_USER)
"""

import logging
import ptl



def get_mom_obj(name=None, attrs={}, pbsconf_file=None, snapmap={},
                 snap=None, server=None, db_access=None):
    return MoM(name, attrs, pbsconf_file, snapmap,
                 snap, server, db_access)


from ptl.lib.pbs_testlib import *

class MoM(PBSService):

    """
    Container for MoM properties.
    Provides various MoM operations, such as creation, insertion,
    deletion of vnodes.

    :param name: The hostname of the server. Defaults to calling
                 pbs_default()
    :type name: str or None
    :param attrs: Dictionary of attributes to set, these will
                  override defaults.
    :type attrs: Dictionary
    :param pbsconf_file: path to config file to parse for
                         ``PBS_HOME``, ``PBS_EXEC``, etc
    :type pbsconf_file: str or None
    :param snapmap: A dictionary of PBS objects ``(node,server,etc)``
                    to mapped files from PBS snap directory
    :type snapmap: Dictionary
    :param snap: path to PBS snap directory (This will overrides
                 snapmap)
    :type snap: str or None
    :param server: A PBS server instance to which this mom is associated
    :param db_acccess: set to either file containing credentials to DB
                       access or dictionary containing
                       {'dbname':...,'user':...,'port':...}
    :type db_access: str or dictionary
    """
    dflt_attributes = {}
    conf_to_cmd_map = {'PBS_MOM_SERVICE_PORT': '-M',
                       'PBS_MANAGER_SERVICE_PORT': '-R',
                       'PBS_HOME': '-d'}

    def __init__(self, name=None, attrs={}, pbsconf_file=None, snapmap={},
                 snap=None, server=None, db_access=None):
        if server is not None:
            self.server = server
            if snap is None and self.server.snap is not None:
                snap = self.server.snap
            if (len(snapmap) == 0) and (len(self.server.snapmap) != 0):
                snapmap = self.server.snapmap
        else:
            self.server = Server(name, pbsconf_file=pbsconf_file,
                                 db_access=db_access, snap=snap,
                                 snapmap=snapmap)

        PBSService.__init__(self, name, attrs, self.dflt_attributes,
                            pbsconf_file, snap=snap, snapmap=snapmap)
        _m = ['mom ', self.shortname]
        if pbsconf_file is not None:
            _m += ['@', pbsconf_file]
        _m += [': ']
        self.logprefix = "".join(_m)
        self.pi = PBSInitServices(hostname=self.hostname,
                                  conf=self.pbs_conf_file)
        self.configd = os.path.join(self.pbs_conf['PBS_HOME'], 'mom_priv',
                                    'config.d')
        self.config = {}
        if self.platform == 'cray' or self.platform == 'craysim':
            usecp = os.path.realpath('/home')
            if self.platform == 'cray':
                if os.path.exists('/opt/cray/alps/default/bin/apbasil'):
                    alps_client = '/opt/cray/alps/default/bin/apbasil'
                else:
                    alps_client = self.du.which(exe='apbasil')
            else:
                alps_client = "/opt/alps/apbasil.sh"
            self.dflt_config = {'$clienthost': self.server.hostname,
                                '$vnodedef_additive': 0,
                                '$alps_client': alps_client,
                                '$usecp': '*:%s %s' % (usecp, usecp)}
        elif self.platform == 'shasta':
            usecp = os.path.realpath('/lus')
            self.dflt_config = {'$clienthost': self.server.hostname,
                                '$usecp': '*:%s %s' % (usecp, usecp)}
        else:
            self.dflt_config = {'$clienthost': self.server.hostname}
        self.version = None
        self._is_cpuset_mom = None

        # If this is true, the mom will revert to default.
        # This is true by default, but can be set to False if
        # required by a test
        self.revert_to_default = True
        self.sleep_cmd = '/bin/sleep'

    def __del__(self):
        del self.__dict__

    def run_printjob(self, hostname=None, job_id=None):
        """
        Run the printjob command for the given job id
        :param hostname: mom hostname
        :type hostname: string
        :param job_id: job's id for which to run printjob cmd
        :type job_id: string
        """
        if hostname is None:
            hostname = self.hostname
        
        if job_id is None:
            return None
        
        printjob = os.path.join(self.pbs_conf['PBS_EXEC'], 'bin',
                                'printjob')
        jbfile = os.path.join(self.pbs_conf['PBS_HOME'], 'mom_priv',
                              'jobs', job_id + '.JB')
        ret = self.du.run_cmd(hostname, cmd=[printjob, jbfile],
                              sudo=True)
        return ret
    
    def check_suspended_state(self, hostname=None, pid=None):
        """
        Check if given job is in suspended state or not
        :param hostname: mom hostname
        :type hostname: string
        """

        if hostname is None:
            hostname = self.hostname
        
        if pid is None:
            self.logger.error("Could not get pid to check the state")
            return False
        state = 'T'
        rv = self.pu.get_proc_state(hostname, pid)
        if rv != state:
            return False
        childlist = self.pu.get_proc_children(hostname, pid)
        for child in childlist:
            rv = self.pu.get_proc_state(hostname, child)
            if rv != state:
                return False
        return True
    
    def isUp(self, max_attempts=None):
        """
        Check for PBS mom up
        """
        # Poll for few seconds to see if mom is up and node is free
        if max_attempts is None:
            max_attempts = self.ptl_conf['max_attempts']
        for _ in range(max_attempts):
            rv = super(MoM, self)._isUp(self)
            if rv:
                break
            time.sleep(1)
        if rv:
            try:
                nodes = self.server.status(NODE, id=self.shortname)
                if nodes:
                    attr = {'state': (MATCH_RE,
                                      'free|provisioning|offline|job-busy')}
                    self.server.expect(NODE, attr, id=self.shortname)
            # Ignore PbsStatusError if mom daemon is up but there aren't
            # any mom nodes
            except PbsStatusError:
                pass
            except PtlExpectError:
                rv = False
        return rv

    def signal(self, sig):
        """
        Send signal to PBS mom
        """
        self.logger.info(self.logprefix + 'sent signal ' + sig)
        return super(MoM, self)._signal(sig, inst=self)

    def get_pid(self):
        """
        Get the PBS mom pid
        """
        return super(MoM, self)._get_pid(inst=self)

    def all_instance_pids(self):
        """
        Get all pids of a instance
        """
        return super(MoM, self)._all_instance_pids(inst=self)

    def start(self, args=None, launcher=None):
        """
        Start the PBS mom

        :param args: Arguments to start the mom
        :type args: str or None
        :param launcher: Optional utility to invoke the launch of the service
        :type launcher: str or list or None
        """
        if args is not None or launcher is not None:
            return super(MoM, self)._start(inst=self, args=args,
                                           cmd_map=self.conf_to_cmd_map,
                                           launcher=launcher)
        else:
            try:
                rv = self.pi.start_mom()
                pid = self._validate_pid(self)
                if pid is None:
                    raise PbsServiceError(rv=False, rc=-1,
                                          msg="Could not find PID")
            except PbsInitServicesError as e:
                raise PbsServiceError(rc=e.rc, rv=e.rv, msg=e.msg)
            return rv

    def stop(self, sig=None):
        """
        Stop the PBS mom

        :param sig: Signal to stop the PBS mom
        :type sig: str
        """
        if sig is not None:
            self.logger.info(self.logprefix + 'stopping MoM on host ' +
                             self.hostname)
            return super(MoM, self)._stop(sig, inst=self)
        else:
            try:
                self.pi.stop_mom()
            except PbsInitServicesError as e:
                raise PbsServiceError(rc=e.rc, rv=e.rv, msg=e.msg)
            return True

    def restart(self):
        """
        Restart the PBS mom
        """
        if self.isUp():
            if not self.stop():
                return False
        return self.start()

    def log_match(self, msg=None, id=None, n=50, tail=True, allmatch=False,
                  regexp=False, max_attempts=None, interval=None,
                  starttime=None, endtime=None, level=logging.INFO,
                  existence=True):
        """
        Match given ``msg`` in given ``n`` lines of MoM log

        :param msg: log message to match, can be regex also when
                    ``regexp`` is True
        :type msg: str
        :param id: The id of the object to trace. Only used for
                   tracejob
        :type id: str
        :param n: 'ALL' or the number of lines to search through,
                  defaults to 50
        :type n: str or int
        :param tail: If true (default), starts from the end of
                     the file
        :type tail: bool
        :param allmatch: If True all matching lines out of then
                         parsed are returned as a list. Defaults
                         to False
        :type allmatch: bool
        :param regexp: If true msg is a Python regular expression.
                       Defaults to False
        :type regexp: bool
        :param max_attempts: the number of attempts to make to find
                             a matching entry
        :type max_attempts: int
        :param interval: the interval between attempts
        :type interval: int
        :param starttime: If set ignore matches that occur before
                          specified time
        :type starttime: float
        :param endtime: If set ignore matches that occur after
                        specified time
        :type endtime: float
        :param level: The logging level, defaults to INFO
        :type level: int
        :param existence: If True (default), check for existence of
                        given msg, else check for non-existence of
                        given msg.
        :type existence: bool

        :return: (x,y) where x is the matching line
                 number and y the line itself. If allmatch is True,
                 a list of tuples is returned.
        :rtype: tuple
        :raises PtlLogMatchError:
                When ``existence`` is True and given
                ``msg`` is not found in ``n`` line
                Or
                When ``existence`` is False and given
                ``msg`` found in ``n`` line.

        .. note:: The matching line number is relative to the record
                  number, not the absolute line number in the file.
        """
        return self._log_match(self, msg, id, n, tail, allmatch, regexp,
                               max_attempts, interval, starttime, endtime,
                               level, existence)

    def pbs_version(self):
        """
        Get the PBS version
        """
        if self.version:
            return self.version

        exe = os.path.join(self.pbs_conf['PBS_EXEC'], 'sbin', 'pbs_mom')
        version = self.du.run_cmd(self.hostname,
                                  [exe, '--version'], sudo=True)['out']
        if version:
            self.logger.debug(version)
            # in some cases pbs_mom --version may return multiple lines, we
            # only care about the one that carries pbs_version information
            for ver in version:
                if 'pbs_version' in ver:
                    version = ver.split('=')[1].strip()
                    break
        else:
            version = self.log_match('pbs_version', tail=False)
            if version:
                version = version[1].strip().split('=')[1].strip()
            else:
                version = "unknown"

        self.version = LooseVersion(version)

        return self.version

    def delete_vnodes(self):
        rah = ATTR_rescavail + '.host'
        rav = ATTR_rescavail + '.vnode'
        a = {rah: self.hostname, rav: None}
        try:
            _vs = self.server.status(HOST, a, id=self.hostname)
        except PbsStatusError:
            try:
                _vs = self.server.status(HOST, a, id=self.shortname)
            except PbsStatusError as e:
                err_msg = e.msg[0].rstrip()
                if (err_msg.endswith('Server has no node list') or
                        err_msg.endswith('Unknown node')):
                    _vs = []
                else:
                    raise e
        vs = []
        for v in _vs:
            if v[rav].split('.')[0] != v[rah].split('.')[0]:
                vs.append(v['id'])
        if len(vs) > 0:
            self.server.manager(MGR_CMD_DELETE, VNODE, id=vs)

    def revert_to_defaults(self, delvnodedefs=True):
        """
        1. ``Revert MoM configuration to defaults.``

        2. ``Remove epilogue and prologue``

        3. ``Delete all vnode definitions
        HUP MoM``

        :param delvnodedefs: if True (the default) delete all vnode
                             definitions and restart the MoM
        :type delvnodedefs: bool

        :returns: True on success and False otherwise
        """
        self.logger.info(self.logprefix +
                         'reverting configuration to defaults')
        restart = False
        if not self.has_snap:
            self.delete_pelog()
            if delvnodedefs and self.has_vnode_defs():
                restart = True
                if not self.delete_vnode_defs():
                    return False
                self.delete_vnodes()
            if not (self.config == self.dflt_config):
                # Clear older mom configuration. Apply default.
                self.config = {}
                self.apply_config(self.dflt_config, hup=False, restart=True)
            if restart:
                self.restart()
            else:
                self.signal('-HUP')
            return self.isUp()
        return True

    def save_configuration(self, outfile=None, mode='w'):
        """
        Save a MoM ``mom_priv/config``

        :param outfile: Optional Path to a file to which configuration
                        is saved, when not provided, data is saved in
                        class variable saved_config
        :type outfile: str
        :param mode: the mode in which to open outfile to save
                     configuration.
        :type mode: str
        :returns: True on success, False on error

        .. note:: first object being saved should open this file
                  with 'w' and subsequent calls from other objects
                  should save with mode 'a' or 'a+'. Defaults to a+
        """
        conf = {}
        mpriv = os.path.join(self.pbs_conf['PBS_HOME'], 'mom_priv')
        cf = os.path.join(mpriv, 'config')
        self._save_config_file(conf, cf)

        if os.path.isdir(os.path.join(mpriv, 'config.d')):
            for f in self.du.listdir(path=os.path.join(mpriv, 'config.d'),
                                     sudo=True):
                self._save_config_file(conf,
                                       os.path.join(mpriv, 'config.d', f))
        mconf = {self.hostname: conf}
        if MGR_OBJ_NODE not in self.server.saved_config:
            self.server.saved_config[MGR_OBJ_NODE] = {}
        self.server.saved_config[MGR_OBJ_NODE].update(mconf)
        if outfile is not None:
            try:
                with open(outfile, mode) as f:
                    json.dump(self.server.saved_config, f)
            except:
                self.logger.error('error saving configuration to ' + outfile)
                return False
        return True

    def load_configuration(self, infile):
        """
        load mom configuration from saved file infile
        """
        rv = self._load_configuration(infile, MGR_OBJ_NODE)
        self.signal('-HUP')
        return rv

    def is_cray(self):
        """
        Returns True if the version of PBS used was built for Cray platforms
        """
        try:
            self.log_match("alps_client", n='ALL', tail=False, max_attempts=1)
        except PtlLogMatchError:
            return False
        else:
            return True

    def is_shasta(self):
        """
        Returns True if the version of PBS used is installed on Shasta platform
        """
        if self.platform == 'shasta':
            return True
        else:
            return False

    def is_cpuset_mom(self):
        """
        Check for cgroup cpuset enabled system
        """
        if self._is_cpuset_mom is not None:
            return self._is_cpuset_mom
        hpe_file1 = "/etc/sgi-compute-node-release"
        hpe_file2 = "/etc/sgi-known-distributions"
        ret1 = self.du.isfile(self.hostname, path=hpe_file1)
        ret2 = self.du.isfile(self.hostname, path=hpe_file2)
        if ret1 or ret2:
            self._is_cpuset_mom = True
        else:
            self._is_cpuset_mom = False
        return self._is_cpuset_mom

    def create_vnode_def(self, name, attrs={}, numnodes=1, sharednode=True,
                         pre='[', post=']', usenatvnode=False, attrfunc=None,
                         vnodes_per_host=1):
        """
        Create a vnode definition string representation

        :param name: The prefix for name of vnode to create,
                     name of vnode will be prefix + pre + <num> +
                     post
        :type name: str
        :param attrs: Dictionary of attributes to set on each vnode
        :type attrs: Dictionary
        :param numnodes: The number of vnodes to create
        :type numnodes: int
        :param sharednode: If true vnodes are shared on a host
        :type sharednode: bool
        :param pre: The symbol preceding the numeric value of that
                    vnode.
        :type pre: str
        :param post: The symbol following the numeric value of that
                     vnode.
        :type post: str
        :param usenatvnode: use the natural vnode as the first vnode
                            to allocate this only makes sense
                            starting with PBS 11.3 when natural
                            vnodes are reported as a allocatable
        :type usenatvnode: bool
        :param attrfunc: function to customize the attributes,
                         signature is (name, numnodes, curnodenum,
                         attrs), must return a dict that contains
                         new or modified attrs that will be added to
                         the vnode def. The function is called once
                         per vnode being created, it does not modify
                         attrs itself across calls.
        :param vnodes_per_host: number of vnodes per host
        :type vnodes_per_host: int
        :returns: A string representation of the vnode definition
                  file
        """
        sethost = False

        attribs = attrs.copy()
        if not sharednode and 'resources_available.host' not in attrs:
            sethost = True

        if attrfunc is None:
            customattrs = attribs

        vdef = ["$configversion 2"]

        # altering the natural vnode information
        if numnodes == 0:
            for k, v in attribs.items():
                vdef += [name + ": " + str(k) + "=" + str(v)]
        else:
            if usenatvnode:
                if attrfunc:
                    customattrs = attrfunc(name, numnodes, "", attribs)
                for k, v in customattrs.items():
                    vdef += [self.shortname + ": " + str(k) + "=" + str(v)]
                # account for the use of the natural vnode
                numnodes -= 1
            else:
                # ensure that natural vnode is not allocatable by the scheduler
                vdef += [self.shortname + ": resources_available.ncpus=0"]
                vdef += [self.shortname + ": resources_available.mem=0"]

        for n in range(numnodes):
            vnid = name + pre + str(n) + post
            if sethost:
                if vnodes_per_host > 1:
                    if n % vnodes_per_host == 0:
                        _nid = vnid
                    else:
                        _nid = name + pre + str(n - n % vnodes_per_host) + post
                    attribs['resources_available.host'] = _nid
                else:
                    attribs['resources_available.host'] = vnid

            if attrfunc:
                customattrs = attrfunc(vnid, numnodes, n, attribs)
            for k, v in customattrs.items():
                vdef += [vnid + ": " + str(k) + "=" + str(v)]

        if numnodes == 0:
            nn = 1
        else:
            nn = numnodes
        if numnodes > 1:
            vnn_msg = ' vnodes '
        else:
            vnn_msg = ' vnode '

        self.logger.info(self.logprefix + 'created ' + str(nn) +
                         vnn_msg + name + ' with attr ' +
                         str(attribs) + ' on host ' + self.hostname)
        vdef += ["\n"]
        del attribs
        return "\n".join(vdef)

    def add_checkpoint_abort_script(self, dirname=None, body=None,
                                    abort_time=30):
        """
        Add checkpoint script in the mom config.
        returns: a temp file for checkpoint script
        """
        chk_file = self.du.create_temp_file(hostname=self.hostname, body=body,
                                            dirname=dirname)
        self.du.chmod(hostname=self.hostname, path=chk_file, mode=0o700)
        self.du.chown(hostname=self.hostname, path=chk_file, runas=ROOT_USER,
                      uid=0, gid=0)
        c = {'$action checkpoint_abort':
             str(abort_time) + ' !' + chk_file + ' %sid'}
        self.add_config(c)
        return chk_file

    def add_restart_script(self, dirname=None, body=None,
                           abort_time=30):
        """
        Add restart script in the mom config.
        returns: a temp file for restart script
        """
        rst_file = self.du.create_temp_file(hostname=self.hostname, body=body,
                                            dirname=dirname)
        self.du.chmod(hostname=self.hostname, path=rst_file, mode=0o700)
        self.du.chown(hostname=self.hostname, path=rst_file, runas=ROOT_USER,
                      uid=0, gid=0)
        c = {'$action restart': str(abort_time) + ' !' + rst_file + ' %sid'}
        self.add_config(c)
        return rst_file

    def parse_config(self):
        """
        Parse mom config file into a dictionary of configuration
        options.

        :returns: A dictionary of configuration options on success,
                  and None otherwise
        """
        try:
            mconf = os.path.join(self.pbs_conf['PBS_HOME'], 'mom_priv',
                                 'config')
            ret = self.du.cat(self.hostname, mconf, sudo=True)
            if ret['rc'] != 0:
                self.logger.error('error parsing configuration file')
                return None

            self.config = {}
            lines = ret['out']
            for line in lines:
                if line.startswith('$action'):
                    (ac, k, v) = line.split(' ', 2)
                    k = ac + ' ' + k
                else:
                    (k, v) = line.split(' ', 1)
                if k in self.config:
                    if isinstance(self.config[k], list):
                        self.config[k].append(v)
                    else:
                        self.config[k] = [self.config[k], v]
                else:
                    self.config[k] = v
        except:
            self.logger.error('error in parse_config')
            return None

        return self.config

    def add_config(self, conf={}, hup=True):
        """
        Add config options to mom_priv_config.

        :param conf: The configurations to add to ``mom_priv/config``
        :type conf: Dictionary
        :param hup: If True (default) ``HUP`` the MoM
        :type hup: bool
        :returns: True on success and False otherwise
        """

        doconfig = False

        if not self.config:
            self.parse_config()

        mc = self.config

        if mc is None:
            mc = {}

        for k, v in conf.items():
            if k in mc and (mc[k] == v or (isinstance(v, list) and
                                           mc[k] in v)):
                self.logger.debug(self.logprefix + 'config ' + k +
                                  ' already set to ' + str(v))
                continue
            else:
                doconfig = True
                break

        if not doconfig:
            return True

        self.logger.info(self.logprefix + "config " + str(conf))

        return self.apply_config(conf, hup)

    def unset_mom_config(self, name, hup=True):
        """
        Delete a mom_config entry

        :param name: The entry to remove from ``mom_priv/config``
        :type name: String
        :param hup: if True (default) ``HUP`` the MoM
        :type hup: bool
        :returns: True on success and False otherwise
        """
        mc = self.parse_config()
        if mc is None or name not in mc:
            return True
        self.logger.info(self.logprefix + "unsetting config " + name)
        del mc[name]

        return self.apply_config(mc, hup)

    def apply_config(self, conf={}, hup=True, restart=False):
        """
        Apply configuration options to MoM.

        :param conf: A dictionary of configuration options to apply
                     to MoM
        :type conf: Dictionary
        :param hup: If True (default) , HUP the MoM to apply the
                    configuration
        :type hup: bool
        :returns: True on success and False otherwise.
        """
        self.config = {**self.config, **conf}
        try:
            fn = self.du.create_temp_file()
            with open(fn, 'w+') as f:
                for k, v in self.config.items():
                    if isinstance(v, list):
                        for eachprop in v:
                            f.write(str(k) + ' ' + str(eachprop) + '\n')
                    else:
                        f.write(str(k) + ' ' + str(v) + '\n')
            dest = os.path.join(
                self.pbs_conf['PBS_HOME'], 'mom_priv', 'config')
            self.du.run_copy(self.hostname, src=fn, dest=dest,
                             preserve_permission=False, sudo=True)
            os.remove(fn)
        except:
            raise PbsMomConfigError(rc=1, rv=False,
                                    msg='error processing add_config')
        if restart:
            return self.restart()
        elif hup:
            return self.signal('-HUP')

        return True

    def get_vnode_def(self, vnodefile=None):
        """
        :returns: A vnode def file as a single string
        """
        if vnodefile is None:
            return None
        with open(vnodefile) as f:
            lines = f.readlines()
        return "".join(lines)

    def insert_vnode_def(self, vdef, fname=None, additive=False, restart=True):
        """
        Insert and enable a vnode definition. Root privilege
        is required

        :param vdef: The vnode definition string as created by
                     create_vnode_def
        :type vdef: str
        :param fname: The filename to write the vnode def string to
        :type fname: str or None
        :param additive: If True, keep all other vnode def files
                         under config.d Default is False
        :type additive: bool
        :param delete: If True, delete all nodes known to the server.
                       Default is True
        :type delete: bool
        :param restart: If True, restart the MoM. Default is True
        :type restart: bool
        """
        try:
            fn = self.du.create_temp_file(self.hostname, body=vdef)
        except:
            raise PbsMomConfigError(rc=1, rv=False,
                                    msg="Failed to insert vnode definition")
        if fname is None:
            fname = 'pbs_vnode_' + str(int(time.time())) + '.def'
        if not additive:
            self.delete_vnode_defs()
        cmd = [os.path.join(self.pbs_conf['PBS_EXEC'], 'sbin', 'pbs_mom')]
        cmd += ['-s', 'insert', fname, fn]
        ret = self.du.run_cmd(self.hostname, cmd, sudo=True, logerr=False,
                              level=logging.INFOCLI)
        self.du.rm(hostname=self.hostname, path=fn, force=True)
        if ret['rc'] != 0:
            raise PbsMomConfigError(rc=1, rv=False, msg="\n".join(ret['err']))
        msg = self.logprefix + 'inserted vnode definition file '
        msg += fname + ' on host: ' + self.hostname
        self.logger.info(msg)
        if restart:
            self.restart()

    def has_vnode_defs(self):
        """
        Check for vnode definition(s)
        """
        cmd = [os.path.join(self.pbs_conf['PBS_EXEC'], 'sbin', 'pbs_mom')]
        cmd += ['-s', 'list']
        ret = self.du.run_cmd(self.hostname, cmd, sudo=True, logerr=False,
                              level=logging.INFOCLI)
        if ret['rc'] == 0:
            files = [x for x in ret['out'] if not x.startswith('PBS')]
            if len(files) > 0:
                return True
            else:
                return False
        else:
            return False

    def delete_vnode_defs(self, vdefname=None):
        """
        delete vnode definition(s) on this MoM

        :param vdefname: name of a vnode definition file to delete,
                         if None all vnode definitions are deleted
        :type vdefname: str
        :returns: True if delete succeed otherwise False
        """
        cmd = [os.path.join(self.pbs_conf['PBS_EXEC'], 'sbin', 'pbs_mom')]
        cmd += ['-s', 'list']
        ret = self.du.run_cmd(self.hostname, cmd, sudo=True, logerr=False,
                              level=logging.INFOCLI)
        if ret['rc'] != 0:
            return False
        rv = True
        if len(ret['out']) > 0:
            for vnodedef in ret['out']:
                vnodedef = vnodedef.strip()
                if (vnodedef == vdefname) or vdefname is None:
                    if vnodedef.startswith('PBS'):
                        continue
                    cmd = [os.path.join(self.pbs_conf['PBS_EXEC'], 'sbin',
                                        'pbs_mom')]
                    cmd += ['-s', 'remove', vnodedef]
                    ret = self.du.run_cmd(self.hostname, cmd, sudo=True,
                                          logerr=False, level=logging.INFOCLI)
                    if ret['rc'] != 0:
                        return False
                    else:
                        rv = True
        return rv

    def has_pelog(self, filename=None):
        """
        Check for prologue and epilogue
        """
        _has_pro = False
        _has_epi = False
        phome = self.pbs_conf['PBS_HOME']
        prolog = os.path.join(phome, 'mom_priv', 'prologue')
        epilog = os.path.join(phome, 'mom_priv', 'epilogue')
        if self.du.isfile(self.hostname, path=prolog, sudo=True):
            _has_pro = True
        if filename == 'prologue':
            return _has_pro
        if self.du.isfile(self.hostname, path=epilog, sudo=True):
            _has_epi = True
        if filename == 'epilogue':
            return _has_pro
        if _has_epi or _has_pro:
            return True
        return False

    def has_prologue(self):
        """
        Check for prologue
        """
        return self.has_pelog('prolouge')

    def has_epilogue(self):
        """
        Check for epilogue
        """
        return self.has_pelog('epilogue')

    def delete_pelog(self):
        """
        Delete any prologue and epilogue files that may have been
        defined on this MoM
        """
        phome = self.pbs_conf['PBS_HOME']
        prolog = os.path.join(phome, 'mom_priv', 'prologue')
        epilog = os.path.join(phome, 'mom_priv', 'epilogue')
        ret = self.du.rm(self.hostname, epilog, force=True,
                         sudo=True, logerr=False)
        if ret:
            ret = self.du.rm(self.hostname, prolog, force=True,
                             sudo=True, logerr=False)
        if not ret:
            self.logger.error('problem deleting prologue/epilogue')
            # we don't bail because the problem may be that files did not
            # exist. Let tester fix the issue
        return ret

    def create_pelog(self, body=None, src=None, filename=None):
        """
        create ``prologue`` and ``epilogue`` files, functionality
        accepts either a body of the script or a source file.

        :returns: True on success and False on error
        """

        if self.has_snap:
            _msg = 'MoM is in loaded from snap so bypassing pelog creation'
            self.logger.info(_msg)
            return False

        if (src is None and body is None) or (filename is None):
            self.logger.error('file and body of script are required')
            return False

        pelog = os.path.join(self.pbs_conf['PBS_HOME'], 'mom_priv', filename)

        self.logger.info(self.logprefix +
                         ' creating ' + filename + ' with body\n' + '---')
        if body is not None:
            self.logger.info(body)
            src = self.du.create_temp_file(prefix='pbs-pelog', body=body)
        elif src is not None:
            with open(src) as _b:
                self.logger.info("\n".join(_b.readlines()))
        self.logger.info('---')

        ret = self.du.run_copy(self.hostname, src=src, dest=pelog,
                               preserve_permission=False, sudo=True)
        if body is not None:
            os.remove(src)
        if ret['rc'] != 0:
            self.logger.error('error creating pelog ')
            return False

        ret = self.du.chown(self.hostname, path=pelog, uid=0, gid=0, sudo=True,
                            logerr=False)
        if not ret:
            self.logger.error('error chowning pelog to root')
            return False
        ret = self.du.chmod(self.hostname, path=pelog, mode=0o755, sudo=True)
        return ret

    def prologue(self, body=None, src=None):
        """
        create prologue
        """
        return self.create_pelog(body, src, 'prologue')

    def epilogue(self, body=None, src=None):
        """
        Create epilogue
        """
        return self.create_pelog(body, src, 'epilogue')

    def action(self, act, script):
        """
        Define action script. Not currently implemented
        """
        pass

    def enable_cgroup_cset(self):
        """
        Configure and enable cgroups hook
        """
        # check if cgroups subsystems including cpusets are mounted
        file = os.path.join(os.sep, 'proc', 'mounts')
        mounts = self.du.cat(self.hostname, file)['out']
        pat = 'cgroup /sys/fs/cgroup'
        enablemem = False
        for line in mounts:
            entries = line.split()
            if entries[2] != 'cgroup':
                continue
            flags = entries[3].split(',')
            if 'memory' in flags:
                enablemem = True
        if str(mounts).count(pat) >= 6 and str(mounts).count('cpuset') >= 2:
            pbs_conf_val = self.du.parse_pbs_config(self.hostname)
            f1 = os.path.join(pbs_conf_val['PBS_EXEC'], 'lib',
                              'python', 'altair', 'pbs_hooks',
                              'pbs_cgroups.CF')
            # set vnode_per_numa_node = true, use_hyperthreads = true
            with open(f1, "r") as cfg:
                cfg_dict = json.load(cfg)
            cfg_dict['vnode_per_numa_node'] = True
            cfg_dict['use_hyperthreads'] = True

            # if the memory subsystem is not mounted, do not enable mem
            # in the cgroups config otherwise PTL tests will fail.
            # This matches what is documented for cgroups and mem.
            cfg_dict['cgroup']['memory']['enabled'] = enablemem
            _, path = tempfile.mkstemp(prefix="cfg", suffix=".json")
            with open(path, "w") as cfg1:
                json.dump(cfg_dict, cfg1, indent=4)
            # read in the cgroup hook configuration
            a = {'content-type': 'application/x-config',
                 'content-encoding': 'default',
                 'input-file': path}
            self.server.manager(MGR_CMD_IMPORT, HOOK, a,
                                'pbs_cgroups')
            os.remove(path)
            # enable cgroups hook
            self.server.manager(MGR_CMD_SET, HOOK,
                                {'enabled': 'True'}, 'pbs_cgroups')
        else:
            self.logger.error('%s: cgroup subsystems not mounted' %
                              self.hostname)
            raise AssertionError('cgroup subsystems not mounted')
