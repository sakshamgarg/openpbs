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


import sys
import time
import re
import threading
import logging
import socket
import os
import json
from ptl.utils.pbs_dshutils import DshUtils
from ptl.utils.platform.pbs_platform import PlatformSwitch


class ProcUtils(object):

    """
    Utilities to query process information
    """

    logger = logging.getLogger(__name__)
    du = DshUtils()
    ps = PlatformSwitch()
    platform = sys.platform

    def __init__(self):
        self.processes = {}
        self.__h2ps = {}
        self.process_param = {}

    def _init_processes(self):
        self.processes = {}

    def _init_process_parameters(self):
        param_list = ["pid_output", "rss", "vsz", "pcpu", "pmem", "size", "cputime",
                      "command", "name", "regexp", "stat", "ppid", "pid",
                      "no-heading"]
        self.process_param = dict.fromkeys(param_list, None)

    def _get_proc_info(self, hostname=None, name=None, pid=None, regexp=False):
        """
        Helper function to ``get_proc_info`` for Unix only system
        """
        if hostname is None:
            hostname = socket.gethostname()

        if hostname in self.__h2ps:
            return self.__h2ps[hostname]

        if pid is None:
            pid = True
        self.process_param.update({'pid_output': True, 'rss': True, 'vsz': True,
                                   'pcpu': True, 'pmem': True, 'size': True,
                                   'cputime': True, 'command': True,
                                   'pid': pid, 'name': name, 'regexp': regexp})

        process_cmd = self.ps.get_process_command(hostname, self.process_param)

        if process_cmd is not None:
            cr = self.du.run_cmd(hostname, process_cmd, level=logging.DEBUG2)
        else:
            return

        if cr['rc'] == 0 and cr['out']:
            for proc in cr['out']:
                _pi = None
                try:
                    _s = proc.split()
                    ps_attr = self.ps.get_ps_cmd_attrs(hostname, _s)
                except BaseException:
                    continue

                if ((pid is not None and ps_attr['p'] == str(pid)) or
                    (name is not None and (
                        (regexp and re.search(name, ps_attr['command'])
                            is not None) or
                        (not regexp and name in ps_attr['command'])))):
                    _pi = ProcInfo(name=ps_attr['command'])
                    _pi.pid = ps_attr['p']
                    _pi.rss = ps_attr['rss']
                    _pi.vsz = ps_attr['vsz']
                    _pi.pcpu = ps_attr['pcpu']
                    _pi.pmem = ps_attr['pmem']
                    _pi.size = ps_attr['size']
                    _pi.cputime = ps_attr['cputime']
                    _pi.command = ps_attr['command']

                if _pi is not None:
                    if ps_attr['command'] in self.processes:
                        self.processes[ps_attr['command']].append(_pi)
                    else:
                        self.processes[ps_attr['command']] = [_pi]
        return self.processes

    def get_proc_info(self, hostname=None, name=None, pid=None, regexp=False):
        """
        Return process information from a process name, or pid,
        on a given host

        :param hostname: The hostname on which to query the process
                         info. On Windows,only localhost is queried.
        :type hostname: str or none
        :param name: The name of the process to query.
        :type name: str or None
        :param pid: The pid of the process to query
        :type pid: int or None
        :param regexp: Match processes by regular expression. Defaults
                       to True. Does not apply to matching by PID.
        :type regexp: bool
        :returns: A list of ProcInfo objects, one for each matching
                  process.

        .. note:: If both, name and pid, are specified, name is used.
        """
        self._init_processes()
        self._init_process_parameters()
        return self._get_proc_info(hostname, name, pid, regexp)

    def get_proc_state(self, hostname=None, pid=None):
        """
        :returns: PID's process state on host hostname

        On error the empty string is returned.
        """
        if not self.du.is_localhost(hostname):
            platform = self.du.get_platform(hostname)
        else:
            platform = sys.platform

        self._init_process_parameters()
        self.process_param.update({'pid': pid, 'stat': True,
                                   'no-heading': True})
        try:
            if platform.startswith('linux') or platform.startswith('shasta'):
                cmd = self.ps.get_process_command(hostname=None, process_param=self.process_param, platform=platform)
                rv = self.du.run_cmd(hostname, cmd, level=logging.DEBUG2)
                return rv['out'][0][0]
        except BaseException:
            self.logger.error('Error getting process state for pid ' + pid)
            return ''

    def get_proc_children(self, hostname=None, ppid=None):
        """
        :returns: A list of children PIDs associated to ``PPID`` on
                  host hostname.

        On error, an empty list is returned.
        """
        try:
            if not isinstance(ppid, str):
                ppid = str(ppid)

            if int(ppid) <= 0:
                raise

            if not self.du.is_localhost(hostname):
                platform = self.du.get_platform(hostname)
            else:
                platform = sys.platform

            childlist = []

            if platform.startswith('linux') or platform.startswith('shasta'):
                self._init_process_parameters()
                self.process_param.update({'pid_output': True, 'ppid': ppid,
                                           'no-heading': True})
                cmd = self.ps.get_process_command(hostname=None, process_param=self.process_param, platform=platform)
                rv = self.du.run_cmd(hostname, cmd)
                children = rv['out'][:-1]
            else:
                children = []

            for child in children:
                child = child.strip()
                if child != '':
                    childlist.append(child)
                    childlist.extend(self.get_proc_children(hostname, child))

            return childlist
        except BaseException:
            self.logger.error('Error getting children processes of parent ' +
                              ppid)
            return []


class ProcInfo(object):

    """
    Process information reports ``PID``, ``RSS``, ``VSZ``, Command
    and Time at which process information is collected
    """

    def __init__(self, name=None, pid=None):
        self.name = name
        self.pid = pid
        self.rss = None
        self.vsz = None
        self.pcpu = None
        self.pmem = None
        self.size = None
        self.cputime = None
        self.time = time.time()
        self.command = None

    def __str__(self):
        return "%s pid: %s rss: %s vsz: %s pcpu: %s pmem: %s \
               size: %s cputime: %s command: %s" % \
               (self.name, str(self.pid), str(self.rss), str(self.vsz),
                str(self.pcpu), str(self.pmem), str(self.size),
                str(self.cputime), self.command)


class ProcMonitor(threading.Thread):

    """
    A background process monitoring tool
    """
    du = DshUtils()

    def __init__(self, name=None, regexp=False, frequency=60):
        threading.Thread.__init__(self)
        self.name = name
        self.frequency = frequency
        self.regexp = regexp
        self._pu = ProcUtils()
        self.stop_thread = threading.Event()
        self.db_proc_info = []

    def set_frequency(self, value=60):
        """
        Set the frequency

        :param value: Frequency value
        :type value: int
        """
        self.logger.debug('procmonitor: set frequency to ' + str(value))
        self.frequency = value

    def get_system_stats(self, nw_protocols=None):
        """
        Run system monitoring
        """
        timenow = int(time.time())
        sysstat = {}
        # if no protocols set, use default
        if not nw_protocols:
            nw_protocols = ['TCP']
        cmd = 'sar -rSub -n %s 1 1' % ','.join(nw_protocols)
        rv = self.du.run_cmd(cmd=cmd, as_script=True)
        if rv['err']:
            return None
        op = rv['out'][2:]
        op = [i.split()[2:] for i in op if
              (i and not i.startswith('Average'))]
        sysstat['name'] = "System"
        sysstat['time'] = time.ctime(timenow)
        for i in range(0, len(op), 2):
            sysstat.update(dict(zip(op[i], op[i + 1])))
        return sysstat

    def run(self):
        """
        Run the process monitoring
        """
        while not self.stop_thread.is_set():
            self._pu.get_proc_info(name=self.name, regexp=self.regexp)
            for _p in self._pu.processes.values():
                for _per_proc in _p:
                    if bool(re.search("^((?!benchpress).)*$", _per_proc.name)):
                        _to_db = {}
                        _to_db['time'] = time.ctime(int(_per_proc.time))
                        _to_db['rss'] = _per_proc.rss
                        _to_db['vsz'] = _per_proc.vsz
                        _to_db['pcpu'] = _per_proc.pcpu
                        _to_db['pmem'] = _per_proc.pmem
                        _to_db['size'] = _per_proc.size
                        _to_db['cputime'] = _per_proc.cputime
                        _to_db['name'] = _per_proc.name
                        self.db_proc_info.append(_to_db)
            _sys_info = self.get_system_stats(nw_protocols=['TCP'])
            if _sys_info is not None:
                self.db_proc_info.append(_sys_info)
            with open('proc_monitor.json', 'a+', encoding='utf-8') as proc:
                json.dump(
                    self.db_proc_info,
                    proc,
                    ensure_ascii=False,
                    indent=4)
            time.sleep(self.frequency)

    def stop(self):
        """
        Stop the process monitoring
        """
        self.stop_thread.set()
        self.join()


if __name__ == '__main__':
    pm = ProcMonitor(name='.*pbs_server.*|.*pbs_sched.*', regexp=True,
                     frequency=1)
    pm.start()
    time.sleep(4)
    pm.stop()
