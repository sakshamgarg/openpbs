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


class Singleton(type):
    
    _clses = {}

    def __call__(cls, *args, **kwargs):
        key = (cls, args, str(kwargs))
        if key not in cls._clses:
            cls._clses[key] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._clses[key]


class PbsGroup(object):

    """
    The PbsGroup type augments a PBS groupname to associate it
    to users to which the group belongs

    :param name: The group name referenced
    :type name: str
    :param gid: gid of group
    :type gid: int or None
    :param users: The list of PbsUser objects the group belongs to
    :type users: List or None
    """

    def __init__(self, name, gid, sid=None):
        self.__dict__['gr_name'] = str(name)
        self.__dict__['gr_passwd'] = 'x'
        self.__dict__['gr_gid'] = int(gid)
        self.__dict__['gr_mem'] = []
        self.__dict__['gr_sid'] = str(sid)
        self.__dict__['_fake'] = False
        self.__dict__['_record'] = (self.gr_name, self.gr_passwd,
                                    self.gr_gid,
                                    map(lambda u: str(u), self.gr_mem),
                                    self.gr_sid)

    def __len__(self):
        return len(self.__dict__['_record'])

    def __getitem__(self, key):
        return self._record[key]

    def __setattr__(self, name, value):
        raise AttributeError('attribute read-only: %s' % name)

    def __repr__(self):
        return 'PbsGroup' + str(self._record)

    def __str__(self):
        return self.__dict__['gr_name']

    def __int__(self):
        return self.__dict__['gr_gid']

    def __cmp__(self, other):
        this = str(self._record)
        if this == other:
            return 0
        elif this < other:
            return -1
        else:
            return 1

    def set_fake(self):
        self.__dict__['_fake'] = True

    def is_fake(self):
        return self.__dict__['_fake']

class PbsUser(object):
    
    __metaclass__ = Singleton

    def __init__(self, name, uid, gid, gecos, homedir, shell, sid=None):
        self.__dict__['pw_name'] = str(name)
        self.__dict__['pw_passwd'] = 'x'
        self.__dict__['pw_uid'] = int(uid)
        self.__dict__['pw_gid'] = int(gid)
        self.__dict__['pw_gecos'] = str(gecos)
        self.__dict__['pw_dir'] = str(homedir)
        self.__dict__['pw_shell'] = str(shell)
        self.__dict__['pw_sid'] = str(sid)
        self.__dict__['pw_groups'] = []
        self.__dict__['_fake'] = False
        self.__dict__['_record'] = (self.pw_name, self.pw_passwd,
                                    self.pw_uid, self.pw_gid,
                                    self.pw_gecos, self.pw_dir,
                                    self.pw_shell, self.pw_sid,
                                    map(lambda g: str(g), self.pw_groups))

    def __len__(self):
        return len(self.__dict__['_record'])

    def __getitem__(self, key):
        return self._record[key]

    def __setattr__(self, name, value):
        raise AttributeError('attribute read-only: %s' % name)

    def __repr__(self):
        return 'PbsUser' + str(self._record)

    def __str__(self):
        return self.__dict__['pw_name']

    def __int__(self):
        return self.__dict__['pw_uid']

    def __cmp__(self, other):
        this = str(self._record)
        if this == other:
            return 0
        elif this < other:
            return -1
        else:
            return 1

    def set_fake(self):
        self.__dict__['_fake'] = True

    def is_fake(self):
        return self.__dict__['_fake']
        
    @staticmethod
    def get_user(user):
        """
        param: user - username
        type: user - str or int or class object
        returns PbsUser class object or None
        """
        if isinstance(user, int):
            for u in PBS_ALL_USERS:
                if u.uid == user:
                    return u
        elif isinstance(user, str):
            for u in PBS_ALL_USERS:
                if u.name == user:
                    return u
        elif isinstance(user, PbsUser):
            if user in PBS_ALL_USERS:
                return user
        return None


# Test users/groups are expected to exist on the test systems
# User running the tests and the test users should have passwordless sudo
# access configured to avoid interrupted (queries for password) test runs

# Groups

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

def __get_check_user(username, uid):
    try:
        return getpwnam(username)
    except:
        user = PbsUser(name=username, uid=uid, gid=-1, gecos=username,
                       homedir=None, shell=None, sid=None)
        user.set_fake()
        return user

def __get_check_group(groupname, gid):
    try:
        return getgrnam(groupname)
    except:
        group = PbsGroup(name=groupname, gid=gid, sid=None)
        group.set_fake()
        return group


def __assign_groups_to_user(user, groups):
    for v in groups:
        if v in user.pw_groups:
            user.pw_groups.remove(v)
        if user in v.gr_mem:
            v.gr_mem.remove(user)
    for idx, v in enumerate(groups):
        user.pw_groups.insert(idx, v)
        v.gr_mem.insert(idx, user)

# Users
TEST_USER = __get_check_user('pbsuser', uid=4359)
TEST_USER1 = __get_check_user('pbsuser1', uid=4361)
TEST_USER2 = __get_check_user('pbsuser2', uid=4362)
TEST_USER3 = __get_check_user('pbsuser3', uid=4363)
TEST_USER4 = __get_check_user('pbsuser4', uid=4364)
TEST_USER5 = __get_check_user('pbsuser5', uid=4365)
TEST_USER6 = __get_check_user('pbsuser6', uid=4366)
TEST_USER7 = __get_check_user('pbsuser7', uid=4368)
OTHER_USER = __get_check_user('pbsother', uid=4358)
PBSTEST_USER = __get_check_user('pbstest', uid=4355)
TST_USR = __get_check_user('tstusr00', uid=11000)
TST_USR1 = __get_check_user('tstusr01', uid=11001)
BUILD_USER = __get_check_user('pbsbuild', uid=9000)
DATA_USER = __get_check_user('pbsdata', uid=4372)
MGR_USER = __get_check_user('pbsmgr', uid=4367)
OPER_USER = __get_check_user('pbsoper', uid=4356)
ADMIN_USER = __get_check_user('pbsadmin', uid=4357)
PBSROOT_USER = __get_check_user('pbsroot', uid=4371)
ROOT_USER = __get_check_user('root', uid=0)

# Groups
TSTGRP0 = __get_check_group('tstgrp00', gid=1900)
TSTGRP1 = __get_check_group('tstgrp01', gid=1901)
TSTGRP2 = __get_check_group('tstgrp02', gid=1902)
TSTGRP3 = __get_check_group('tstgrp03', gid=1903)
TSTGRP4 = __get_check_group('tstgrp04', gid=1904)
TSTGRP5 = __get_check_group('tstgrp05', gid=1905)
TSTGRP6 = __get_check_group('tstgrp06', gid=1906)
TSTGRP7 = __get_check_group('tstgrp07', gid=1907)
GRP_PBS = __get_check_group('pbs', gid=901)
GRP_AGT = __get_check_group('agt', gid=1146)
ROOT_GRP = __get_check_group('root', gid=0)

# Assign groups to users
# first group from group list is primary group of user
__assign_groups_to_user(TEST_USER, [TSTGRP0])
__assign_groups_to_user(TEST_USER1, [TSTGRP0, TSTGRP1, TSTGRP2])
__assign_groups_to_user(TEST_USER2, [TSTGRP0, TSTGRP1, TSTGRP3])
__assign_groups_to_user(TEST_USER3, [TSTGRP0, TSTGRP1, TSTGRP4])
__assign_groups_to_user(TEST_USER4, [TSTGRP1, TSTGRP4, TSTGRP5])
__assign_groups_to_user(TEST_USER5, [TSTGRP2, TSTGRP4, TSTGRP6])
__assign_groups_to_user(TEST_USER6, [TSTGRP3, TSTGRP4, TSTGRP7])
__assign_groups_to_user(TEST_USER7, [TSTGRP1])
__assign_groups_to_user(OTHER_USER, [TSTGRP0, TSTGRP2, GRP_PBS, GRP_AGT])
__assign_groups_to_user(PBSTEST_USER, [TSTGRP0, TSTGRP2, GRP_PBS, GRP_AGT])
__assign_groups_to_user(TST_USR, [TSTGRP0])
__assign_groups_to_user(TST_USR1, [TSTGRP0])
__assign_groups_to_user(BUILD_USER, [TSTGRP0])
__assign_groups_to_user(DATA_USER, [TSTGRP0])
__assign_groups_to_user(MGR_USER, [TSTGRP0])
__assign_groups_to_user(OPER_USER, [TSTGRP0, TSTGRP2, GRP_PBS, GRP_AGT])
__assign_groups_to_user(ADMIN_USER, [TSTGRP0, TSTGRP2, GRP_PBS, GRP_AGT])
__assign_groups_to_user(PBSROOT_USER, [TSTGRP0, TSTGRP2])
__assign_groups_to_user(ROOT_USER, [ROOT_GRP])

PBS_USERS = (TEST_USER, TEST_USER1, TEST_USER2, TEST_USER3, TEST_USER4,
             TEST_USER5, TEST_USER6, TEST_USER7, OTHER_USER, PBSTEST_USER,
             TST_USR, TST_USR1)

PBS_GROUPS = (TSTGRP0, TSTGRP1, TSTGRP2, TSTGRP3, TSTGRP4, TSTGRP5, TSTGRP6,
              TSTGRP7, GRP_PBS, GRP_AGT)

PBS_OPER_USERS = (OPER_USER,)

PBS_MGR_USERS = (MGR_USER, ADMIN_USER)

PBS_DATA_USERS = (DATA_USER,)

PBS_ROOT_USERS = (PBSROOT_USER, ROOT_USER)

PBS_BUILD_USERS = (BUILD_USER,)

REQUIRED_USERS = (TEST_USER, TEST_USER1, TEST_USER2, TEST_USER3)

PBS_ALL_USERS = (PBS_USERS + PBS_OPER_USERS + PBS_MGR_USERS +
                 PBS_DATA_USERS + PBS_ROOT_USERS + PBS_BUILD_USERS)

"""
TSTGRP0 = PbsGroup('tstgrp00', gid=1900)
TSTGRP1 = PbsGroup('tstgrp01', gid=1901)
TSTGRP2 = PbsGroup('tstgrp02', gid=1902)
TSTGRP3 = PbsGroup('tstgrp03', gid=1903)
TSTGRP4 = PbsGroup('tstgrp04', gid=1904)
TSTGRP5 = PbsGroup('tstgrp05', gid=1905)
TSTGRP6 = PbsGroup('tstgrp06', gid=1906)
TSTGRP7 = PbsGroup('tstgrp07', gid=1907)
GRP_PBS = PbsGroup('pbs', gid=901)
GRP_AGT = PbsGroup('agt', gid=1146)
ROOT_GRP = PbsGroup(grp.getgrgid(0).gr_name, gid=0)

# Users
# first group from group list is primary group of user
TEST_USER = PbsUser('pbsuser', uid=4359, groups=[TSTGRP0])
TEST_USER1 = PbsUser('pbsuser1', uid=4361, groups=[TSTGRP0, TSTGRP1, TSTGRP2])
TEST_USER2 = PbsUser('pbsuser2', uid=4362, groups=[TSTGRP0, TSTGRP1, TSTGRP3])
TEST_USER3 = PbsUser('pbsuser3', uid=4363, groups=[TSTGRP0, TSTGRP1, TSTGRP4])
TEST_USER4 = PbsUser('pbsuser4', uid=4364, groups=[TSTGRP1, TSTGRP4, TSTGRP5])
TEST_USER5 = PbsUser('pbsuser5', uid=4365, groups=[TSTGRP2, TSTGRP4, TSTGRP6])
TEST_USER6 = PbsUser('pbsuser6', uid=4366, groups=[TSTGRP3, TSTGRP4, TSTGRP7])
TEST_USER7 = PbsUser('pbsuser7', uid=4368, groups=[TSTGRP1])

OTHER_USER = PbsUser('pbsother', uid=4358, groups=[TSTGRP0, TSTGRP2, GRP_PBS,
                                                   GRP_AGT])
PBSTEST_USER = PbsUser('pbstest', uid=4355, groups=[TSTGRP0, TSTGRP2, GRP_PBS,
                                                    GRP_AGT])
TST_USR = PbsUser('tstusr00', uid=11000, groups=[TSTGRP0])
TST_USR1 = PbsUser('tstusr01', uid=11001, groups=[TSTGRP0])

BUILD_USER = PbsUser('pbsbuild', uid=9000, groups=[TSTGRP0])
DATA_USER = PbsUser('pbsdata', uid=4372, groups=[TSTGRP0])
MGR_USER = PbsUser('pbsmgr', uid=4367, groups=[TSTGRP0])
OPER_USER = PbsUser('pbsoper', uid=4356, groups=[TSTGRP0, TSTGRP2, GRP_PBS,
                                                 GRP_AGT])
ADMIN_USER = PbsUser('pbsadmin', uid=4357, groups=[TSTGRP0, TSTGRP2, GRP_PBS,
                                                   GRP_AGT])
PBSROOT_USER = PbsUser('pbsroot', uid=4371, groups=[TSTGRP0, TSTGRP2])
ROOT_USER = PbsUser('root', uid=0, groups=[ROOT_GRP])

PBS_USERS = (TEST_USER, TEST_USER1, TEST_USER2, TEST_USER3, TEST_USER4,
             TEST_USER5, TEST_USER6, TEST_USER7, OTHER_USER, PBSTEST_USER,
             TST_USR, TST_USR1)

PBS_GROUPS = (TSTGRP0, TSTGRP1, TSTGRP2, TSTGRP3, TSTGRP4, TSTGRP5, TSTGRP6,
              TSTGRP7, GRP_PBS, GRP_AGT)

PBS_OPER_USERS = (OPER_USER,)

PBS_MGR_USERS = (MGR_USER, ADMIN_USER)

PBS_DATA_USERS = (DATA_USER,)

PBS_ROOT_USERS = (PBSROOT_USER, ROOT_USER)

PBS_BUILD_USERS = (BUILD_USER,)

REQUIRED_USERS = (TEST_USER, TEST_USER1, TEST_USER2, TEST_USER3)

PBS_ALL_USERS = (PBS_USERS + PBS_OPER_USERS + PBS_MGR_USERS +
                 PBS_DATA_USERS + PBS_ROOT_USERS + PBS_BUILD_USERS)
"""