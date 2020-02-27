# Copyright (C) 2018 inbitcoin s.r.l.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
""" Tests for db module """

from importlib import import_module
from unittest import TestCase

from . import proj_root

MOD = import_module(proj_root + '.db')


class DbTests(TestCase):
    """ Tests for db module """

    def test_AccessToken(self):
        data = b'token'
        par = b'params'
        res = MOD.AccessToken(data=data, scrypt_params=par)
        self.assertEqual(
            str(res),
            ('<AccessToken(data="b\'token\'", scrypt_params="b\'params\'")>'))

    def test_ImplementationSecret(self):
        impl = 'implementation'
        sec_type = 'password'
        sec = b'secret'
        act = 1
        par = b'params'
        res = MOD.ImplementationSecret(
            implementation=impl, secret_type=sec_type, active=act, secret=sec,
            scrypt_params=par)
        self.assertEqual(
            str(res),
            ('<ImplementationSecret(implementation="implementation", '
             'secret_type="password", active="1", secret="b\'secret\'", '
             'scrypt_params="b\'params\'")>'))

    def test_MacRootKey(self):
        data = 'mac_params'
        par = b'params'
        res = MOD.MacRootKey(data=data, scrypt_params=par)
        self.assertEqual(
            str(res),
            ('<MacRootKey(data="mac_params", scrypt_params="b\'params\'")>'))


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
