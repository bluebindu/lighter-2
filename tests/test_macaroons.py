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

""" Tests for macaroons module """

from codecs import decode, encode
from importlib import import_module
from macaroonbakery.bakery import Bakery
from os import urandom
from pymacaroons import Macaroon
from unittest import TestCase, skip
from unittest.mock import Mock, mock_open, patch

from tests import fixtures_macaroons as fix

from . import proj_root

MACAROONS = getattr(import_module(proj_root + '.macaroons'), 'MACAROONS')
settings = import_module(proj_root + '.settings')
MOD = import_module(proj_root + '.macaroons')


class MacaroonsTests(TestCase):
    """ Tests for macaroons module """

    @patch(MOD.__name__ + '._validate_macaroon', autospec=True)
    @patch(MOD.__name__ + '.LOGGER')
    def test_check_macaroons(self, mocked_logger, mocked_validate):
        key = 'macaroon'
        root_key = urandom(32)
        fix.create_lightning_macaroons(root_key)
        # Correct case
        md = Mock()
        md.key = key
        md.value = fix.ADMIN_MAC
        metadata = (md,)
        method = '/lighter.Lightning/GetInfo'
        mocked_validate.return_value = True
        res = MOD.check_macaroons(metadata, method)
        assert not mocked_logger.error.called
        self.assertEqual(res, True)
        # No macaroons case
        reset_mocks(vars())
        metadata = []
        res = MOD.check_macaroons(metadata, method)
        assert mocked_logger.error.called
        self.assertEqual(res, False)
        # Wrong value case
        reset_mocks(vars())
        md.value = 'lighter'
        metadata = (md,)
        res = MOD.check_macaroons(metadata, method)
        assert mocked_logger.error.called
        self.assertEqual(res, False)

    def test_validate_macaroon(self):
        method = '/lighter.Lightning/PayInvoice'
        root_key = urandom(32)
        fix.create_lightning_macaroons(root_key)
        settings.RUNTIME_BAKER = MOD.get_baker(root_key, put_ops=True)
        # Valid macaroon
        print('sdMAC AD', fix.ADMIN_MAC)

        value = decode(fix.ADMIN_MAC, 'hex')
        mac = Macaroon.deserialize(value)
        res = MOD._validate_macaroon(mac, settings.ALL_PERMS[method])
        self.assertEqual(res, True)
        # Valid macaroon but operation not allowed
        value = decode(fix.READ_MAC, 'hex')
        mac = Macaroon.deserialize(value)
        res = MOD._validate_macaroon(mac, settings.ALL_PERMS[method])
        self.assertEqual(res, False)
        # Invalid root_key
        root_key = urandom(32)
        settings.RUNTIME_BAKER = MOD.get_baker(root_key, put_ops=True)
        res = MOD._validate_macaroon(mac, settings.ALL_PERMS[method])
        self.assertEqual(res, False)

    def test_get_baker(self):
        # Without ops
        root_key = urandom(32)
        res = MOD.get_baker(root_key)
        self.assertTrue(isinstance(res, Bakery))
        # Putting ops
        res = MOD.get_baker(root_key, put_ops=True)
        self.assertTrue(isinstance(res, Bakery))
        for permitted_ops in MACAROONS.values():
            entity = res.oven.ops_entity(permitted_ops)
            ops = res.oven.ops_store.get_ops(entity)
            self.assertTrue(isinstance(ops, list))


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
