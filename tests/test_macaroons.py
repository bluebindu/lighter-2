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
from unittest import TestCase, skip
from unittest.mock import Mock, mock_open, patch
from pymacaroons import Macaroon

from lighter import settings
from lighter.macaroons import MACAROONS
from lighter.utils import gen_random_data

MOD = import_module('lighter.macaroons')

ADMIN_MAC = ('4167454862476c6e6148526c63674a4f41776f516b7538646e4c51787070'
             '733057446f62556d5430715249424d426f32436a4674645778306153316e'
             '646a5655616e7036633256564d455a714d586c3255305a5053454a514f57'
             '746c536b45345a30644c51334268626b70466355644a52305a7645674571'
             '4141496e64476c745a5331695a575a76636d55674d6a41794d4330774d79'
             '30784d4651784d7a6f314d446f774e79347a4f5445774e6a686141414147'
             '494d6634386537613454314948782d6e42506a6851795850344a53534732'
             '576e4448795a70736f316a477970')

READ_MAC = ('4167454862476c6e6148526c63674a4f41776f514c695f71643177594a68575f'
            '6c7a734d3848414b794249424d426f32436a4674645778306153317855584532'
            '554534356155784e546c704b53566731626e566f526c4a7159546c6f63586734'
            '4e7a4d74646c394f52545a4252584577636d5646456745714141496e64476c74'
            '5a5331695a575a76636d55674d6a41794d4330774d7930784d4651784d7a6f31'
            '4d446f774e79347a4f4463774f444e614141414749446273736b677853707749'
            '675370773541587742514d6e4f63367149717436576f555437494b4357424661')

ROOT_KEY = (b'\xee\xc4\x817\xc6}\x08\xd1\xab\x19\xab\xf2\xf4\xe9\xd3\x1a0'
            b'\x8aGb{\xb1i4H\x13N`\xa4b\xc3\xdc')


class MacaroonsTests(TestCase):
    """ Tests for macaroons module """

    @patch('lighter.macaroons._validate_macaroon', autospec=True)
    @patch('lighter.macaroons.LOGGER')
    def test_check_macaroons(self, mocked_logger, mocked_validate):
        key = 'macaroon'
        # Correct case
        md = Mock()
        md.key = key
        md.value = ADMIN_MAC
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
        settings.LIGHTNING_BAKERY = MOD.get_baker(ROOT_KEY, put_ops=True)
        # Valid macaroon
        value = decode(ADMIN_MAC, 'hex')
        mac = Macaroon.deserialize(value)
        res = MOD._validate_macaroon(mac, settings.ALL_PERMS[method])
        self.assertEqual(res, True)
        # Valid macaroon but operation not allowed
        value = decode(READ_MAC, 'hex')
        mac = Macaroon.deserialize(value)
        res = MOD._validate_macaroon(mac, settings.ALL_PERMS[method])
        self.assertEqual(res, False)
        # Invalid root_key
        root_key = gen_random_data(32)
        settings.LIGHTNING_BAKERY = MOD.get_baker(root_key, put_ops=True)
        res = MOD._validate_macaroon(mac, settings.ALL_PERMS[method])
        self.assertEqual(res, False)

    def test_get_baker(self):
        # Without ops
        res = MOD.get_baker(ROOT_KEY)
        self.assertTrue(isinstance(res, Bakery))
        # Putting ops
        res = MOD.get_baker(ROOT_KEY, put_ops=True)
        self.assertTrue(isinstance(res, Bakery))
        for permitted_ops in MACAROONS.values():
            entity = res.oven.ops_entity(permitted_ops)
            ops = res.oven.ops_store.get_ops(entity)
            self.assertTrue(isinstance(ops, list))

    @patch('lighter.macaroons.LOGGER')
    @patch('lighter.macaroons.DbHandler', autospec=True)
    @patch('lighter.utils.Crypter')
    def test_create_lightning_macaroons(self, mocked_db, mocked_logger):
        password = 'password'
        mopen = mock_open()
        with patch('lighter.macaroons.open', mopen, create=True) as mocked_open:
            crypter = MOD.Crypter(password)
            MOD.create_lightning_macaroons(crypter)
            handle = mopen()
            assert handle.write.called


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
