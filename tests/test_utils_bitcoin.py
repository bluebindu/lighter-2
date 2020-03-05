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

""" Tests for utils.bitcoin module """

from importlib import import_module
from unittest import TestCase
from unittest.mock import call, patch

from . import fixtures_utils as fix, proj_root

CTX = 'context'
Enf = getattr(import_module(proj_root + '.utils.bitcoin'), 'Enforcer')
LND_PAYREQ = getattr(import_module(proj_root + '.light_lnd'), 'LND_PAYREQ')
pb = import_module(proj_root + '.lighter_pb2')
settings = import_module(proj_root + '.settings')

MOD = import_module(proj_root + '.utils.bitcoin')


class UtilsBitcoinTests(TestCase):
    """ Tests for utils.bitcoin module """

    @patch(MOD.__name__ + '.Enforcer.check_value')
    @patch(MOD.__name__ + '._convert_value', autospec=True)
    def test_convert(self, mocked_conv_val, mocked_check_val):
        # Correct case: bits to msats
        mocked_conv_val.return_value = 77700000
        res = MOD.convert(CTX, Enf.MSATS, 777, enforce=Enf.LN_TX)
        calls = [
            call(CTX, Enf.BITS, Enf.MSATS, 777, Enf.MSATS),
            call(CTX, Enf.BITS, Enf.MSATS, 777, Enf.MSATS)]
        mocked_conv_val.assert_has_calls(calls)
        self.assertEqual(res, 77700000)
        # Correct case: msats to bits
        reset_mocks(vars())
        mocked_conv_val.return_value = 777
        res = MOD.convert(CTX, Enf.MSATS, 777000000)
        mocked_conv_val.assert_called_once_with(CTX, Enf.MSATS, Enf.BITS,
                                                777000000, Enf.MSATS)
        assert not mocked_check_val.called
        self.assertEqual(res, 777)
        # Correct case: bits to btc
        reset_mocks(vars())
        mocked_conv_val.side_effect = [77700000, 0.777]
        res = MOD.convert(CTX, Enf.BTC, 777000, enforce=Enf.OC_TX)
        calls = [
            call(CTX, Enf.BITS, Enf.OC_TX['unit'], 777000, Enf.SATS),
            call(CTX, Enf.BITS, Enf.BTC, 777000, Enf.SATS)]
        mocked_conv_val.assert_has_calls(calls)
        self.assertEqual(res, 0.777000)

    @patch(MOD.__name__ + '.Err')
    def test_convert_value(self, mocked_err):
        mocked_err().value_error.side_effect = Exception()
        # Correct case: Decimal output
        res = MOD._convert_value(CTX, Enf.BITS, Enf.SATS, 777, Enf.MSATS)
        self.assertEqual(res, 77700)
        assert not mocked_err().value_error.called
        # Correct case: int output
        reset_mocks(vars())
        res = MOD._convert_value(
            CTX, Enf.BITS, Enf.SATS, 777, max_precision=Enf.SATS)
        self.assertEqual(type(res), int)
        # Error case: string input
        reset_mocks(vars())
        with self.assertRaises(Exception):
            res = MOD._convert_value(CTX, Enf.BITS, Enf.SATS, 'err',
                                     Enf.MSATS)
        mocked_err().value_error.assert_called_once_with(CTX)
        # Error case: too big number input
        reset_mocks(vars())
        with self.assertRaises(Exception):
            res = MOD._convert_value(CTX, Enf.BITS, Enf.SATS,
                                     777777777777777777777777777, Enf.SATS)
        mocked_err().value_error.assert_called_once_with(CTX)
        # Error case: number gets truncated
        reset_mocks(vars())
        with self.assertRaises(Exception):
            res = MOD._convert_value(CTX, Enf.BITS, Enf.SATS, 0.009, Enf.SATS)
        mocked_err().value_error.assert_called_once_with(CTX)

    @patch(MOD.__name__ + '.Err')
    def test_conversion(self, mocked_err):
        mocked_err().value_error.side_effect = Exception()
        # Correct case: bits to msats
        res = MOD.convert(CTX, Enf.MSATS, 777, enforce=Enf.LN_TX)
        self.assertEqual(res, 77700000)
        # Correct case: msats to bits
        res = MOD.convert(CTX, Enf.MSATS, 77700000)
        self.assertEqual(res, 777)
        # Correct case: bits to btc
        res = MOD.convert(
            CTX, Enf.BTC, 777000, enforce=Enf.OC_TX,
            max_precision=Enf.SATS)
        self.assertEqual(res, 0.777000)
        # Correct case: btc to bits
        res = MOD.convert(CTX, Enf.BTC, 0.777, max_precision=Enf.BITS)
        self.assertEqual(res, 777000)
        # Error case: bits to sats, losing precision
        with self.assertRaises(Exception):
            res = MOD.convert(CTX, Enf.SATS, 0.009, enforce=LND_PAYREQ,
                              max_precision=Enf.SATS)

    def test_get_address_type(self):
        # Bech32 address case
        addr = 'bcrt1q9s8pfy8ktptz2'
        res = MOD.get_address_type(addr)
        self.assertEqual(res, pb.P2WKH)
        addr = 'tb1qw508d6qejxtdg4y'
        res = MOD.get_address_type(addr)
        self.assertEqual(res, pb.P2WKH)
        # Legacy address case
        addr = 'm2gfudf487cn5acf284'
        res = MOD.get_address_type(addr)
        self.assertEqual(res, pb.NP2WKH)

    def test_get_channel_balances(self):
        # Full channel list case
        channels = fix.LISTCHANNELRESPONSE.channels
        res = MOD.get_channel_balances(CTX, channels)
        self.assertEqual(res.balance, 3824.3)
        self.assertEqual(res.out_tot_now, 3157.24)
        self.assertEqual(res.out_max_now, 3110.71)
        self.assertEqual(res.in_tot, 1244.71)
        self.assertEqual(res.in_tot_now, 682.81)
        self.assertEqual(res.in_max_now, 659.34)
        # Empty channel list case
        reset_mocks(vars())
        res = MOD.get_channel_balances(CTX, [])
        self.assertEqual(res, pb.ChannelBalanceResponse())

    @patch(MOD.__name__ + '._has_numbers', autospec=True)
    def test_has_amount_encoded(self, mocked_has_num):
        pay_req = 'lntb5n1pw3mupk'
        mocked_has_num.return_value = True
        res = MOD.has_amount_encoded(pay_req)
        self.assertEqual(res, True)
        pay_req = 'lntb1pw3mumupk'
        mocked_has_num.return_value = False
        res = MOD.has_amount_encoded(pay_req)
        self.assertEqual(res, False)

    def test_has_numbers(self):
        res = MOD._has_numbers('light3r')
        self.assertEqual(res, True)
        res = MOD._has_numbers('lighter')
        self.assertEqual(res, False)

    @patch(MOD.__name__ + '.Err')
    def test_check_value(self, mocked_err):
        mocked_err().value_too_low.side_effect = Exception()
        mocked_err().value_too_high.side_effect = Exception()
        # Correct case, default type
        Enf.check_value(CTX, 7)
        # Correct case, specific type
        Enf.check_value(CTX, 7, enforce=Enf.LN_TX)
        # Error value_too_low case
        reset_mocks(vars())
        with self.assertRaises(Exception):
            Enf.check_value(CTX, 0.001, enforce=Enf.LN_TX)
        mocked_err().value_too_low.assert_called_once_with(CTX)
        assert not mocked_err().value_too_high.called
        # Error value_too_high case
        reset_mocks(vars())
        with self.assertRaises(Exception):
            Enf.check_value(CTX, 2**32 + 1, enforce=Enf.LN_TX)
        assert not mocked_err().value_too_low.called
        mocked_err().value_too_high.assert_called_once_with(CTX)
        # Check disabled case
        reset_mocks(vars())
        settings.ENFORCE = False
        Enf.check_value(CTX, 7)
        assert not mocked_err().value_too_low.called
        assert not mocked_err().value_too_high.called


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
