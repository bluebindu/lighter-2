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
""" Tests for light_eclair module """

from importlib import import_module
from unittest import mock, TestCase
from unittest.mock import call, patch

from lighter import lighter_pb2 as pb
from lighter import light_eclair, settings
from lighter.light_eclair import ERRORS
from lighter.utils import Enforcer as Enf
from tests import fixtures_eclair as fix

MOD = import_module('lighter.light_eclair')
CTX = 'context'


class LightEclairTests(TestCase):
    """ Tests for light_eclair module """

    def test_update_settings(self):
        password = b'password'
        # Correct case
        reset_mocks(vars())
        values = {
            'ECL_HOST': 'eclair',
            'ECL_PORT': '8080',
        }
        with patch.dict('os.environ', values):
            MOD.update_settings(password)
        ecl_cli_path = '/srv/app/lighter/eclair-cli'
        self.assertEqual(
            settings.CMD_BASE,
            [ecl_cli_path, '-a', '{}:{}'.format(
                values['ECL_HOST'], values['ECL_PORT'])])

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    def test_GetInfo(self, mocked_command, mocked_check_err):
        # Testnet case
        mocked_command.return_value = fix.GETINFO_TESTNET
        res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'getinfo', env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, fix.GETINFO_TESTNET, always_abort=False)
        self.assertEqual(res.network, 'testnet')
        # Mainnet case
        reset_mocks(vars())
        mocked_command.return_value = fix.GETINFO_MAINNET
        res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'getinfo', env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, fix.GETINFO_MAINNET, always_abort=False)
        self.assertEqual(res.network, 'mainnet')
        # Unknown network case
        reset_mocks(vars())
        mocked_command.return_value = fix.GETINFO_UNKNOWN
        res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'getinfo', env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, fix.GETINFO_UNKNOWN, always_abort=False)
        self.assertEqual(res.network, 'unknown')
        # Filled case
        reset_mocks(vars())
        mocked_command.return_value = fix.GETINFO
        res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'getinfo', env=settings.ECL_ENV)
        self.assertEqual(res.network, 'testnet')
        self.assertEqual(res.identity_pubkey, 'id')
        self.assertEqual(res.alias, 'pie')
        self.assertEqual(res.blockheight, 7777)
        # Strange error case
        reset_mocks(vars())
        mocked_command.return_value = fix.STRANGERESPONSE
        res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'getinfo', env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, fix.STRANGERESPONSE, always_abort=False)
        self.assertEqual(res, pb.GetInfoResponse())
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.BADRESPONSE
        mocked_check_err.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'getinfo', env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_eclair.convert', autospec=True)
    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    def test_ChannelBalance(self, mocked_command, mocked_check_err,
                            mocked_conv):
        # Filled
        mocked_command.side_effect = [fix.CHANNELS_ONE, fix.CHANNEL_NORMAL]
        mocked_conv.return_value = 0.0
        res = MOD.ChannelBalance('request', CTX)
        mocked_command.assert_called_with(CTX, 'channel',
                                          fix.CHANNELS_ONE[0]['channelId'],
                                          env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, fix.CHANNELS_ONE, always_abort=False)
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS, 0.0)
        self.assertEqual(res.balance, 0.0)
        # Empty
        reset_mocks(vars())
        mocked_command.side_effect = None
        mocked_command.return_value = []
        mocked_conv.return_value = 0.0
        res = MOD.ChannelBalance('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'channels', env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, mocked_command.return_value, always_abort=False)
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS, 0.0)
        self.assertEqual(res.balance, 0.0)

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    def test_ListPeers(self, mocked_command, mocked_check_err):
        mocked_command.return_value = fix.PEERS2
        res = MOD.ListPeers('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'peers', env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, mocked_command.return_value, always_abort=False)
        self.assertEqual(res.peers[0].pubkey, 'pubkey_2')
        # Empty case
        reset_mocks(vars())
        mocked_command.return_value = []
        res = MOD.ListPeers('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'peers', env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, mocked_command.return_value, always_abort=False)
        self.assertEqual(res, pb.ListPeersResponse())

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair._add_channel', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    def test_ListChannels(self, mocked_command, mocked_add, mocked_check_err):
        # Active only
        mocked_command.side_effect = [fix.CHANNELS_ONE, fix.CHANNEL_NORMAL]
        request = pb.ListChannelsRequest(active_only=True)
        res = MOD.ListChannels(request, CTX)
        calls = [
            call(CTX, 'channels', env=settings.ECL_ENV),
            call(CTX, 'channel', fix.CHANNELS_ONE[0]['channelId'],
                 env=settings.ECL_ENV)
        ]
        mocked_command.assert_has_calls(calls)
        mocked_add.assert_called_once_with(
            CTX, pb.ListChannelsResponse(), fix.CHANNEL_NORMAL)
        mocked_check_err.assert_called_once_with(
            CTX, fix.CHANNEL_NORMAL, always_abort=False)
        self.assertEqual(res, pb.ListChannelsResponse())
        # List all channels
        reset_mocks(vars())
        mocked_command.side_effect = [fix.CHANNELS_ONE, fix.CHANNEL_WAITING]
        request = pb.ListChannelsRequest(active_only=False)
        res = MOD.ListChannels(request, CTX)
        calls = [
            call(CTX, 'channels', env=settings.ECL_ENV),
            call(CTX, 'channel', fix.CHANNELS_ONE[0]['channelId'],
                 env=settings.ECL_ENV)
        ]
        mocked_command.assert_has_calls(calls)
        mocked_add.assert_called_once_with(
            CTX, pb.ListChannelsResponse(), fix.CHANNEL_WAITING)
        mocked_check_err.assert_called_once_with(
            CTX, fix.CHANNEL_WAITING, always_abort=False)
        self.assertEqual(res, pb.ListChannelsResponse())
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = 'badresponse'
        mocked_check_err.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.ListChannels('request', CTX)
        mocked_command.assert_called_once_with(
            CTX, 'channels', env=settings.ECL_ENV)
        assert not mocked_add.called

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    @patch('lighter.light_eclair.convert', autospec=True)
    @patch('lighter.light_eclair.Err')
    def test_CreateInvoice(self, mocked_err, mocked_conv, mocked_command,
                           mocked_check_err):
        # Correct case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(
            description="aaa zzz", amount_bits=777, expiry_time=1666)
        mocked_conv.return_value = 77700000
        mocked_command.side_effect = ['lntb1pdkq', fix.DETAILS]
        res = MOD.CreateInvoice(request, CTX)
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        calls = [
            call(CTX, 'receive', '77700000', 'aaa zzz', '1666',
                 env=settings.ECL_ENV),
            call(CTX, 'checkinvoice', 'lntb1pdkq', env=settings.ECL_ENV)
        ]
        mocked_command.assert_has_calls(calls)
        mocked_check_err.assert_called_with(
            CTX, fix.DETAILS, always_abort=False)
        self.assertEqual(mocked_check_err.call_count, 2)
        self.assertEqual(res.payment_request, 'lntb1pdkq')
        self.assertEqual(res.payment_hash, 'a3af1a3caef9370b3d75a49f35425c')
        self.assertEqual(res.expires_at, 1533041362 + 3600)
        # Empty request case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest()
        mocked_command.side_effect = ['lntb1pdkq', fix.DETAILS]
        res = MOD.CreateInvoice(request, CTX)
        assert not mocked_err().unsettable.called
        calls = [
            call(CTX, 'receive', settings.DEFAULT_DESCRIPTION,
                 env=settings.ECL_ENV),
            call(CTX, 'checkinvoice', 'lntb1pdkq', env=settings.ECL_ENV)
        ]
        mocked_command.assert_has_calls(calls)
        mocked_check_err.assert_called_with(
            CTX, fix.DETAILS, always_abort=False)
        self.assertEqual(mocked_check_err.call_count, 2)
        self.assertEqual(res.payment_request, 'lntb1pdkq')
        self.assertEqual(res.payment_hash, 'a3af1a3caef9370b3d75a49f35425c')
        self.assertEqual(res.expires_at, 1533041362 + 3600)
        # Unimplemented parameter case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(min_final_cltv_expiry=7)
        mocked_err().unimplemented_parameter.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CreateInvoice(request, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'min_final_cltv_expiry')
        assert not mocked_command.called
        assert not mocked_check_err.called
        # Unsettable parameter expiry_time case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(expiry_time=7)
        mocked_err().unsettable.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CreateInvoice(request, CTX)
        mocked_err().unsettable.assert_called_once_with(
            CTX, 'expiry_time (amount necessary)')
        assert not mocked_command.called
        assert not mocked_check_err.called
        # Error case
        request = pb.CreateInvoiceRequest(description='aaa zzz')
        mocked_command.side_effect = ['', 'badresponse']
        MOD.CreateInvoice(request, CTX)
        mocked_command.assert_called_with(
            CTX, 'checkinvoice', '', env=settings.ECL_ENV)
        mocked_check_err.assert_called_with(
            CTX, 'badresponse', always_abort=False)

    @patch('lighter.light_eclair.command', autospec=True)
    @patch('lighter.light_eclair.Err')
    @patch('lighter.light_eclair.check_req_params', autospec=True)
    def test_CheckInvoice(self, mocked_check_par, mocked_err, mocked_command):
        # Correct case
        request = pb.CheckInvoiceRequest(payment_hash='random')
        mocked_command.return_value = True
        res = MOD.CheckInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'checkpayment',
                                               'random', env=settings.ECL_ENV)
        assert not mocked_err().invalid.called
        self.assertEqual(res.settled, True)
        # Missing parameter case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CheckInvoice(request, CTX)
        # Error case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.CheckInvoiceRequest(payment_hash='incorrect')
        mocked_command.return_value = 'Error'
        mocked_err().invalid.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, CTX)
        mocked_command.assert_called_once_with(
            CTX, 'checkpayment', 'incorrect', env=settings.ECL_ENV)
        mocked_err().invalid.assert_called_once_with(CTX, 'payment_hash')
        self.assertEqual(res, 'not set')

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    @patch('lighter.light_eclair.convert', autospec=True)
    @patch('lighter.light_eclair.DecodeInvoice', autospec=True)
    @patch('lighter.light_eclair.Err')
    @patch('lighter.light_eclair.check_req_params', autospec=True)
    def test_PayInvoice(self, mocked_check_par, mocked_err, mocked_decode,
                        mocked_conv, mocked_command, mocked_check_err):
        # Correct case: with amount requested
        request = pb.PayInvoiceRequest(
            payment_request='random', amount_bits=77.7)
        mocked_decode.return_value = pb.DecodeInvoiceResponse()
        mocked_conv.return_value = 7770000
        mocked_command.return_value = fix.SEND
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_decode.assert_called_once_with(dec_req, CTX)
        assert not mocked_err().unsettable.called
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_TX)
        mocked_command.assert_called_once_with(CTX, 'send', 'random',
                                               '7770000', env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, fix.SEND, always_abort=False)
        self.assertEqual(res.payment_preimage, fix.SEND['paymentPreimage'])
        # Correct case: no amount requested
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='random')
        mocked_decode.return_value = pb.DecodeInvoiceResponse()
        mocked_command.return_value = fix.SEND
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_decode.assert_called_once_with(dec_req, CTX)
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        mocked_command.assert_called_once_with(CTX, 'send', 'random', env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, fix.SEND, always_abort=False)
        self.assertEqual(res.payment_preimage, fix.SEND['paymentPreimage'])
        # Missing parameter case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        assert not mocked_decode.called
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_check_err.called
        # Unimplemented parameter case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.PayInvoiceRequest(cltv_expiry_delta=7)
        mocked_err().unimplemented_parameter.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'cltv_expiry_delta')
        assert not mocked_decode.called
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_check_err.called
        # Unsettable parameter amount_bits case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(
            payment_request='random', amount_bits=77.7)
        mocked_decode.return_value = pb.DecodeInvoiceResponse(amount_bits=7.7)
        mocked_err().unsettable.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_decode.assert_called_once_with(dec_req, CTX)
        mocked_err().unsettable.assert_called_once_with(
            CTX, 'amount_bits')
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_check_err.called
        # Parameter payment_request not valid case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='random')
        mocked_decode.return_value = pb.DecodeInvoiceResponse()
        mocked_command.return_value = fix.SEND_ERROR
        mocked_err().invalid.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_decode.assert_called_once_with(dec_req, CTX)
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        mocked_command.assert_called_once_with(CTX, 'send',
                                               request.payment_request,
                                               env=settings.ECL_ENV)
        mocked_err().invalid.assert_called_once_with(CTX, 'payment_request')
        assert not mocked_check_err.called
        # Strange error case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='something')
        mocked_decode.return_value = pb.DecodeInvoiceResponse()
        mocked_command.return_value = fix.STRANGERESPONSE
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        mocked_decode.assert_called_once_with(dec_req, CTX)
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        mocked_command.assert_called_once_with(CTX, 'send',
                                               request.payment_request,
                                               env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, fix.STRANGERESPONSE, always_abort=False)
        self.assertEqual(res, pb.PayInvoiceResponse())
        # Unexpected error case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='something')
        mocked_decode.return_value = pb.DecodeInvoiceResponse()
        mocked_command.return_value = fix.BADRESPONSE
        mocked_check_err.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        mocked_decode.assert_called_once_with(dec_req, CTX)
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        mocked_command.assert_called_once_with(CTX, 'send',
                                               request.payment_request,
                                               env=settings.ECL_ENV)
        mocked_check_err.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair._add_route_hint', autospec=True)
    @patch('lighter.light_eclair.convert', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    @patch('lighter.light_eclair.Err')
    @patch('lighter.light_eclair.check_req_params', autospec=True)
    def test_DecodeInvoice(self, mocked_check_par, mocked_err, mocked_command,
                           mocked_conv, mocked_add, mocked_check_err):
        # Correct case: with description hash
        request = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_command.return_value = fix.CHECKINVOICE_HASH
        mocked_conv.return_value = 7.77
        res = MOD.DecodeInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'checkinvoice',
                                               'random', env=settings.ECL_ENV)
        assert not mocked_err().invoice_incorrect.called
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS,
                                            fix.CHECKINVOICE_HASH['amount'])
        assert mocked_add.called
        mocked_check_err.assert_called_once_with(
            CTX, fix.CHECKINVOICE_HASH, always_abort=False)
        self.assertEqual(res.amount_bits, 7.77)
        self.assertEqual(res.timestamp, fix.CHECKINVOICE_HASH['timestamp'])
        self.assertEqual(res.destination_pubkey,
                         fix.CHECKINVOICE_HASH['nodeId'])
        self.assertEqual(res.payment_hash,
                         fix.CHECKINVOICE_HASH['tags'][0]['hash'])
        self.assertEqual(res.description, '')
        self.assertEqual(res.description_hash,
                         fix.CHECKINVOICE_HASH['tags'][1]['hash'])
        self.assertEqual(res.expiry_time, 0)
        self.assertEqual(res.min_final_cltv_expiry, 0)
        # Correct case: with simple description
        reset_mocks(vars())
        request = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_command.return_value = fix.CHECKINVOICE_DESC
        mocked_conv.return_value = 20000
        res = MOD.DecodeInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'checkinvoice',
                                               'random', env=settings.ECL_ENV)
        assert not mocked_err().invoice_incorrect.called
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS,
                                            fix.CHECKINVOICE_DESC['amount'])
        assert not mocked_add.called
        mocked_check_err.assert_called_once_with(
            CTX, fix.CHECKINVOICE_DESC, always_abort=False)
        self.assertEqual(res.amount_bits, 20000)
        self.assertEqual(res.timestamp, fix.CHECKINVOICE_DESC['timestamp'])
        self.assertEqual(res.destination_pubkey,
                         fix.CHECKINVOICE_DESC['nodeId'])
        self.assertEqual(res.payment_hash,
                         fix.CHECKINVOICE_DESC['tags'][0]['hash'])
        self.assertEqual(res.description,
                         fix.CHECKINVOICE_DESC['tags'][1]['description'])
        self.assertEqual(res.description_hash, '')
        # Missing parameter case
        reset_mocks(vars())
        request = pb.DecodeInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, CTX)
        assert not mocked_command.called
        assert not mocked_conv.called
        assert not mocked_add.called
        assert not mocked_check_err.called
        # Incorrect invoice case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_command.return_value = 'aaa invalid payment request zzz'
        mocked_err().invalid.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'checkinvoice',
                                               'random', env=settings.ECL_ENV)
        mocked_err().invalid.assert_called_once_with(CTX, 'payment_request')
        assert not mocked_conv.called
        assert not mocked_add.called
        assert not mocked_check_err.called
        # Error case
        reset_mocks(vars())
        request = pb.DecodeInvoiceRequest(payment_request='something')
        mocked_command.return_value = fix.BADRESPONSE
        mocked_check_err.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'checkinvoice',
                                               'something',
                                               env=settings.ECL_ENV)
        assert not mocked_conv.called
        assert not mocked_add.called
        mocked_check_err.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)
        self.assertEqual(res, 'not set')

    def test_defined(self):
        """
        This method is so simple that it will not be mocked in other tests
        """
        # Correct case
        data = {'key': 'value'}
        res = MOD._defined(data, 'key')
        self.assertEqual(res, True)
        # None case
        data = {'key': None}
        res = MOD._defined(data, 'key')
        self.assertEqual(res, False)
        # Unexistent key case
        res = MOD._defined(data, 'not a key')
        self.assertEqual(res, False)

    @patch('lighter.light_eclair.convert', autospec=True)
    def test_add_channel(self, mocked_conv):
        response = pb.ListChannelsResponse()
        mocked_conv.side_effect = [0, 20000]
        res = MOD._add_channel(CTX, response, fix.CHANNEL_NORMAL)
        calls = [
            call(CTX, Enf.MSATS, 0),
            call(CTX, Enf.MSATS, 2000000000)
        ]
        mocked_conv.assert_has_calls(calls)
        self.assertEqual(res, None)
        self.assertEqual(response.channels[0].remote_pubkey,
                         fix.CHANNEL_NORMAL['nodeId'])
        self.assertEqual(response.channels[0].channel_id,
                         fix.CHANNEL_NORMAL['channelId'])
        self.assertEqual(response.channels[0].short_channel_id,
                         fix.CHANNEL_NORMAL['data']['shortChannelId'])
        self.assertEqual(response.channels[0].local_balance, 0)
        self.assertEqual(response.channels[0].remote_balance, 20000)
        self.assertEqual(response.channels[0].capacity, 20000)

    def test_add_route_hint(self):
        response = pb.DecodeInvoiceResponse()
        ecl_route = fix.CHECKINVOICE_HASH['tags'][3]['path']
        res = MOD._add_route_hint(response, ecl_route)
        self.assertEqual(res, None)
        self.assertEqual(response.route_hints[0].hop_hints[0].pubkey,
                         ecl_route[0]['nodeId'])
        self.assertEqual(response.route_hints[0].hop_hints[0].short_channel_id,
                         ecl_route[0]['shortChannelId'])
        self.assertEqual(response.route_hints[0].hop_hints[0].fee_base_msat, 1)
        self.assertEqual(
            response.route_hints[0].hop_hints[0].fee_proportional_millionths,
            ecl_route[0]['feeProportionalMillionths'])
        self.assertEqual(
            response.route_hints[0].hop_hints[0].cltv_expiry_delta,
            ecl_route[0]['cltvExpiryDelta'])
        self.assertEqual(response.route_hints[0].hop_hints[1].pubkey,
                         ecl_route[1]['nodeId'])
        self.assertEqual(response.route_hints[0].hop_hints[1].short_channel_id,
                         ecl_route[1]['shortChannelId'])
        self.assertEqual(response.route_hints[0].hop_hints[1].fee_base_msat, 2)
        self.assertEqual(
            response.route_hints[0].hop_hints[1].fee_proportional_millionths,
            ecl_route[1]['feeProportionalMillionths'])
        self.assertEqual(
            response.route_hints[0].hop_hints[1].cltv_expiry_delta,
            ecl_route[1]['cltvExpiryDelta'])

    @patch('lighter.light_eclair.Err')
    def test_handle_error(self, mocked_err):
        mocked_err().report_error.side_effect = Exception()
        mocked_err().unexpected_error.side_effect = Exception()
        # Key 'failures' in ecl_res
        reset_mocks(vars())
        with self.assertRaises(Exception):
            MOD._handle_error(CTX, fix.BADRESPONSE)
        error = 'unmapped error + extra error'
        mocked_err().report_error.assert_called_once_with(CTX, error)
        assert not mocked_err().unexpected_error.called
        # No key 'failures', report_error finds error, always_abort=False
        reset_mocks(vars())
        ecl_res = 'strange error'
        with self.assertRaises(Exception):
            MOD._handle_error(CTX, ecl_res, always_abort=False)
        mocked_err().report_error.assert_called_once_with(
            CTX, ecl_res, always_abort=False)
        assert not mocked_err().unexpected_error.called
        # No key 'failures', report_error doesn't find error, always_abort=True
        reset_mocks(vars())
        ecl_res = {'no failures': 'in ecl_res'}
        mocked_err().report_error.side_effect = None
        mocked_err().unexpected_error.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD._handle_error(CTX, ecl_res)
        mocked_err().report_error.assert_called_once_with(
            CTX, ecl_res, always_abort=False)
        mocked_err().unexpected_error.assert_called_once_with(
            CTX, ecl_res)


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
