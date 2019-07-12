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
from unittest import TestCase
from unittest.mock import call, patch

from lighter import lighter_pb2 as pb
from lighter import settings
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
    def test_GetInfo(self, mocked_command, mocked_handle):
        cmd = 'getinfo'
        # Mainnet case
        reset_mocks(vars())
        mocked_command.return_value = fix.GETINFO_MAINNET
        res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, cmd, env=settings.ECL_ENV)
        mocked_handle.assert_called_once_with(
            CTX, fix.GETINFO_MAINNET, always_abort=False)
        self.assertEqual(res.network, 'mainnet')
        # Regtest case
        reset_mocks(vars())
        mocked_command.return_value = fix.GETINFO_UNKNOWN
        res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, cmd, env=settings.ECL_ENV)
        mocked_handle.assert_called_once_with(
            CTX, fix.GETINFO_UNKNOWN, always_abort=False)
        self.assertEqual(res.network, 'regtest')
        # Testnet case
        reset_mocks(vars())
        mocked_command.return_value = fix.GETINFO_TESTNET
        res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, cmd, env=settings.ECL_ENV)
        self.assertEqual(res.network, 'testnet')
        self.assertEqual(res.identity_pubkey, fix.GETINFO_TESTNET['nodeId'])
        self.assertEqual(res.alias, fix.GETINFO_TESTNET['alias'])
        self.assertEqual(res.blockheight, fix.GETINFO_TESTNET['blockHeight'])
        # Strange error case
        reset_mocks(vars())
        mocked_command.return_value = fix.STRANGERESPONSE
        res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, cmd, env=settings.ECL_ENV)
        mocked_handle.assert_called_once_with(
            CTX, fix.STRANGERESPONSE, always_abort=False)
        self.assertEqual(res, pb.GetInfoResponse())
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.BADRESPONSE
        mocked_handle.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, cmd, env=settings.ECL_ENV)
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_eclair.convert', autospec=True)
    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    def test_ChannelBalance(self, mocked_command, mocked_handle,
                            mocked_conv):
        cmd = 'channels'
        # Filled
        mocked_command.return_value = fix.CHANNELS
        mocked_conv.return_value = 0.0
        res = MOD.ChannelBalance('request', CTX)
        mocked_command.assert_called_with(CTX, cmd, env=settings.ECL_ENV)
        mocked_handle.assert_called_once_with(
            CTX, fix.CHANNELS, always_abort=False)
        assert mocked_conv.called
        self.assertEqual(res.balance, 0.0)
        # Empty
        reset_mocks(vars())
        mocked_command.return_value = []
        mocked_conv.return_value = 0.0
        res = MOD.ChannelBalance('request', CTX)
        mocked_command.assert_called_once_with(CTX, cmd, env=settings.ECL_ENV)
        mocked_handle.assert_called_once_with(
            CTX, mocked_command.return_value, always_abort=False)
        assert mocked_conv.called
        self.assertEqual(res.balance, 0.0)

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    def test_ListPeers(self, mocked_command, mocked_handle):
        peers = 'peers'
        allnodes = 'allnodes'
        mocked_command.side_effect = fix.PEERS, fix.ALLNODES
        res = MOD.ListPeers('request', CTX)
        calls = [
            call(CTX, peers, env=settings.ECL_ENV),
            call(CTX, allnodes, env=settings.ECL_ENV)
        ]
        mocked_command.assert_has_calls(calls)
        mocked_handle.assert_called_once_with(
            CTX, fix.PEERS, always_abort=False)
        self.assertEqual(res.peers[0].pubkey, fix.PEERS[0]['nodeId'])
        # Empty case
        reset_mocks(vars())
        mocked_command.side_effect = [[], fix.ALLNODES]
        res = MOD.ListPeers('request', CTX)
        calls = [
            call(CTX, peers, env=settings.ECL_ENV),
            call(CTX, allnodes, env=settings.ECL_ENV)
        ]
        mocked_command.assert_has_calls(calls)
        mocked_handle.assert_called_once_with(CTX, [], always_abort=False)
        self.assertEqual(res, pb.ListPeersResponse())

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair._add_channel', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    def test_ListChannels(self, mocked_command, mocked_add, mocked_handle):
        cmd = 'channels'
        # List all channels
        reset_mocks(vars())
        mocked_command.return_value = fix.CHANNELS
        request = pb.ListChannelsRequest(active_only=False)
        res = MOD.ListChannels(request, CTX)
        mocked_command.assert_called_once_with(CTX, cmd, env=settings.ECL_ENV)
        calls = [
            call(CTX, pb.ListChannelsResponse(), fix.CHANNEL_NORMAL, False),
            call(CTX, pb.ListChannelsResponse(), fix.CHANNEL_WAITING_FUNDING,
                 False)]
        mocked_add.assert_has_calls(calls)
        mocked_handle.assert_called_once_with(
            CTX, fix.CHANNELS, always_abort=False)
        self.assertEqual(res, pb.ListChannelsResponse())
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = 'badresponse'
        mocked_handle.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.ListChannels('request', CTX)
        mocked_command.assert_called_once_with(
            CTX, cmd, env=settings.ECL_ENV)
        assert not mocked_add.called

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    @patch('lighter.light_eclair.convert', autospec=True)
    @patch('lighter.light_eclair.Err')
    def test_CreateInvoice(self, mocked_err, mocked_conv, mocked_command,
                           mocked_handle):
        cmd = 'createinvoice'
        mocked_handle.side_effect = Exception()
        pay_req = fix.CREATEINVOICE['serialized']
        pay_hash = fix.CREATEINVOICE['paymentHash']
        expiry_time = fix.CREATEINVOICE['timestamp'] + \
            fix.CREATEINVOICE['expiry']
        # Correct case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(
            description="d", amount_bits=7, expiry_time=3000,
            fallback_addr="f")
        mocked_conv.return_value = 777
        mocked_command.return_value = fix.CREATEINVOICE
        res = MOD.CreateInvoice(request, CTX)
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        mocked_command.assert_called_once_with(
            CTX, cmd, '--description="d"', '--amountMsat="777"',
            '--expireIn="3000"', '--fallbackAddress="f"', env=settings.ECL_ENV)
        assert not mocked_handle.called
        self.assertEqual(res.payment_request, pay_req)
        self.assertEqual(res.payment_hash, pay_hash)
        self.assertEqual(res.expires_at, expiry_time)
        # Empty request case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest()
        mocked_command.return_value = fix.CREATEINVOICE
        res = MOD.CreateInvoice(request, CTX)
        assert not mocked_err().unsettable.called
        mocked_command.assert_called_once_with(
            CTX, cmd,
            '--description="{}"'.format(settings.DEFAULT_DESCRIPTION),
            env=settings.ECL_ENV)
        assert not mocked_handle.called
        self.assertEqual(res.payment_request, pay_req)
        self.assertEqual(res.payment_hash, pay_hash)
        self.assertEqual(res.expires_at, expiry_time)
        # Error case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest()
        mocked_command.return_value = fix.ERROR
        with self.assertRaises(Exception):
            res = MOD.CreateInvoice(request, CTX)
        mocked_handle.assert_called_with(
            CTX, fix.ERROR, always_abort=True)
        # Unimplemented parameter case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(min_final_cltv_expiry=7)
        mocked_err().unimplemented_parameter.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CreateInvoice(request, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'min_final_cltv_expiry')
        assert not mocked_command.called
        assert not mocked_handle.called

    @patch('lighter.light_eclair.command', autospec=True)
    @patch('lighter.light_eclair.Err')
    @patch('lighter.light_eclair.check_req_params', autospec=True)
    def test_CheckInvoice(self, mocked_check_par, mocked_err, mocked_command):
        cmd = 'getreceivedinfo'
        # Correct case
        request = pb.CheckInvoiceRequest(payment_hash='random')
        mocked_command.return_value = fix.GETRECEIVEDINFO
        res = MOD.CheckInvoice(request, CTX)
        mocked_command.assert_called_once_with(
            CTX, cmd, '--paymentHash="random"', env=settings.ECL_ENV)
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
            CTX, cmd, '--paymentHash="incorrect"', env=settings.ECL_ENV)
        mocked_err().invalid.assert_called_once_with(CTX, 'payment_hash')
        self.assertEqual(res, 'not set')

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    @patch('lighter.light_eclair.convert', autospec=True)
    @patch('lighter.light_eclair.has_amount_encoded', autospec=True)
    @patch('lighter.light_eclair.Err')
    @patch('lighter.light_eclair.check_req_params', autospec=True)
    def test_PayInvoice(self, mocked_check_par, mocked_err, mocked_has_amt,
                        mocked_conv, mocked_command, mocked_handle):
        cmd = 'payinvoice'
        cmd2 = 'getsentinfo'
        # Correct case: with amount requested
        request = pb.PayInvoiceRequest(
            payment_request='random', amount_bits=7)
        mocked_has_amt.return_value = False
        mocked_conv.return_value = 777
        mocked_command.side_effect = [fix.PAYINVOICE, fix.GETSENTINFO_SUCCESS]
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        assert not mocked_err().unsettable.called
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_TX)
        calls = [
            call(CTX, cmd, '--invoice="random"', '--amountMsat="777"',
                 env=settings.ECL_ENV),
            call(CTX, cmd2, '--id="{}"'.format(fix.PAYINVOICE),
                 env=settings.ECL_ENV)
        ]
        mocked_command.assert_has_calls(calls)
        assert not mocked_handle.called
        self.assertEqual(
            res.payment_preimage, fix.GETSENTINFO_SUCCESS[0]['preimage'])
        # Correct case: no amount requested
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='random')
        mocked_has_amt.return_value = False
        mocked_command.side_effect = [fix.PAYINVOICE, fix.GETSENTINFO_SUCCESS]
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        calls = [
            call(CTX, cmd, '--invoice="random"', env=settings.ECL_ENV),
            call(CTX, cmd2, '--id="{}"'.format(fix.PAYINVOICE),
                 env=settings.ECL_ENV)
        ]
        mocked_command.assert_has_calls(calls)
        assert not mocked_handle.called
        self.assertEqual(
            res.payment_preimage, fix.GETSENTINFO_SUCCESS[0]['preimage'])
        # Missing parameter payment_request case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest()
        mocked_check_par.side_effect = [Exception(), None]
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_handle.called
        # Unimplemented parameter case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.PayInvoiceRequest(cltv_expiry_delta=7)
        mocked_err().unimplemented_parameter.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'cltv_expiry_delta')
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_handle.called
        # Unsettable parameter amount_bits case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(
            payment_request='random', amount_bits=77.7)
        mocked_has_amt.return_value = True
        mocked_err().unsettable.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_err().unsettable.assert_called_once_with(
            CTX, 'amount_bits')
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_handle.called
        # Missing parameter amount_bits case
        reset_mocks(vars())
        mocked_check_par.side_effect = [None, Exception()]
        request = pb.PayInvoiceRequest(payment_request='random')
        mocked_has_amt.return_value = False
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        self.assertEqual(mocked_check_par.call_count, 2)
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_handle.called
        # Parameter payment_request not valid case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.PayInvoiceRequest(payment_request='random')
        mocked_has_amt.return_value = False
        mocked_command.side_effect = [
            fix.PAYINVOICE_ERROR, fix.GETSENTINFO_SUCCESS]
        mocked_err().invalid.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        mocked_command.assert_called_once_with(
            CTX, cmd, '--invoice="{}"'.format(request.payment_request),
            env=settings.ECL_ENV)
        mocked_err().invalid.assert_called_once_with(CTX, 'payment_request')
        assert not mocked_handle.called
        # Failed case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='random')
        mocked_has_amt.return_value = False
        mocked_command.side_effect = [fix.PAYINVOICE, fix.GETSENTINFO_FAIL]
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        calls = [
            call(CTX, cmd, '--invoice="random"', env=settings.ECL_ENV),
            call(CTX, cmd2, '--id="{}"'.format(fix.PAYINVOICE),
                 env=settings.ECL_ENV)
        ]
        mocked_command.assert_has_calls(calls)
        assert not mocked_handle.called
        # Pending case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='random')
        mocked_has_amt.return_value = False
        mocked_command.side_effect = [fix.PAYINVOICE, fix.GETSENTINFO_PENDING]
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        calls = [
            call(CTX, cmd, '--invoice="random"', env=settings.ECL_ENV),
            call(CTX, cmd2, '--id="{}"'.format(fix.PAYINVOICE),
                 env=settings.ECL_ENV)
        ]
        mocked_command.assert_has_calls(calls)
        assert not mocked_handle.called
        # Strange error case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='something')
        mocked_has_amt.return_value = False
        mocked_command.side_effect = [fix.PAYINVOICE, fix.STRANGERESPONSE]
        mocked_handle.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        self.assertEqual(mocked_command.call_count, 2)
        mocked_handle.assert_called_once_with(
            CTX, fix.STRANGERESPONSE, always_abort=True)

    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair._is_description_hash', autospec=True)
    @patch('lighter.light_eclair.convert', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    @patch('lighter.light_eclair.Err')
    @patch('lighter.light_eclair.check_req_params', autospec=True)
    def test_DecodeInvoice(self, mocked_check_par, mocked_err, mocked_command,
                           mocked_conv, mocked_d_hash, mocked_handle):
        cmd = 'parseinvoice'
        # Correct case: with description hash
        request = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_command.return_value = fix.PARSEINVOICE_D_HASH
        mocked_conv.return_value = 7.77
        mocked_d_hash.return_value = True
        res = MOD.DecodeInvoice(request, CTX)
        mocked_command.assert_called_once_with(
            CTX, cmd, '--invoice="random"', env=settings.ECL_ENV)
        assert not mocked_err().invoice_incorrect.called
        assert mocked_conv.called
        assert not mocked_handle.called
        self.assertEqual(res.amount_bits, 7.77)
        self.assertEqual(res.timestamp, fix.PARSEINVOICE_D_HASH['timestamp'])
        self.assertEqual(res.destination_pubkey,
                         fix.PARSEINVOICE_D_HASH['nodeId'])
        self.assertEqual(res.payment_hash,
                         fix.PARSEINVOICE_D_HASH['paymentHash'])
        self.assertEqual(res.description, '')
        self.assertEqual(res.description_hash,
                         fix.PARSEINVOICE_D_HASH['description'])
        self.assertEqual(res.expiry_time, 0)
        self.assertEqual(res.min_final_cltv_expiry, 0)
        # Correct case: with simple description
        reset_mocks(vars())
        mocked_d_hash.return_value = False
        request = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_command.return_value = fix.PARSEINVOICE
        mocked_conv.return_value = 20000
        res = MOD.DecodeInvoice(request, CTX)
        mocked_command.assert_called_once_with(
            CTX, cmd, '--invoice="random"', env=settings.ECL_ENV)
        assert not mocked_err().invoice_incorrect.called
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS,
                                            fix.PARSEINVOICE['amount'])
        assert not mocked_handle.called
        self.assertEqual(res.amount_bits, 20000)
        self.assertEqual(res.timestamp, fix.PARSEINVOICE['timestamp'])
        self.assertEqual(res.destination_pubkey,
                         fix.PARSEINVOICE['nodeId'])
        self.assertEqual(res.payment_hash,
                         fix.PARSEINVOICE['paymentHash'])
        self.assertEqual(res.description,
                         fix.PARSEINVOICE['description'])
        self.assertEqual(res.description_hash, '')
        # Missing parameter case
        reset_mocks(vars())
        request = pb.DecodeInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, CTX)
        assert not mocked_command.called
        assert not mocked_conv.called
        assert not mocked_handle.called
        # Incorrect invoice case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.DecodeInvoiceRequest(payment_request='random')
        mocked_command.return_value = 'aaa invalid payment request zzz'
        mocked_err().invalid.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, CTX)
        mocked_command.assert_called_once_with(
            CTX, cmd, '--invoice="random"', env=settings.ECL_ENV)
        mocked_err().invalid.assert_called_once_with(CTX, 'payment_request')
        assert not mocked_conv.called
        assert not mocked_handle.called
        # Error case
        reset_mocks(vars())
        request = pb.DecodeInvoiceRequest(payment_request='something')
        mocked_command.return_value = fix.ERROR
        mocked_handle.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, CTX)
            mocked_command.assert_called_once_with(
                CTX, cmd, '--invoice="something"', env=settings.ECL_ENV)
        assert not mocked_conv.called
        mocked_handle.assert_called_once_with(
            CTX, fix.ERROR, always_abort=True)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_eclair.convert', autospec=True)
    @patch('lighter.light_eclair._handle_error', autospec=True)
    @patch('lighter.light_eclair.command', autospec=True)
    @patch('lighter.light_eclair.Err')
    @patch('lighter.light_eclair.check_req_params', autospec=True)
    def test_OpenChannel(self, mocked_check_par, mocked_err, mocked_command,
                         mocked_handle, mocked_conv):
        amt = 7
        mocked_err().invalid.side_effect = Exception()
        mocked_err().connect_failed.side_effect = Exception()
        mocked_handle.side_effect = Exception()
        # Filled
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI, push_bits=77,
            private=True)
        mocked_command.side_effect = [fix.CONNECT, fix.OPEN, fix.CHANNEL_NORMAL]
        res = MOD.OpenChannel(request, CTX)
        self.assertEqual(res.funding_txid,
            '53a2466cc224937a4ef91a69fed27dac24831c53b2a0a64bf484ec587d851543')
        # Error in opening channel case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI)
        mocked_command.side_effect = [fix.CONNECT, fix.ERROR]
        mocked_handle.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_handle.assert_called_once_with(
            CTX, fix.ERROR, always_abort=True)
        # Connect failed case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI)
        mocked_command.side_effect = [fix.ERROR]
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_err().connect_failed.assert_called_once_with(CTX)
        # invalid node_uri case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(funding_bits=amt, node_uri='wrong')
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_err().invalid.assert_called_once_with(CTX, 'node_uri')
        assert not mocked_command.called
        # Missing parameter case
        reset_mocks(vars())
        request = pb.OpenChannelRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        assert not mocked_command.called
        mocked_check_par.side_effect = None
        # Error in retrieving channel info (should not happen)
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI)
        mocked_command.side_effect = [fix.CONNECT, fix.ERROR_CHANNEL]
        res = MOD.OpenChannel(request, CTX)
        self.assertEqual(res, pb.OpenChannelResponse())

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

    def test_is_description_hash(self):
        res = MOD._is_description_hash(fix.PARSEINVOICE_D_HASH['description'])
        self.assertEqual(res, True)
        res = MOD._is_description_hash(fix.PARSEINVOICE['description'])
        self.assertEqual(res, False)

    @patch('lighter.light_eclair.convert', autospec=True)
    @patch('lighter.light_eclair._get_state', autospec=True)
    def test_add_channel(self, mocked_state, mocked_conv):
        # Add channel case
        response = pb.ListChannelsResponse()
        mocked_conv.side_effect = [0, 20000]
        mocked_state.return_value = pb.OPEN
        res = MOD._add_channel(CTX, response, fix.CHANNEL_NORMAL, False)
        calls = [
            call(CTX, Enf.MSATS, 50000000),
            call(CTX, Enf.MSATS, 150000000)
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
        self.assertEqual(response.channels[0].private, True)
        # Skip add of closed channel case
        reset_mocks(vars())
        response = pb.ListChannelsResponse()
        mocked_state.return_value = -1
        res = MOD._add_channel(CTX, response, fix.CHANNEL_NORMAL, False)
        self.assertEqual(response, pb.ListChannelsResponse())
        # Skip add of inactive channel case
        reset_mocks(vars())
        response = pb.ListChannelsResponse()
        mocked_state.return_value = pb.OPEN
        res = MOD._add_channel(CTX, response, fix.CHANNEL_OFFLINE, True)
        self.assertEqual(response, pb.ListChannelsResponse())

    def test_get_state(self):
        res = MOD._get_state(fix.CHANNEL_WAITING_FUNDING)
        self.assertEqual(res, pb.PENDING_OPEN)
        res = MOD._get_state(fix.CHANNEL_NORMAL)
        self.assertEqual(res, pb.OPEN)
        res = MOD._get_state(fix.CHANNEL_OFFLINE)
        self.assertEqual(res, pb.OPEN)
        res = MOD._get_state(fix.CHANNEL_UNKNOWN)
        self.assertEqual(res, pb.UNKNOWN)
        res = MOD._get_state(fix.CHANNEL_MUTUAL)
        self.assertEqual(res, pb.PENDING_MUTUAL_CLOSE)
        res = MOD._get_state(fix.CHANNEL_UNILATERAL)
        self.assertEqual(res, pb.PENDING_FORCE_CLOSE)
        res = MOD._get_state(fix.CHANNEL_CLOSED)
        self.assertEqual(res, -1)

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
            CTX, str(ecl_res))


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
