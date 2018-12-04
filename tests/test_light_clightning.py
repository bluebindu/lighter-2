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
""" Tests for light_clightning module """

from importlib import import_module
from json import loads
from unittest import TestCase
from unittest.mock import call, patch, Mock, MagicMock

from lighter import lighter_pb2 as pb
from lighter import light_clightning, settings
from lighter.light_clightning import ERRORS
from lighter.utils import Enforcer as Enf
from tests import fixtures_clightning as fix

MOD = import_module('lighter.light_clightning')


class LightClightningTests(TestCase):
    """ Tests for light_clightning module """

    def test_update_settings(self):
        # Correct case
        values = {
            'CL_CLI': 'lightning-cli',
            'CL_CLI_DIR': '/path',
            'CL_RPC': 'lightning-rpc',
            'CL_RPC_DIR': '/path/'
        }
        with patch.dict('os.environ', values):
            MOD.update_settings()
        self.assertEqual(settings.CMD_BASE, [
            '/path/lightning-cli', '--lightning-dir={}'.format(
                values['CL_RPC_DIR']), '--rpc-file={}'.format(
                    values['CL_RPC']), '-k'
        ])
        # Missing variable
        reset_mocks(vars())
        settings.CMD_BASE = ''
        values = {}
        with patch.dict('os.environ', values):
            with self.assertRaises(KeyError):
                MOD.update_settings()
        self.assertEqual(settings.CMD_BASE, '')

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_GetInfo(self, mocked_command, mocked_check_err):
        # Correct case
        mocked_command.return_value = fix.getinfo
        res = MOD.GetInfo('request', 'context')
        mocked_command.assert_called_once_with('context', 'getinfo')
        mocked_check_err.assert_called_once_with(
            'context', fix.getinfo, always_abort=False)
        self.assertEqual(res.identity_pubkey, '022d558f74f2ab2a78d29ebf')
        self.assertEqual(res.alias, 'pie')
        self.assertEqual(res.color, '#DCDCDC')
        self.assertEqual(res.version, 'v0.6')
        self.assertEqual(res.blockheight, 7777)
        self.assertEqual(res.network, 'testnet')
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.badresponse
        mocked_check_err.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.GetInfo('request', 'context')
        mocked_command.assert_called_once_with('context', 'getinfo')
        mocked_check_err.assert_called_once_with(
            'context', fix.badresponse, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_NewAddress(self, mocked_command, mocked_check_err):
        # Default case: request.type = 0 = NP2WKH = P2SH_SEGWIT
        request = pb.NewAddressRequest()
        mocked_command.return_value = fix.newaddress[pb.NP2WKH]
        res = MOD.NewAddress(request, 'context')
        mocked_command.assert_called_once_with('context', 'newaddr',
                                               'addresstype=p2sh-segwit')
        mocked_check_err.assert_called_once_with(
            'context', fix.newaddress[pb.NP2WKH], always_abort=False)
        self.assertEqual(res.address, fix.newaddress[pb.NP2WKH]['address'])
        # Legacy case: request.type = 0 = NP2WKH = P2SH_SEGWIT
        reset_mocks(vars())
        request = pb.NewAddressRequest(type=pb.NP2WKH)
        mocked_command.return_value = fix.newaddress[pb.NP2WKH]
        res = MOD.NewAddress(request, 'context')
        mocked_command.assert_called_once_with('context', 'newaddr',
                                               'addresstype=p2sh-segwit')
        mocked_check_err.assert_called_once_with(
            'context', fix.newaddress[pb.NP2WKH], always_abort=False)
        self.assertEqual(res.address, fix.newaddress[pb.NP2WKH]['address'])
        # Segwit case: request.type = 1 = P2WKH = BECH32
        reset_mocks(vars())
        request = pb.NewAddressRequest(type=pb.P2WKH)
        mocked_command.return_value = fix.newaddress[pb.P2WKH]
        res = MOD.NewAddress(request, 'context')
        mocked_command.assert_called_once_with('context', 'newaddr',
                                               'addresstype=bech32')
        mocked_check_err.assert_called_once_with(
            'context', fix.newaddress[pb.P2WKH], always_abort=False)
        self.assertEqual(res.address, fix.newaddress[pb.P2WKH]['address'])
        # Error case
        reset_mocks(vars())
        request = pb.NewAddressRequest()
        res = 'not set'
        mocked_command.return_value = fix.badresponse
        mocked_check_err.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.NewAddress(request, 'context')
        mocked_command.assert_called_once_with('context', 'newaddr',
                                               'addresstype=p2sh-segwit')
        mocked_check_err.assert_called_once_with(
            'context', fix.badresponse, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_WalletBalance(self, mocked_command, mocked_check_err,
                           mocked_conv):
        # Correct case
        mocked_command.return_value = fix.listfunds
        mocked_conv.return_value = 0.14
        res = MOD.WalletBalance('request', 'context')
        mocked_command.assert_called_once_with('context', 'listfunds')
        mocked_check_err.assert_called_once_with(
            'context', fix.listfunds, always_abort=False)
        mocked_conv.assert_called_once_with('context', Enf.SATS, 14)
        self.assertEqual(res.balance, 0.14)
        # No funds case
        reset_mocks(vars())
        mocked_command.return_value = fix.listfunds_empty
        mocked_conv.return_value = 0.0
        res = MOD.WalletBalance('request', 'context')
        mocked_command.assert_called_once_with('context', 'listfunds')
        mocked_check_err.assert_called_once_with(
            'context', fix.listfunds_empty, always_abort=False)
        mocked_conv.assert_called_once_with('context', Enf.SATS, 0.0)
        self.assertEqual(res.balance, 0.0)
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.badresponse
        mocked_check_err.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.WalletBalance('request', 'context')
        mocked_command.assert_called_once_with('context', 'listfunds')
        mocked_check_err.assert_called_once_with(
            'context', fix.badresponse, always_abort=False)

    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_ChannelBalance(self, mocked_command, mocked_check_err,
                            mocked_conv):
        # Correct case
        mocked_command.return_value = fix.listfunds
        mocked_conv.return_value = 10
        res = MOD.ChannelBalance('request', 'context')
        mocked_command.assert_called_once_with('context', 'listfunds')
        mocked_check_err.assert_called_once_with(
            'context', fix.listfunds, always_abort=False)
        mocked_conv.assert_called_once_with('context', Enf.SATS, 1000)
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.badresponse
        res = MOD.ChannelBalance('request', 'context')
        mocked_command.assert_called_once_with('context', 'listfunds')
        mocked_check_err.assert_called_once_with(
            'context', fix.badresponse, always_abort=False)

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_ListPeers(self, mocked_command, mocked_check_err):
        # Correct case
        mocked_command.return_value = fix.listpeers
        res = MOD.ListPeers('request', 'context')
        mocked_command.assert_called_once_with('context', 'listpeers')
        mocked_check_err.assert_called_once_with(
            'context', fix.listpeers, always_abort=False)
        self.assertEqual(res.peers[0].pubkey, '02212d3ec887188b284dbb7b222d2e')
        self.assertEqual(res.peers[0].alias, 'yalls.org')
        self.assertEqual(res.peers[0].address, '54.236.55.50:9735')
        # No peers case
        reset_mocks(vars())
        mocked_command.return_value = fix.listpeers_empty
        res = MOD.ListPeers('request', 'context')
        mocked_command.assert_called_once_with('context', 'listpeers')
        mocked_check_err.assert_called_once_with(
            'context', fix.listpeers_empty, always_abort=False)
        self.assertEqual(res, pb.ListPeersResponse())
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.badresponse
        res = MOD.ListPeers('request', 'context')
        mocked_command.assert_called_once_with('context', 'listpeers')
        mocked_check_err.assert_called_once_with(
            'context', fix.badresponse, always_abort=False)

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning._add_channel', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_ListChannels(self, mocked_command, mocked_add, mocked_check_err):
        # Correct case: request.active_only = False
        request = pb.ListChannelsRequest()
        mocked_command.return_value = fix.listpeers
        res = MOD.ListChannels(request, 'context')
        mocked_command.assert_called_once_with('context', 'listpeers')
        assert mocked_add.called
        mocked_check_err.assert_called_once_with(
            'context', fix.listpeers, always_abort=False)
        # Correct case: request.active_only = True
        reset_mocks(vars())
        request = pb.ListChannelsRequest(active_only=True)
        mocked_command.return_value = fix.listpeers
        res = MOD.ListChannels(request, 'context')
        mocked_command.assert_called_once_with('context', 'listpeers')
        mocked_check_err.assert_called_once_with(
            'context', fix.listpeers, always_abort=False)
        # No channels case
        reset_mocks(vars())
        mocked_command.return_value = fix.listpeers_empty
        res = MOD.ListChannels('request', 'context')
        mocked_command.assert_called_once_with('context', 'listpeers')
        assert not mocked_add.called
        mocked_check_err.assert_called_once_with(
            'context', fix.listpeers_empty, always_abort=False)
        self.assertEqual(res, pb.ListChannelsResponse())
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.badresponse
        res = MOD.ListChannels('request', 'context')
        mocked_command.assert_called_once_with('context', 'listpeers')
        assert not mocked_add.called
        mocked_check_err.assert_called_once_with(
            'context', fix.badresponse, always_abort=False)

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    @patch('lighter.light_clightning._create_label', autospec=True)
    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning.Err')
    def test_CreateInvoice(self, mocked_err, mocked_conv, mocked_label,
                           mocked_command, mocked_check_err):
        # Correct case
        request = pb.CreateInvoiceRequest(
            amount_bits=7,
            description='funny',
            expiry_time=1800,
            fallback_addr='2Mwfzt2fAqRSDUaMLFwjtkTukVUBJB4kDqv')
        mocked_conv.return_value = 700000
        mocked_label.return_value = 'label'
        mocked_command.return_value = fix.invoice
        res = MOD.CreateInvoice(request, 'context')
        assert not mocked_err().unsettable.called
        mocked_conv.assert_called_once_with(
            'context', Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        mocked_label.assert_called_once_with()
        mocked_command.assert_called_once_with(
            'context', 'invoice', 'msatoshi="700000"', 'description="funny"',
            'label="label"', 'expiry="1800"',
            'fallbacks=["2Mwfzt2fAqRSDUaMLFwjtkTukVUBJB4kDqv"]')
        mocked_check_err.assert_called_once_with(
            'context', fix.invoice, always_abort=False)
        self.assertEqual(res.payment_hash, fix.invoice['payment_hash'])
        self.assertEqual(res.payment_request, fix.invoice['bolt11'])
        self.assertEqual(res.expires_at, fix.invoice['expires_at'])
        # Correct case: donation invoice (missing amount_bits)
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(description='funny')
        mocked_label.return_value = 'label'
        mocked_command.return_value = fix.invoice
        res = MOD.CreateInvoice(request, 'context')
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        mocked_label.assert_called_once_with()
        mocked_command.assert_called_once_with(
            'context', 'invoice', 'msatoshi="any"', 'description="funny"',
            'label="label"')
        mocked_check_err.assert_called_once_with(
            'context', fix.invoice, always_abort=False)
        self.assertEqual(res.payment_hash, fix.invoice['payment_hash'])
        self.assertEqual(res.payment_request, fix.invoice['bolt11'])
        self.assertEqual(res.expires_at, fix.invoice['expires_at'])
        # Correct case: description default if missing in request
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(amount_bits=7)
        mocked_label.return_value = 'label'
        mocked_command.return_value = fix.invoice
        res = MOD.CreateInvoice(request, 'context')
        assert not mocked_err().unsettable.called
        mocked_conv.assert_called_once_with(
            'context', Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        mocked_label.assert_called_once_with()
        mocked_command.assert_called_once_with(
            'context', 'invoice', 'msatoshi="700000"',
            'description="{}"'.format(settings.DEFAULT_DESCRIPTION),
            'label="label"')
        mocked_check_err.assert_called_once_with(
            'context', fix.invoice, always_abort=False)
        self.assertEqual(res.payment_hash, fix.invoice['payment_hash'])
        self.assertEqual(res.payment_request, fix.invoice['bolt11'])
        self.assertEqual(res.expires_at, fix.invoice['expires_at'])
        # Unsettable parameter min_final_cltv_expiry case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(min_final_cltv_expiry=7)
        mocked_err().unsettable.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CreateInvoice(request, 'context')
        mocked_err().unsettable.assert_called_once_with(
            'context', 'min_final_cltv_expiry')
        assert not mocked_conv.called
        assert not mocked_label.called
        assert not mocked_command.called
        assert not mocked_check_err.called
        # Error case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(amount_bits=7, description='funny')
        mocked_command.return_value = fix.badresponse
        mocked_check_err.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.CreateInvoice(request, 'context')
        assert not mocked_err().unsettable.called
        mocked_conv.assert_called_once_with(
            'context', Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        mocked_label.assert_called_once_with()
        mocked_command.assert_called_once_with(
            'context', 'invoice', 'msatoshi="700000"', 'description="funny"',
            'label="label"')
        mocked_check_err.assert_called_once_with(
            'context', fix.badresponse, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.Err')
    @patch('lighter.light_clightning.command', autospec=True)
    def test_CheckInvoice(self, mocked_command, mocked_err, mocked_check_err):
        # Correct case: paid invoice
        request = pb.CheckInvoiceRequest(
            payment_hash=
            '302cd6bc8dd20437172f48d8693c7099fd4cb6d08e3f8519b406b21880677b28')
        mocked_command.return_value = fix.listinvoices
        res = MOD.CheckInvoice(request, 'context')
        mocked_command.assert_called_once_with('context', 'listinvoices')
        assert not mocked_err().missing_parameter.called
        assert not mocked_check_err.called
        assert not mocked_err().invoice_not_found.called
        self.assertEqual(res.settled, True)
        # Correct case: unpaid invoice
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest(
            payment_hash=
            '2229b24c728326e2adb2c6166d3ba432fba8867678c6d2bca08b04ca09227a97')
        mocked_command.return_value = fix.listinvoices
        res = MOD.CheckInvoice(request, 'context')
        mocked_command.assert_called_once_with('context', 'listinvoices')
        assert not mocked_err().missing_parameter.called
        assert not mocked_check_err.called
        assert not mocked_err().invoice_not_found.called
        self.assertEqual(res.settled, False)
        # Missing parameter payment_hash case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest()
        mocked_err().missing_parameter.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, 'context')
        assert not mocked_command.called
        mocked_err().missing_parameter.assert_called_once_with(
            'context', 'payment_hash')
        assert not mocked_check_err.called
        assert not mocked_err().invoice_not_found.called
        # Invoice not found case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest(payment_hash='unexistent')
        mocked_command.return_value = fix.listinvoices
        mocked_err().invoice_not_found.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, 'context')
        mocked_command.assert_called_once_with('context', 'listinvoices')
        mocked_check_err.assert_called_once_with(
            'context', fix.listinvoices, always_abort=False)
        mocked_err().invoice_not_found.assert_called_once_with('context')
        self.assertEqual(res, 'not set')
        # Invoice found with no status case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest(
            payment_hash=
            '6c6466e514c26db149d8801b910e2201390cfa7112bf4f42ce01897b5ff83058')
        mocked_command.return_value = fix.listinvoices
        res = MOD.CheckInvoice(request, 'context')
        mocked_command.assert_called_once_with('context', 'listinvoices')
        assert not mocked_err().missing_parameter.called
        assert not mocked_err().invoice_not_found.called
        assert not mocked_check_err.called
        self.assertEqual(res, pb.CheckInvoiceResponse())
        # Error case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest(payment_hash='random')
        mocked_command.return_value = fix.badresponse
        mocked_check_err.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, 'context')
        mocked_command.assert_called_once_with('context', 'listinvoices')
        assert not mocked_err().missing_parameter.called
        mocked_check_err.assert_called_once_with(
            'context', fix.badresponse, always_abort=False)
        assert not mocked_err().invoice_not_found.called
        # Sette
        assert 7

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    @patch('lighter.light_clightning.Enf.check_value')
    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning.DecodeInvoice', autospec=True)
    @patch('lighter.light_clightning.Err')
    def test_PayInvoice(self, mocked_err, mocked_decode, mocked_conv,
                        mocked_check_val, mocked_command, mocked_check_err):
        # Correct case
        request = pb.PayInvoiceRequest(
            payment_request='lntb77u1something',
            amount_bits=777,
            description='funny',
            cltv_expiry_delta=7)
        mocked_decode.return_value = pb.DecodeInvoiceResponse()
        mocked_conv.return_value = 77700000
        mocked_command.return_value = fix.pay
        res = MOD.PayInvoice(request, 'context')
        assert not mocked_err().missing_parameter.called
        dec_req = pb.DecodeInvoiceRequest(payment_request='lntb77u1something')
        mocked_decode.assert_called_once_with(dec_req, 'context')
        assert not mocked_err().unsettable.called
        mocked_conv.assert_called_once_with(
            'context', Enf.MSATS, request.amount_bits, enforce=Enf.LN_TX)
        mocked_command.assert_called_once_with(
            'context', 'pay', 'bolt11="lntb77u1something"',
            'msatoshi="77700000"', 'description="funny"', 'maxdelay="7"')
        mocked_check_err.assert_called_once_with(
            'context', fix.pay, always_abort=False)
        self.assertEqual(
            res.payment_preimage,
            'd628d988a3a33fde1db8c1b800d16a1135ee030e21866ae24ae9269d7cd41632')
        # Missing parameter payment_request case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest()
        mocked_err().missing_parameter.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, 'context')
        mocked_err().missing_parameter.assert_called_once_with(
            'context', 'payment_request')
        assert not mocked_decode.called
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_check_err.called
        # Unsettable parameter amount_bits case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(
            payment_request='something', amount_bits=777)
        mocked_decode.return_value = pb.DecodeInvoiceResponse(amount_bits=7)
        mocked_err().unsettable.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, 'context')
        assert not mocked_err().missing_parameter.called
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        mocked_decode.assert_called_once_with(dec_req, 'context')
        mocked_err().unsettable.assert_called_once_with(
            'context', 'amount_bits')
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_check_err.called
        # Error response case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='something')
        mocked_check_val.return_value = 0
        mocked_command.return_value = fix.badresponse
        mocked_check_err.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, 'context')
        assert not mocked_err().missing_parameter.called
        assert not mocked_decode.called
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        mocked_command.assert_called_once_with('context', 'pay',
                                               'bolt11="something"')
        mocked_check_err.assert_called_once_with(
            'context', fix.badresponse, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning._add_route_hint', autospec=True)
    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    @patch('lighter.light_clightning.Err')
    def test_DecodeInvoice(self, mocked_err, mocked_command, mocked_conv,
                           mocked_add, mocked_check_err):
        # Correct case: simple description, fallback and routes
        request = pb.DecodeInvoiceRequest(
            payment_request='lntb77u1something', description='funny')
        mocked_command.return_value = fix.decodepay
        mocked_conv.return_value = 7
        res = MOD.DecodeInvoice(request, 'context')
        assert not mocked_err().missing_parameter.called
        mocked_command.assert_called_once_with('context', 'decodepay',
                                               'bolt11="lntb77u1something"',
                                               'description="funny"')
        mocked_conv.assert_called_once_with('context', Enf.MSATS, 700000)
        assert mocked_add.called
        self.assertEqual(mocked_add.call_count, 2)
        mocked_check_err.assert_called_once_with(
            'context', fix.decodepay, always_abort=False)
        self.assertEqual(res.amount_bits, 7)
        self.assertEqual(res.timestamp, 1533127505)
        self.assertEqual(
            res.payment_hash,
            'b6fac49eac5b36bb6699e716645ddf4d823746ea522c3d3ebde2f04f9a652ec0')
        self.assertEqual(res.description, 'Funny\r')
        self.assertEqual(
            res.destination_pubkey,
            '02212d3ec887188b284dbb7b2e6eb40629a6e14fb049673f22d2a0aa05f902090e'
        )
        self.assertEqual(res.description_hash, '')
        self.assertEqual(res.expiry_time, 3600)
        self.assertEqual(res.min_final_cltv_expiry, 144)
        self.assertEqual(res.fallback_addr,
                         '2NENXARsztTVBv1ZyJMMVF1YPGfgS5eejgC')
        # Correct case: hashed description, fallback, no routes
        reset_mocks(vars())
        mocked_command.return_value = fix.decodepay_hash
        mocked_conv.return_value = 1.5
        res = MOD.DecodeInvoice(request, 'context')
        assert not mocked_err().missing_parameter.called
        mocked_command.assert_called_once_with('context', 'decodepay',
                                               'bolt11="lntb77u1something"',
                                               'description="funny"')
        mocked_conv.assert_called_once_with('context', Enf.MSATS, 150000)
        assert not mocked_add.called
        mocked_check_err.assert_called_once_with(
            'context', fix.decodepay_hash, always_abort=False)
        self.assertEqual(res.amount_bits, 1.5)
        self.assertEqual(res.timestamp, 1496314658)
        self.assertEqual(
            res.payment_hash,
            '0001020304050607080900010203040506070809000102030405060708090102')
        self.assertEqual(res.description, '')
        self.assertEqual(
            res.destination_pubkey,
            '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
        )
        self.assertEqual(
            res.description_hash,
            '3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1')
        self.assertEqual(res.expiry_time, 3600)
        self.assertEqual(res.min_final_cltv_expiry, 9)
        self.assertEqual(res.fallback_addr,
                         'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP')
        # Missing parameter payment_request
        reset_mocks(vars())
        request = pb.DecodeInvoiceRequest()
        mocked_err().missing_parameter.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, 'context')
        mocked_err().missing_parameter.assert_called_once_with(
            'context', 'payment_request')
        assert not mocked_command.called
        assert not mocked_conv.called
        assert not mocked_add.called
        assert not mocked_check_err.called
        # Error response case
        reset_mocks(vars())
        request = pb.DecodeInvoiceRequest(payment_request='lntb77u1something')
        mocked_command.return_value = fix.badresponse
        mocked_check_err.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, 'context')
        assert not mocked_err().missing_parameter.called
        mocked_command.assert_called_once_with('context', 'decodepay',
                                               'bolt11="lntb77u1something"')
        assert not mocked_conv.called
        assert not mocked_add.called
        mocked_check_err.assert_called_once_with(
            'context', fix.badresponse, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_clightning.convert', autospec=True)
    def test_add_channel(self, mocked_conv):
        response = pb.ListChannelsResponse()
        cl_peer = fix.listpeers['peers'][0]
        cl_chan = cl_peer['channels'][0]
        mocked_conv.side_effect = [50000.0, 48.0]
        res = MOD._add_channel('context', response, cl_peer, cl_chan)
        calls = [
            call('context', Enf.MSATS, 5000000000),
            call('context', Enf.MSATS, 4800000)
        ]
        mocked_conv.assert_has_calls(calls)
        self.assertEqual(res, None)
        self.assertEqual(res, None)
        self.assertEqual(response.channels[0].remote_pubkey,
                         '0322deb288d430d3165af3d7456432111ff6cff3f431c9ae1')
        self.assertEqual(response.channels[0].short_channel_id, '1323814:55:0')
        self.assertEqual(
            response.channels[0].channel_id,
            'd32457de4d654931271272c1d8aa2a73576891e9cc918afacfa54f6bdfb8')
        self.assertEqual(
            response.channels[0].funding_txid,
            'b8df6b4fa5ffa8a91cce9916857aaad8c1777212273149654dde5724d3bd')
        self.assertEqual(response.channels[0].to_self_delay, 144)
        self.assertEqual(response.channels[0].capacity, 50000.0)
        self.assertEqual(response.channels[0].local_balance, 48.0)
        self.assertEqual(response.channels[0].remote_balance, 50000 - 48)

    @patch('lighter.light_clightning.convert', autospec=True)
    def test_add_route_hint(self, mocked_conv):
        response = pb.DecodeInvoiceResponse()
        cl_route = fix.decodepay['routes'][0]
        mocked_conv.side_effect = [0.00001, 0.00002]
        res = MOD._add_route_hint('context', response, cl_route)
        calls = [call('context', Enf.MSATS, 1), call('context', Enf.MSATS, 2)]
        mocked_conv.assert_has_calls(calls)
        self.assertEqual(res, None)
        self.assertEqual(
            response.route_hints[0].hop_hints[0].pubkey,
            '029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'
        )
        self.assertEqual(response.route_hints[0].hop_hints[0].short_channel_id,
                         '66051:263430:1800')
        self.assertEqual(response.route_hints[0].hop_hints[0].fee_base_bits,
                         0.00001)
        self.assertEqual(
            response.route_hints[0].hop_hints[0].fee_proportional_millionths,
            20)
        self.assertEqual(
            response.route_hints[0].hop_hints[0].cltv_expiry_delta, 3)
        self.assertEqual(
            response.route_hints[0].hop_hints[1].pubkey,
            '039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'
        )
        self.assertEqual(response.route_hints[0].hop_hints[1].short_channel_id,
                         '197637:395016:2314')
        self.assertEqual(response.route_hints[0].hop_hints[1].fee_base_bits,
                         0.00002)
        self.assertEqual(
            response.route_hints[0].hop_hints[1].fee_proportional_millionths,
            30)
        self.assertEqual(
            response.route_hints[0].hop_hints[1].cltv_expiry_delta, 4)

    @patch('lighter.light_clightning.datetime', autospec=True)
    def test_create_label(self, mocked_datetime):
        mocked_datetime.now().timestamp.return_value = 1533152937.911157
        res = MOD._create_label()
        self.assertEqual(res, '1533152937911157')

    @patch('lighter.light_clightning.Err')
    def test_handle_error(self, mocked_err):
        mocked_err().report_error.side_effect = Exception()
        mocked_err().unexpected_error.side_effect = Exception()
        # Keys code and message in cl_res
        reset_mocks(vars())
        cl_res = {'code': 7, 'message': 'an error'}
        with self.assertRaises(Exception):
            MOD._handle_error('context', cl_res)
        mocked_err().report_error.assert_called_once_with(
            'context', cl_res['message'])
        assert not mocked_err().unexpected_error.called
        # Keys code and message not in cl_res, always_abort=True
        reset_mocks(vars())
        cl_res = {'no code': 'in cl_res'}
        with self.assertRaises(Exception):
            MOD._handle_error('context', cl_res)
        assert not mocked_err().report_error.called
        mocked_err().unexpected_error.assert_called_once_with(
            'context', cl_res)
        # Keys code and message not in cl_res, always_abort=False
        reset_mocks(vars())
        cl_res = {'no code': 'in cl_res'}
        light_clightning._handle_error(
            'context', cl_res, always_abort=False)
        assert not mocked_err().report_error.called
        assert not mocked_err().unexpected_error.called


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
