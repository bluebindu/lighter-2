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
from unittest import TestCase
from unittest.mock import call, patch

from lighter import lighter_pb2 as pb
from lighter import light_clightning, settings
from lighter.utils import Enforcer as Enf
from tests import fixtures_clightning as fix

MOD = import_module('lighter.light_clightning')
CTX = 'context'


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
            MOD.update_settings(None)
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
                MOD.update_settings(None)
        self.assertEqual(settings.CMD_BASE, '')

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_GetInfo(self, mocked_command, mocked_handle):
        # Correct case
        mocked_command.return_value = fix.GETINFO
        res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'getinfo')
        mocked_handle.assert_called_once_with(
            CTX, fix.GETINFO, always_abort=False)
        self.assertEqual(res.identity_pubkey, '022d558f74f2ab2a78d29ebf')
        self.assertEqual(res.alias, fix.GETINFO['alias'])
        self.assertEqual(res.color, '#{}'.format(fix.GETINFO['color']))
        self.assertEqual(res.version, fix.GETINFO['version'])
        self.assertEqual(res.blockheight, fix.GETINFO['blockheight'])
        self.assertEqual(res.network, 'mainnet')
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.BADRESPONSE
        mocked_handle.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.GetInfo('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'getinfo')
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_NewAddress(self, mocked_command, mocked_handle):
        # Legacy case: request.type = 0 = NP2WKH = P2SH_SEGWIT
        reset_mocks(vars())
        request = pb.NewAddressRequest()
        mocked_command.return_value = fix.NEWADDRESS_P2SH_SEGWIT
        res = MOD.NewAddress(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'newaddr',
                                               'addresstype=p2sh-segwit')
        mocked_handle.assert_called_once_with(
            CTX, fix.NEWADDRESS_P2SH_SEGWIT, always_abort=False)
        self.assertEqual(
            res.address, fix.NEWADDRESS_P2SH_SEGWIT['p2sh-segwit'])
        # Segwit case: request.type = 1 = P2WKH = BECH32
        reset_mocks(vars())
        request = pb.NewAddressRequest(type=pb.P2WKH)
        mocked_command.return_value = fix.NEWADDRESS_BECH32
        res = MOD.NewAddress(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'newaddr',
                                               'addresstype=bech32')
        mocked_handle.assert_called_once_with(
            CTX, fix.NEWADDRESS_BECH32, always_abort=False)
        self.assertEqual(res.address, fix.NEWADDRESS_BECH32['bech32'])
        # Error case
        reset_mocks(vars())
        request = pb.NewAddressRequest()
        res = 'not set'
        mocked_command.return_value = fix.BADRESPONSE
        mocked_handle.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.NewAddress(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'newaddr',
                                               'addresstype=p2sh-segwit')
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_WalletBalance(self, mocked_command, mocked_handle,
                           mocked_conv):
        # Correct case
        mocked_command.return_value = fix.LISTFUNDS
        mocked_conv.return_value = 0.14
        res = MOD.WalletBalance('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'listfunds')
        mocked_handle.assert_called_once_with(
            CTX, fix.LISTFUNDS, always_abort=False)
        mocked_conv.assert_called_once_with(CTX, Enf.SATS, 14)
        self.assertEqual(res.balance, 0.14)
        # No funds case
        reset_mocks(vars())
        mocked_command.return_value = fix.LISTFUNDS_EMPTY
        mocked_conv.return_value = 0.0
        res = MOD.WalletBalance('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'listfunds')
        mocked_handle.assert_called_once_with(
            CTX, fix.LISTFUNDS_EMPTY, always_abort=False)
        mocked_conv.assert_called_once_with(CTX, Enf.SATS, 0.0)
        self.assertEqual(res.balance, 0.0)
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.BADRESPONSE
        mocked_handle.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.WalletBalance('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'listfunds')
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)

    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_ChannelBalance(self, mocked_command, mocked_handle,
                            mocked_conv):
        # Correct case
        mocked_command.return_value = fix.LISTFUNDS
        mocked_conv.return_value = 10
        res = MOD.ChannelBalance('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'listfunds')
        mocked_handle.assert_called_once_with(
            CTX, fix.LISTFUNDS, always_abort=False)
        mocked_conv.assert_called_once_with(CTX, Enf.SATS, 1000)
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.BADRESPONSE
        res = MOD.ChannelBalance('request', CTX)
        mocked_command.assert_called_once_with(CTX, 'listfunds')
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning._add_channel', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_ListChannels(self, mocked_command, mocked_add, mocked_handle):
        api = 'listpeers'
        # Correct case: request.active_only = False
        request = pb.ListChannelsRequest()
        mocked_command.return_value = fix.LISTPEERS
        res = MOD.ListChannels(request, CTX)
        mocked_command.assert_called_once_with(CTX, api)
        assert mocked_add.called
        mocked_handle.assert_called_once_with(
            CTX, fix.LISTPEERS, always_abort=False)
        # Correct case: request.active_only = True
        reset_mocks(vars())
        request = pb.ListChannelsRequest(active_only=True)
        mocked_command.return_value = fix.LISTPEERS
        res = MOD.ListChannels(request, CTX)
        mocked_command.assert_called_once_with(CTX, api)
        mocked_handle.assert_called_once_with(
            CTX, fix.LISTPEERS, always_abort=False)
        # No channels case
        reset_mocks(vars())
        mocked_command.return_value = fix.LISTPEERS_EMPTY
        res = MOD.ListChannels('request', CTX)
        mocked_command.assert_called_once_with(CTX, api)
        assert not mocked_add.called
        mocked_handle.assert_called_once_with(
            CTX, fix.LISTPEERS_EMPTY, always_abort=False)
        self.assertEqual(res, pb.ListChannelsResponse())
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.BADRESPONSE
        res = MOD.ListChannels('request', CTX)
        mocked_command.assert_called_once_with(CTX, api)
        assert not mocked_add.called
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning._add_payment', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_ListPayments(self, mocked_command, mocked_add, mocked_handle):
        api = 'listpayments'
        # Correct case
        request = pb.ListPaymentsRequest()
        mocked_command.return_value = fix.PAYMENTS
        res = MOD.ListPayments(request, CTX)
        mocked_command.assert_called_once_with(CTX, api)
        assert mocked_add.called
        # Error case
        reset_mocks(vars())
        mocked_command.return_value = fix.BADRESPONSE
        res = MOD.ListPayments('request', CTX)
        mocked_command.assert_called_once_with(CTX, api)
        assert not mocked_add.called
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    def test_ListPeers(self, mocked_command, mocked_handle):
        listpeers = 'listpeers'
        listnodes = 'listnodes'
        # Correct case
        mocked_command.side_effect = [fix.LISTPEERS, fix.LISTNODES]
        res = MOD.ListPeers('request', CTX)
        self.assertEqual(mocked_command.call_count, 2)
        mocked_handle.assert_called_once_with(
            CTX, fix.LISTPEERS, always_abort=False)
        self.assertEqual(res.peers[0].pubkey, fix.LISTPEERS['peers'][1]['id'])
        self.assertEqual(res.peers[0].alias, 'lighter')
        self.assertEqual(res.peers[0].address, '54.236.55.50:9735')
        # No peers case
        reset_mocks(vars())
        mocked_command.side_effect = [fix.LISTPEERS_EMPTY, fix.LISTNODES]
        res = MOD.ListPeers('request', CTX)
        mocked_command.assert_called_once_with(CTX, listpeers)
        mocked_handle.assert_called_once_with(
            CTX, fix.LISTPEERS_EMPTY, always_abort=False)
        self.assertEqual(res, pb.ListPeersResponse())
        # Error case
        reset_mocks(vars())
        mocked_command.side_effect = [fix.BADRESPONSE, fix.LISTNODES]
        res = MOD.ListPeers('request', CTX)
        mocked_command.assert_called_once_with(CTX, listpeers)
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    @patch('lighter.light_clightning._create_label', autospec=True)
    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning.Err')
    def test_CreateInvoice(self, mocked_err, mocked_conv, mocked_label,
                           mocked_command, mocked_handle):
        # Correct case
        request = pb.CreateInvoiceRequest(
            amount_bits=7,
            description='funny',
            expiry_time=1800,
            fallback_addr='2Mwfzt2fAqRSDUaMLFwjtkTukVUBJB4kDqv')
        mocked_conv.return_value = 700000
        mocked_label.return_value = 'label'
        mocked_command.return_value = fix.INVOICE
        res = MOD.CreateInvoice(request, CTX)
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        mocked_label.assert_called_once_with()
        mocked_command.assert_called_once_with(
            CTX, 'invoice', 'msatoshi="700000"', 'description="funny"',
            'label="label"', 'expiry="1800"',
            'fallbacks=["2Mwfzt2fAqRSDUaMLFwjtkTukVUBJB4kDqv"]')
        mocked_handle.assert_called_once_with(
            CTX, fix.INVOICE, always_abort=False)
        self.assertEqual(res.payment_hash, fix.INVOICE['payment_hash'])
        self.assertEqual(res.payment_request, fix.INVOICE['bolt11'])
        self.assertEqual(res.expires_at, fix.INVOICE['expires_at'])
        # Correct case: donation invoice (missing amount_bits)
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(description='funny')
        mocked_label.return_value = 'label'
        mocked_command.return_value = fix.INVOICE
        res = MOD.CreateInvoice(request, CTX)
        assert not mocked_conv.called
        mocked_label.assert_called_once_with()
        mocked_command.assert_called_once_with(
            CTX, 'invoice', 'msatoshi="any"', 'description="funny"',
            'label="label"')
        mocked_handle.assert_called_once_with(
            CTX, fix.INVOICE, always_abort=False)
        self.assertEqual(res.payment_hash, fix.INVOICE['payment_hash'])
        self.assertEqual(res.payment_request, fix.INVOICE['bolt11'])
        self.assertEqual(res.expires_at, fix.INVOICE['expires_at'])
        # Correct case: description default if missing in request
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(amount_bits=7)
        mocked_label.return_value = 'label'
        mocked_command.return_value = fix.INVOICE
        res = MOD.CreateInvoice(request, CTX)
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        mocked_label.assert_called_once_with()
        mocked_command.assert_called_once_with(
            CTX, 'invoice', 'msatoshi="700000"', 'description="{}"'.format(
                settings.DEFAULT_DESCRIPTION), 'label="label"')
        mocked_handle.assert_called_once_with(
            CTX, fix.INVOICE, always_abort=False)
        self.assertEqual(res.payment_hash, fix.INVOICE['payment_hash'])
        self.assertEqual(res.payment_request, fix.INVOICE['bolt11'])
        self.assertEqual(res.expires_at, fix.INVOICE['expires_at'])
        # Unimplemented parameter case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(min_final_cltv_expiry=7)
        mocked_err().unimplemented_parameter.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CreateInvoice(request, CTX)
        assert not mocked_conv.called
        assert not mocked_label.called
        assert not mocked_command.called
        assert not mocked_handle.called
        # Error case
        reset_mocks(vars())
        mocked_err().unimplemented_parameter.side_effect = None
        request = pb.CreateInvoiceRequest(amount_bits=7, description='funny')
        mocked_command.return_value = fix.BADRESPONSE
        mocked_handle.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.CreateInvoice(request, CTX)
        assert not mocked_err().unsettable.called
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        mocked_label.assert_called_once_with()
        mocked_command.assert_called_once_with(
            CTX, 'invoice', 'msatoshi="700000"', 'description="funny"',
            'label="label"')
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.Err')
    @patch('lighter.light_clightning.command', autospec=True)
    @patch('lighter.light_clightning.check_req_params', autospec=True)
    def test_CheckInvoice(self, mocked_check_par, mocked_command, mocked_err, mocked_handle):
        # Correct case: paid invoice
        request = pb.CheckInvoiceRequest(
            payment_hash=
            '302cd6bc8dd20437172f48d8693c7099fd4cb6d08e3f8519b406b21880677b28')
        mocked_command.return_value = fix.LISTINVOICES
        res = MOD.CheckInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'listinvoices')
        assert not mocked_handle.called
        assert not mocked_err().invoice_not_found.called
        self.assertEqual(res.settled, True)
        # Correct case: unpaid invoice
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest(
            payment_hash=
            '2229b24c728326e2adb2c6166d3ba432fba8867678c6d2bca08b04ca09227a97')
        mocked_command.return_value = fix.LISTINVOICES
        res = MOD.CheckInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'listinvoices')
        assert not mocked_handle.called
        assert not mocked_err().invoice_not_found.called
        self.assertEqual(res.settled, False)
        # Missing parameter case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, CTX)
        assert not mocked_command.called
        assert not mocked_handle.called
        assert not mocked_err().invoice_not_found.called
        # Invoice not found case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.CheckInvoiceRequest(payment_hash='unexistent')
        mocked_command.return_value = fix.LISTINVOICES
        mocked_err().invoice_not_found.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'listinvoices')
        mocked_handle.assert_called_once_with(
            CTX, fix.LISTINVOICES, always_abort=False)
        mocked_err().invoice_not_found.assert_called_once_with(CTX)
        self.assertEqual(res, 'not set')
        # Invoice found with no status case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest(
            payment_hash=
            '6c6466e514c26db149d8801b910e2201390cfa7112bf4f42ce01897b5ff83058')
        mocked_command.return_value = fix.LISTINVOICES
        res = MOD.CheckInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'listinvoices')
        assert not mocked_err().invoice_not_found.called
        assert not mocked_handle.called
        self.assertEqual(res, pb.CheckInvoiceResponse())
        # Error case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest(payment_hash='random')
        mocked_command.return_value = fix.BADRESPONSE
        mocked_handle.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'listinvoices')
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)
        assert not mocked_err().invoice_not_found.called
        # Sette
        assert 7

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    @patch('lighter.light_clightning.Enf.check_value')
    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning.DecodeInvoice', autospec=True)
    @patch('lighter.light_clightning.Err')
    @patch('lighter.light_clightning.check_req_params', autospec=True)
    def test_PayInvoice(self, mocked_check_par, mocked_err, mocked_decode,
                        mocked_conv, mocked_check_val, mocked_command,
                        mocked_handle):
        # Correct case
        request = pb.PayInvoiceRequest(
            payment_request='lntb77u1something',
            amount_bits=777,
            description='funny',
            cltv_expiry_delta=7)
        mocked_decode.return_value = pb.DecodeInvoiceResponse()
        mocked_conv.return_value = 77700000
        mocked_command.return_value = fix.PAY
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='lntb77u1something')
        mocked_decode.assert_called_once_with(dec_req, CTX)
        assert not mocked_err().unsettable.called
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_TX)
        mocked_command.assert_called_once_with(
            CTX, 'pay', 'bolt11="lntb77u1something"', 'msatoshi="77700000"',
            'description="funny"', 'maxdelay="7"')
        mocked_handle.assert_called_once_with(
            CTX, fix.PAY, always_abort=False)
        self.assertEqual(
            res.payment_preimage,
            'd628d988a3a33fde1db8c1b800d16a1135ee030e21866ae24ae9269d7cd41632')
        # Missing parameter amount_bits case
        reset_mocks(vars())
        mocked_check_par.side_effect = [None, Exception()]
        request = pb.PayInvoiceRequest(payment_request='something')
        mocked_decode.return_value = pb.DecodeInvoiceResponse()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        mocked_decode.assert_called_once_with(dec_req, CTX)
        self.assertEqual(mocked_check_par.call_count, 2)
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_handle.called
        # Missing parameter payment_request case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        assert not mocked_decode.called
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_handle.called
        # Unsettable parameter amount_bits case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.PayInvoiceRequest(
            payment_request='something', amount_bits=777)
        mocked_decode.return_value = pb.DecodeInvoiceResponse(amount_bits=7)
        mocked_err().unsettable.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        mocked_decode.assert_called_once_with(dec_req, CTX)
        mocked_err().unsettable.assert_called_once_with(CTX, 'amount_bits')
        assert not mocked_conv.called
        assert not mocked_command.called
        assert not mocked_handle.called
        # Incorrect cltv_expiry_delta case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='something',
                                       cltv_expiry_delta=65537)
        mocked_check_val.return_value = False
        mocked_err().out_of_range.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        assert not mocked_command.called
        # Error response case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='something')
        mocked_check_val.return_value = 0
        mocked_command.return_value = fix.BADRESPONSE
        mocked_handle.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        assert mocked_decode.called
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        mocked_command.assert_called_once_with(CTX, 'pay',
                                               'bolt11="something"')
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    @patch('lighter.light_clightning.Enf.check_value')
    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning.Err')
    @patch('lighter.light_clightning.check_req_params', autospec=True)
    def test_PayOnChain(self, mocked_check_par, mocked_err, mocked_conv,
                        mocked_check_val, mocked_command, mocked_handle):
        api = 'withdraw'
        amt = 7
        fee_sat_byte = 1
        # Missing parameter case
        request = pb.PayOnChainRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.PayOnChain(request, CTX)
        # Incorrect fee case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.PayOnChainRequest(
            amount_bits=amt, address=fix.ADDRESS, fee_sat_byte=fee_sat_byte)
        mocked_check_val.return_value = False
        mocked_err().out_of_range.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.PayOnChain(request, CTX)
        assert not mocked_command.called
        # Correct case
        reset_mocks(vars())
        request = pb.PayOnChainRequest(
            amount_bits=amt, address=fix.ADDRESS, fee_sat_byte=fee_sat_byte)
        mocked_conv.return_value = amt
        mocked_check_val.return_value = True
        mocked_command.return_value = fix.WITHDRAW
        MOD.PayOnChain(request, CTX)
        # Error case
        reset_mocks(vars())
        request = pb.PayOnChainRequest(address=fix.ADDRESS, amount_bits=amt)
        mocked_command.return_value = fix.BADRESPONSE
        res = MOD.PayOnChain(request, CTX)
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)

    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning._add_route_hint', autospec=True)
    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    @patch('lighter.light_clightning.Err')
    @patch('lighter.light_clightning.check_req_params', autospec=True)
    def test_DecodeInvoice(self, mocked_check_par, mocked_err, mocked_command,
                           mocked_conv, mocked_add, mocked_handle):
        # Correct case: simple description, fallback and routes
        request = pb.DecodeInvoiceRequest(
            payment_request='lntb77u1s', description='funny')
        mocked_command.return_value = fix.DECODEPAY
        mocked_conv.return_value = 7
        res = MOD.DecodeInvoice(request, CTX)
        mocked_command.assert_called_once_with(
            CTX, 'decodepay', 'bolt11="lntb77u1s"', 'description="funny"')
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS, 700000)
        assert mocked_add.called
        self.assertEqual(mocked_add.call_count, 2)
        mocked_handle.assert_called_once_with(
            CTX, fix.DECODEPAY, always_abort=False)
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
        mocked_command.return_value = fix.DECODEPAY_HASH
        mocked_conv.return_value = 1.5
        res = MOD.DecodeInvoice(request, CTX)
        mocked_command.assert_called_once_with(
            CTX, 'decodepay', 'bolt11="lntb77u1s"', 'description="funny"')
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS, 150000)
        assert not mocked_add.called
        mocked_handle.assert_called_once_with(
            CTX, fix.DECODEPAY_HASH, always_abort=False)
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
        # Missing parameter case
        reset_mocks(vars())
        request = pb.DecodeInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, CTX)
        assert not mocked_command.called
        assert not mocked_conv.called
        assert not mocked_add.called
        assert not mocked_handle.called
        # Error response case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.DecodeInvoiceRequest(payment_request='lntb77u1s')
        mocked_command.return_value = fix.BADRESPONSE
        mocked_handle.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, CTX)
        mocked_command.assert_called_once_with(CTX, 'decodepay',
                                               'bolt11="lntb77u1s"')
        assert not mocked_conv.called
        assert not mocked_add.called
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)
        self.assertEqual(res, 'not set')

    @patch('lighter.light_clightning.convert', autospec=True)
    @patch('lighter.light_clightning._handle_error', autospec=True)
    @patch('lighter.light_clightning.command', autospec=True)
    @patch('lighter.light_clightning.Err')
    @patch('lighter.light_clightning.check_req_params', autospec=True)
    def test_OpenChannel(self, mocked_check_par, mocked_err, mocked_command,
                         mocked_handle, mocked_conv):
        amt = 7
        mocked_err().invalid.side_effect = Exception()
        mocked_err().unimplemented_parameter.side_effect = Exception()
        mocked_err().connect_failed.side_effect = Exception()
        # Filled
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI,
            private=True)
        mocked_command.side_effect = [fix.CONNECT, fix.FUNDCHANNEL]
        MOD.OpenChannel(request, CTX)
        assert not mocked_err().unimplemented_parameter.called
        # invalid node_uri case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(funding_bits=amt, node_uri='wrong')
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_err().invalid.assert_called_once_with(CTX, 'node_uri')
        # Missing parameter case
        reset_mocks(vars())
        request = pb.OpenChannelRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        assert not mocked_command.called
        # Unimplemented push_bits case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.OpenChannelRequest(
            node_uri=fix.NODE_URI, funding_bits=amt, push_bits=amt)
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        assert not mocked_command.called
        # Connect failed case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI,
            private=True)
        mocked_command.side_effect = ["", None]
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_err().connect_failed.assert_called_once_with(CTX)
        # Error case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI,
            private=True)
        mocked_command.side_effect = [fix.CONNECT, fix.BADRESPONSE]
        mocked_handle.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_handle.assert_called_once_with(
            CTX, fix.BADRESPONSE, always_abort=False)

    @patch('lighter.light_clightning.convert', autospec=True)
    def test_add_channel(self, mocked_conv):
        response = pb.ListChannelsResponse()
        cl_peer = fix.LISTPEERS['peers'][0]
        cl_chan = cl_peer['channels'][0]
        res = MOD._add_channel(CTX, response, cl_peer, cl_chan)
        self.assertEqual(mocked_conv.call_count, 2)
        self.assertEqual(res, None)
        self.assertEqual(res, None)
        self.assertEqual(response.channels[0].remote_pubkey, cl_peer['id'])
        self.assertEqual(response.channels[0].short_channel_id, cl_chan['short_channel_id'])
        self.assertEqual(response.channels[0].channel_id, cl_chan['channel_id'])
        self.assertEqual(response.channels[0].funding_txid, cl_chan['funding_txid'])
        self.assertEqual(response.channels[0].to_self_delay, cl_chan['our_to_self_delay'])
        self.assertEqual(response.channels[0].capacity, 1.0)
        self.assertEqual(response.channels[0].local_balance, 1.0)
        self.assertEqual(response.channels[0].remote_balance, 0.0)

    @patch('lighter.light_clightning.convert', autospec=True)
    def test_add_payment(self, mocked_conv):
        # Full response
        response = pb.ListPaymentsResponse()
        cl_payment = fix.PAYMENTS['payments'][0]
        MOD._add_payment(CTX, response, cl_payment)
        self.assertEqual(response.payments[0].payment_hash,
                         cl_payment['payment_hash'])
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS,
                                            cl_payment['msatoshi_sent'])
        # Failed payment case
        reset_mocks(vars())
        response = pb.ListPaymentsResponse()
        cl_payment = fix.PAYMENTS['payments'][3]
        MOD._add_payment(CTX, response, cl_payment)
        self.assertEqual(response.ListFields(), [])
        assert not mocked_conv.called

    def test_add_route_hint(self):
        response = pb.DecodeInvoiceResponse()
        cl_route = fix.DECODEPAY['routes'][0]
        res = MOD._add_route_hint(response, cl_route)
        self.assertEqual(res, None)
        self.assertEqual(
            response.route_hints[0].hop_hints[0].pubkey,
            '029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'
        )
        self.assertEqual(response.route_hints[0].hop_hints[0].short_channel_id,
                         '66051:263430:1800')
        self.assertEqual(response.route_hints[0].hop_hints[0].fee_base_msat, 1)
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
        self.assertEqual(response.route_hints[0].hop_hints[1].fee_base_msat, 2)
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
        # MacaroonKeys code and message in cl_res
        reset_mocks(vars())
        cl_res = {'code': 7, 'message': 'an error'}
        with self.assertRaises(Exception):
            MOD._handle_error(CTX, cl_res)
        mocked_err().report_error.assert_called_once_with(
            CTX, cl_res['message'])
        assert not mocked_err().unexpected_error.called
        # MacaroonKeys code and message not in cl_res, always_abort=True
        reset_mocks(vars())
        cl_res = {'no code': 'in cl_res'}
        with self.assertRaises(Exception):
            MOD._handle_error(CTX, cl_res)
        assert not mocked_err().report_error.called
        mocked_err().unexpected_error.assert_called_once_with(CTX, cl_res)
        # MacaroonKeys code and message not in cl_res, always_abort=False
        reset_mocks(vars())
        cl_res = {'no code': 'in cl_res'}
        light_clightning._handle_error(CTX, cl_res, always_abort=False)
        assert not mocked_err().report_error.called
        assert not mocked_err().unexpected_error.called


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
