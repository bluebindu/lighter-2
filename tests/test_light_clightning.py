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

from concurrent.futures import TimeoutError as TimeoutFutError
from importlib import import_module
from unittest import TestCase
from unittest.mock import Mock, patch

from . import fixtures_clightning as fix, proj_root

CTX = 'context'
Enf = getattr(import_module(proj_root + '.utils.bitcoin'), 'Enforcer')
pb = import_module(proj_root + '.lighter_pb2')
settings = import_module(proj_root + '.settings')

MOD = import_module(proj_root + '.light_clightning')


class LightClightningTests(TestCase):
    """ Tests for light_clightning module """

    @patch(MOD.__name__ + '.path', autospec=True)
    @patch(MOD.__name__ + '.get_path', autospec=True)
    @patch(MOD.__name__ + '.set_defaults', autospec=True)
    def test_get_settings(self, mocked_set_def, mocked_get_path, mocked_path):
        # Correct case
        cl_rpc_dir = '/path'
        cl_rpc = 'lightning-rpc'
        config = Mock()
        config.get.side_effect = [cl_rpc_dir, cl_rpc]
        mocked_get_path.return_value = cl_rpc_dir
        mocked_path.join.return_value = '{}/{}'.format(cl_rpc_dir, cl_rpc)
        MOD.get_settings(config, 'clightning')
        cl_values = ['CL_RPC']
        mocked_set_def.assert_called_once_with(config, cl_values)
        # Error case
        reset_mocks(vars())
        config.get.side_effect = [cl_rpc_dir, cl_rpc]
        mocked_path.exists.return_value = False
        with self.assertRaises(RuntimeError):
            MOD.get_settings(config, 'clightning')

    def test_update_settings(self):
        MOD.update_settings(None)

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    def test_GetInfo(self, mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Correct case
        ses.getinfo.return_value = (fix.GETINFO, False)
        res = MOD.GetInfo('request', CTX)
        ses.getinfo.assert_called_once_with(CTX)
        self.assertEqual(res.identity_pubkey, fix.GETINFO['id'])
        self.assertEqual(res.node_uri, '{}@{}:{}'.format(
            fix.GETINFO['id'], fix.GETINFO['address'][0]['address'],
            fix.GETINFO['address'][0]['port']))
        self.assertEqual(res.alias, fix.GETINFO['alias'])
        self.assertEqual(res.color, '#{}'.format(fix.GETINFO['color']))
        self.assertEqual(res.version, fix.GETINFO['version'])
        self.assertEqual(res.blockheight, fix.GETINFO['blockheight'])
        self.assertEqual(res.network, 'mainnet')
        # Correct case: with empty address list
        reset_mocks(vars())
        ses.getinfo.return_value = (fix.GETINFO_EMPTY, False)
        res = MOD.GetInfo('request', CTX)
        ses.getinfo.assert_called_once_with(CTX)
        self.assertEqual(res.node_uri, '')
        # Error case
        reset_mocks(vars())
        ses.getinfo.return_value = (fix.BADRESPONSE, True)
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.GetInfo('request', CTX)
        ses.getinfo.assert_called_once_with(CTX)
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)
        self.assertEqual(res, 'not set')

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    def test_NewAddress(self, mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Legacy case: request.type = 0 = NP2WKH = P2SH_SEGWIT
        request = pb.NewAddressRequest()
        ses.newaddr.return_value = (fix.NEWADDRESS_P2SH_SEGWIT, False)
        res = MOD.NewAddress(request, CTX)
        ses.newaddr.assert_called_once_with(
            CTX, {'addresstype': 'p2sh-segwit'})
        self.assertEqual(
            res.address, fix.NEWADDRESS_P2SH_SEGWIT['p2sh-segwit'])
        # Segwit case: request.type = 1 = P2WKH = BECH32
        reset_mocks(vars())
        request = pb.NewAddressRequest(type=pb.P2WKH)
        ses.newaddr.return_value = (fix.NEWADDRESS_BECH32, False)
        res = MOD.NewAddress(request, CTX)
        ses.newaddr.assert_called_once_with(CTX, {'addresstype': 'bech32'})
        self.assertEqual(res.address, fix.NEWADDRESS_BECH32['bech32'])
        # Error case
        reset_mocks(vars())
        request = pb.NewAddressRequest()
        res = 'not set'
        ses.newaddr.return_value = (fix.BADRESPONSE, True)
        with self.assertRaises(Exception):
            res = MOD.NewAddress(request, CTX)
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)
        self.assertEqual(res, 'not set')

    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    def test_WalletBalance(self, mocked_rpcses, mocked_handle, mocked_conv):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Correct case
        ses.listfunds.return_value = (fix.LISTFUNDS, False)
        mocked_conv.return_value = 0.14
        res = MOD.WalletBalance('request', CTX)
        ses.listfunds.assert_called_once_with(CTX)
        self.assertEqual(mocked_conv.call_count, 2)
        self.assertEqual(res.balance, 0.14)
        # No funds case
        reset_mocks(vars())
        ses.listfunds.return_value = (fix.LISTFUNDS_EMPTY, False)
        mocked_conv.return_value = 0.0
        res = MOD.WalletBalance('request', CTX)
        ses.listfunds.assert_called_once_with(CTX)
        self.assertEqual(mocked_conv.call_count, 2)
        self.assertEqual(res.balance, 0.0)
        # Error case
        reset_mocks(vars())
        ses.listfunds.return_value = (fix.BADRESPONSE, True)
        with self.assertRaises(Exception):
            res = MOD.WalletBalance('request', CTX)
        ses.listfunds.assert_called_once_with(CTX)
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)

    @patch(MOD.__name__ + '.get_channel_balances', autospec=True)
    @patch(MOD.__name__ + '.ListChannels', autospec=True)
    def test_ChannelBalance(self, mocked_ListChannels, mocked_get_chan_bal):
        mocked_get_chan_bal.return_value = pb.ChannelBalanceResponse()
        res = MOD.ChannelBalance('request', CTX)
        self.assertEqual(res, pb.ChannelBalanceResponse())

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '._add_channel', autospec=True)
    @patch(MOD.__name__ + '._get_channel_state', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    def test_ListChannels(self, mocked_rpcses, mocked_state, mocked_add,
                          mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Correct case: request.active_only = False
        request = pb.ListChannelsRequest()
        ses.listpeers.return_value = (fix.LISTPEERS, False)
        mocked_state.return_value = pb.OPEN
        res = MOD.ListChannels(request, CTX)
        ses.listpeers.assert_called_once_with(CTX)
        assert mocked_add.called
        # Correct case: request.active_only = True
        reset_mocks(vars())
        request = pb.ListChannelsRequest(active_only=True)
        ses.listpeers.return_value = (fix.LISTPEERS, False)
        res = MOD.ListChannels(request, CTX)
        ses.listpeers.assert_called_once_with(CTX)
        # No channels case
        reset_mocks(vars())
        ses.listpeers.return_value = (fix.LISTPEERS_EMPTY, False)
        res = MOD.ListChannels('request', CTX)
        ses.listpeers.assert_called_once_with(CTX)
        assert not mocked_add.called
        self.assertEqual(res, pb.ListChannelsResponse())
        # Negative state case (closed channel)
        reset_mocks(vars())
        request = pb.ListChannelsRequest()
        ses.listpeers.return_value = (fix.LISTPEERS, False)
        mocked_state.return_value = -1
        res = MOD.ListChannels(request, CTX)
        ses.listpeers.assert_called_once_with(CTX)
        assert not mocked_add.called
        # Error case
        reset_mocks(vars())
        ses.listpeers.return_value = (fix.BADRESPONSE, True)
        with self.assertRaises(Exception):
            res = MOD.ListChannels('request', CTX)
        ses.listpeers.assert_called_once_with(CTX)
        assert not mocked_add.called
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '._add_payment', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    def test_ListPayments(self, mocked_rpcses, mocked_add, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Correct case
        request = pb.ListPaymentsRequest()
        ses.listsendpays.return_value = (fix.PAYMENTS, False)
        res = MOD.ListPayments(request, CTX)
        ses.listsendpays.assert_called_once_with(CTX)
        assert mocked_add.called
        # Error case
        reset_mocks(vars())
        ses.listsendpays.return_value = (fix.BADRESPONSE, True)
        with self.assertRaises(Exception):
            res = MOD.ListPayments('request', CTX)
        ses.listsendpays.assert_called_once_with(CTX)
        assert not mocked_add.called
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    def test_ListPeers(self, mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Correct case
        ses.listpeers.return_value = (fix.LISTPEERS, False)
        ses.listnodes.return_value = (fix.LISTNODES, False)
        res = MOD.ListPeers('request', CTX)
        ses.listpeers.assert_called_once_with(CTX)
        peer_id = fix.LISTPEERS['peers'][1]['id']
        ses.listnodes.assert_called_once_with(CTX, {'id': peer_id})
        self.assertEqual(res.peers[0].pubkey, peer_id)
        self.assertEqual(res.peers[0].alias, 'lighter')
        self.assertEqual(res.peers[0].address, '54.236.55.50:9735')
        # No peers case
        reset_mocks(vars())
        ses.listpeers.return_value = (fix.LISTPEERS_EMPTY, False)
        ses.listnodes.return_value = (fix.LISTNODES, False)
        res = MOD.ListPeers('request', CTX)
        ses.listpeers.assert_called_once_with(CTX)
        self.assertEqual(res, pb.ListPeersResponse())
        # Error case
        reset_mocks(vars())
        ses.listpeers.return_value = (fix.BADRESPONSE, True)
        ses.listnodes.return_value = (fix.LISTNODES, False)
        with self.assertRaises(Exception):
            res = MOD.ListPeers('request', CTX)
        ses.listpeers.assert_called_once_with(CTX)
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    @patch(MOD.__name__ + '._create_label', autospec=True)
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '.Err')
    def test_CreateInvoice(self, mocked_err, mocked_conv, mocked_label,
                           mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Correct case
        request = pb.CreateInvoiceRequest(
            amount_bits=7,
            description='funny',
            expiry_time=1800,
            fallback_addr='2Mwfzt2fAqRSDUaMLFwjtkTukVUBJB4kDqv')
        mocked_conv.return_value = 700000
        lbl = 'label'
        mocked_label.return_value = lbl
        ses.invoice.return_value = (fix.INVOICE, False)
        res = MOD.CreateInvoice(request, CTX)
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        mocked_label.assert_called_once_with()
        cl_req = {'msatoshi': 700000, 'description': 'funny', 'label': lbl,
               'expiry': 1800,
               'fallbacks': ["2Mwfzt2fAqRSDUaMLFwjtkTukVUBJB4kDqv"]}
        ses.invoice.assert_called_once_with(CTX, cl_req)
        self.assertEqual(res.payment_hash, fix.INVOICE['payment_hash'])
        self.assertEqual(res.payment_request, fix.INVOICE['bolt11'])
        self.assertEqual(res.expires_at, fix.INVOICE['expires_at'])
        # Correct case: donation invoice (missing amount_bits)
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(description='funny')
        ses.invoice.return_value = (fix.INVOICE, False)
        res = MOD.CreateInvoice(request, CTX)
        assert not mocked_conv.called
        mocked_label.assert_called_once_with()
        cl_req = {'msatoshi': 'any', 'description': 'funny', 'label': lbl,
               'expiry': settings.EXPIRY_TIME}
        ses.invoice.assert_called_once_with(CTX, cl_req)
        self.assertEqual(res.payment_hash, fix.INVOICE['payment_hash'])
        self.assertEqual(res.payment_request, fix.INVOICE['bolt11'])
        self.assertEqual(res.expires_at, fix.INVOICE['expires_at'])
        # Correct case: description missing in request
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(amount_bits=7)
        mocked_label.return_value = 'label'
        ses.invoice.return_value = (fix.INVOICE, False)
        res = MOD.CreateInvoice(request, CTX)
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        mocked_label.assert_called_once_with()
        cl_req = {'msatoshi': 700000, 'description': '', 'label': lbl,
               'expiry': settings.EXPIRY_TIME}
        ses.invoice.assert_called_once_with(CTX, cl_req)
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
        assert not ses.invoice.called
        assert not mocked_handle.called
        # Error case
        reset_mocks(vars())
        mocked_err().unimplemented_parameter.side_effect = None
        request = pb.CreateInvoiceRequest(amount_bits=7, description='funny')
        ses.invoice.return_value = (fix.BADRESPONSE, True)
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.CreateInvoice(request, CTX)
        assert not mocked_err().unsettable.called
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        mocked_label.assert_called_once_with()
        cl_req = {'msatoshi': 700000, 'description': 'funny', 'label': lbl,
               'expiry': settings.EXPIRY_TIME}
        ses.invoice.assert_called_once_with(CTX, cl_req)
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)
        self.assertEqual(res, 'not set')

    @patch(MOD.__name__ + '._get_invoice_state', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.ClightningRPC')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_CheckInvoice(self, mocked_check_par, mocked_rpcses, mocked_err,
                          mocked_handle, mocked_inv_st):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Correct case: paid invoice
        request = pb.CheckInvoiceRequest(
            payment_hash=
            '302cd6bc8dd20437172f48d8693c7099fd4cb6d08e3f8519b406b21880677b28')
        ses.listinvoices.return_value = (fix.LISTINVOICES, False)
        mocked_inv_st.return_value = pb.PAID
        res = MOD.CheckInvoice(request, CTX)
        ses.listinvoices.assert_called_once_with(CTX)
        assert not mocked_err().invoice_not_found.called
        self.assertEqual(res.settled, True)
        self.assertEqual(res.state, pb.PAID)
        # Correct case: unpaid invoice
        reset_mocks(vars())
        mocked_inv_st.return_value = pb.PENDING
        res = MOD.CheckInvoice(request, CTX)
        ses.listinvoices.assert_called_once_with(CTX)
        assert not mocked_err().invoice_not_found.called
        self.assertEqual(res.settled, False)
        self.assertEqual(res.state, pb.PENDING)
        # Correct case: expired invoice
        reset_mocks(vars())
        mocked_inv_st.return_value = pb.EXPIRED
        res = MOD.CheckInvoice(request, CTX)
        ses.listinvoices.assert_called_once_with(CTX)
        assert not mocked_err().invoice_not_found.called
        self.assertEqual(res.settled, False)
        self.assertEqual(res.state, pb.EXPIRED)
        # Missing parameter case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, CTX)
        assert not ses.listinvoices.called
        assert not mocked_err().invoice_not_found.called
        # Invoice not found case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.CheckInvoiceRequest(payment_hash='unexistent')
        ses.listinvoices.return_value = (fix.LISTINVOICES, False)
        mocked_err().invoice_not_found.side_effect = Exception()
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, CTX)
        ses.listinvoices.assert_called_once_with(CTX)
        mocked_err().invoice_not_found.assert_called_once_with(CTX)
        self.assertEqual(res, 'not set')
        # Error case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest(payment_hash='random')
        ses.listinvoices.return_value = (fix.BADRESPONSE, True)
        mocked_handle.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, CTX)
        ses.listinvoices.assert_called_once_with(CTX)
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)
        assert not mocked_err().invoice_not_found.called

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    @patch(MOD.__name__ + '.Enf.check_value')
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '.has_amount_encoded', autospec=True)
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_PayInvoice(self, mocked_check_par, mocked_err, mocked_has_amt,
                        mocked_conv, mocked_check_val, mocked_rpcses,
                        mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Correct case
        pay_req = 'lntb77u1something'
        request = pb.PayInvoiceRequest(
            payment_request=pay_req,
            amount_bits=777,
            description='funny',
            cltv_expiry_delta=7)
        mocked_has_amt.return_value = False
        mocked_conv.return_value = 77700000
        ses.pay.return_value = (fix.PAY, False)
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request=pay_req)
        assert not mocked_err().unsettable.called
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_TX)
        cl_req = {'bolt11': pay_req, 'msatoshi': 77700000, 'maxdelay': 7}
        ses.pay.assert_called_once_with(CTX, cl_req)
        self.assertEqual(
            res.payment_preimage,
            'd628d988a3a33fde1db8c1b800d16a1135ee030e21866ae24ae9269d7cd41632')
        # Missing parameter amount_bits case
        reset_mocks(vars())
        mocked_check_par.side_effect = [None, Exception()]
        request = pb.PayInvoiceRequest(payment_request=pay_req)
        mocked_has_amt.return_value = False
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request=pay_req)
        self.assertEqual(mocked_check_par.call_count, 2)
        assert not mocked_conv.called
        assert not ses.pay.called
        # Missing parameter payment_request case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        assert not ses.pay.called
        # Unsettable parameter amount_bits case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.PayInvoiceRequest(
            payment_request=pay_req, amount_bits=777)
        mocked_has_amt.return_value = True
        mocked_err().unsettable.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request=pay_req)
        mocked_err().unsettable.assert_called_once_with(CTX, 'amount_bits')
        assert not mocked_conv.called
        assert not ses.pay.called
        # Incorrect cltv_expiry_delta case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request=pay_req,
                                       cltv_expiry_delta=65537)
        mocked_check_val.return_value = False
        mocked_err().out_of_range.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        assert not ses.pay.called
        # Error response case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request=pay_req)
        mocked_check_val.return_value = 0
        ses.pay.return_value = (fix.BADRESPONSE, True)
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        ses.pay.assert_called_once_with(CTX, {'bolt11': pay_req})
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)
        self.assertEqual(res, 'not set')

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    @patch(MOD.__name__ + '.Enf.check_value')
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_PayOnChain(self, mocked_check_par, mocked_err, mocked_conv,
                        mocked_check_val, mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # api = 'withdraw'
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
        assert not ses.withdraw.called
        # Correct case
        reset_mocks(vars())
        request = pb.PayOnChainRequest(
            amount_bits=amt, address=fix.ADDRESS, fee_sat_byte=fee_sat_byte)
        mocked_conv.return_value = amt
        mocked_check_val.return_value = True
        ses.withdraw.return_value = (fix.WITHDRAW, False)
        MOD.PayOnChain(request, CTX)
        # Error case
        reset_mocks(vars())
        request = pb.PayOnChainRequest(address=fix.ADDRESS, amount_bits=amt)
        ses.withdraw.return_value = (fix.BADRESPONSE, True)
        with self.assertRaises(Exception):
            res = MOD.PayOnChain(request, CTX)
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '._add_route_hint', autospec=True)
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_DecodeInvoice(self, mocked_check_par, mocked_err, mocked_rpcses,
                           mocked_conv, mocked_add, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        pay_req = 'lntb77u1s'
        # Correct case: simple description, fallback and routes
        request = pb.DecodeInvoiceRequest(
            payment_request=pay_req, description='funny')
        ses.decodepay.return_value = (fix.DECODEPAY, False)
        mocked_conv.return_value = 7
        res = MOD.DecodeInvoice(request, CTX)
        cl_req = {'bolt11': pay_req, 'description': 'funny'}
        ses.decodepay.assert_called_once_with(CTX, cl_req)
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS, 700000)
        assert mocked_add.called
        self.assertEqual(mocked_add.call_count, 2)
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
        ses.decodepay.return_value = (fix.DECODEPAY_HASH, False)
        mocked_conv.return_value = 1.5
        res = MOD.DecodeInvoice(request, CTX)
        ses.decodepay.assert_called_once_with(CTX, cl_req)
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS, 150000)
        assert not mocked_add.called
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
        assert not ses.decodepay.called
        assert not mocked_conv.called
        assert not mocked_add.called
        # Error response case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.DecodeInvoiceRequest(payment_request=pay_req)
        ses.decodepay.return_value = (fix.BADRESPONSE, True)
        res = 'not set'
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(request, CTX)
        ses.decodepay.assert_called_once_with(CTX, {'bolt11': pay_req})
        assert not mocked_conv.called
        assert not mocked_add.called
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)
        self.assertEqual(res, 'not set')

    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_OpenChannel(self, mocked_check_par, mocked_err, mocked_rpcses,
                         mocked_handle, mocked_conv):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        amt = 7
        mocked_err().invalid.side_effect = Exception()
        mocked_err().unimplemented_parameter.side_effect = Exception()
        mocked_err().connect_failed.side_effect = Exception()
        # Filled
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI, push_bits=amt,
            private=True)
        ses.connect.return_value = (fix.CONNECT, False)
        ses.fundchannel.return_value = (fix.FUNDCHANNEL, False)
        MOD.OpenChannel(request, CTX)
        assert not mocked_err().unimplemented_parameter.called
        self.assertEqual(mocked_conv.call_count, 2)
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
        assert not ses.connect.called
        mocked_check_par.side_effect = None
        # Connect failed case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI,
            private=True)
        ses.connect.return_value = ('', True)
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_err().connect_failed.assert_called_once_with(CTX)
        # Error case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI,
            private=True)
        ses.connect.return_value = (fix.CONNECT, False)
        ses.fundchannel.return_value = (fix.BADRESPONSE, True)
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)

    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.get_thread_timeout', autospec=True)
    @patch(MOD.__name__ + '.ThreadPoolExecutor', autospec=True)
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_CloseChannel(self, mocked_check_par, mocked_thread,
                          mocked_thread_time, mocked_handle, mocked_err):
        mocked_err().report_error.side_effect = Exception()
        mocked_thread_time.return_value = 2
        # Unilateral close
        future = Mock()
        executor = Mock()
        future.result.return_value = fix.CLOSE_FORCED
        executor.submit.return_value = future
        mocked_thread.return_value = executor
        request = pb.CloseChannelRequest(channel_id='777', force=True)
        res = MOD.CloseChannel(request, CTX)
        mocked_check_par.assert_called_once_with(CTX, request, 'channel_id')
        self.assertEqual(res.closing_txid, fix.CLOSE_FORCED['txid'])
        # Mutual close
        reset_mocks(vars())
        future.result.return_value = fix.CLOSE_MUTUAL
        executor.submit.return_value = future
        mocked_thread.return_value = executor
        request = pb.CloseChannelRequest(channel_id='777')
        res = MOD.CloseChannel(request, CTX)
        self.assertEqual(res.closing_txid, fix.CLOSE_MUTUAL['txid'])
        # Result times out
        reset_mocks(vars())
        future.result.side_effect = TimeoutFutError()
        res = MOD.CloseChannel(request, CTX)
        executor.shutdown.assert_called_once_with(wait=False)
        self.assertEqual(res, pb.CloseChannelResponse())
        # Result throws RuntimeError
        reset_mocks(vars())
        future.result.side_effect = RuntimeError(fix.BADRESPONSE)
        MOD.CloseChannel(request, CTX)
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)
        # literal_eval throws SyntaxError
        reset_mocks(vars())
        err = 'err'
        future.result.side_effect = RuntimeError(err)
        with self.assertRaises(Exception):
            MOD.CloseChannel(request, CTX)
        assert not mocked_handle.called
        mocked_err().report_error.assert_called_once_with(CTX, err)
        future.result.side_effect = None

    @patch(MOD.__name__ + '.convert', autospec=True)
    def test_add_channel(self, mocked_conv):
        # Add channel case
        response = pb.ListChannelsResponse()
        cl_peer = fix.LISTPEERS['peers'][0]
        cl_chan = cl_peer['channels'][0]
        res = MOD._add_channel(CTX, response, cl_peer, cl_chan, pb.OPEN, False)
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
        # Skip add of inactive channel case
        reset_mocks(vars())
        response = pb.ListChannelsResponse()
        res = MOD._add_channel(
            CTX, response, cl_peer, fix.CHANNEL_AWAITING_LOCKIN,
            pb.PENDING_OPEN, True)
        self.assertEqual(response, pb.ListChannelsResponse())

    @patch(MOD.__name__ + '.convert', autospec=True)
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

    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.ClightningRPC')
    def test_close_channel(self, mocked_rpcses, mocked_log):
        ses = mocked_rpcses.return_value
        cl_req = {'id': 'channel_id'}
        # Correct case
        ses.close.return_value = (fix.CLOSE_MUTUAL, False)
        res = MOD._close_channel(cl_req)
        assert mocked_log.debug.called
        self.assertEqual(res, fix.CLOSE_MUTUAL)
        # Error response case
        reset_mocks(vars())
        ses.close.return_value = (fix.BADRESPONSE, True)
        with self.assertRaises(RuntimeError):
            res = MOD._close_channel(cl_req)
            self.assertEqual(res, None)
        assert mocked_log.debug.called
        # RuntimeError case
        reset_mocks(vars())
        err = 'err'
        ses.close.side_effect = RuntimeError(err)
        with self.assertRaises(RuntimeError):
            res = MOD._close_channel(cl_req)
        assert mocked_log.debug.called

    @patch(MOD.__name__ + '.datetime', autospec=True)
    def test_create_label(self, mocked_datetime):
        mocked_datetime.now().timestamp.return_value = 1533152937.911157
        res = MOD._create_label()
        self.assertEqual(res, '1533152937911157')

    def test_get_channel_state(self):
        res = MOD._get_channel_state(fix.CHANNEL_CLOSED)
        self.assertEqual(res, -1)
        res = MOD._get_channel_state(fix.CHANNEL_RESOLVED)
        self.assertEqual(res, -1)
        res = MOD._get_channel_state(fix.CHANNEL_NORMAL)
        self.assertEqual(res, pb.OPEN)
        res = MOD._get_channel_state(fix.CHANNEL_UNILATERAL)
        self.assertEqual(res, pb.PENDING_FORCE_CLOSE)
        res = MOD._get_channel_state(fix.CHANNEL_SHUTTING_DOWN)
        self.assertEqual(res, pb.PENDING_MUTUAL_CLOSE)
        res = MOD._get_channel_state(fix.CHANNEL_AWAITING_UNILATERAL)
        self.assertEqual(res, pb.PENDING_FORCE_CLOSE)
        res = MOD._get_channel_state(fix.CHANNEL_MUTUAL)
        self.assertEqual(res, pb.PENDING_MUTUAL_CLOSE)
        res = MOD._get_channel_state(fix.CHANNEL_AWAITING_LOCKIN)
        self.assertEqual(res, pb.PENDING_OPEN)
        res = MOD._get_channel_state(fix.CHANNEL_UNKNOWN)
        self.assertEqual(res, pb.UNKNOWN)

    def test_get_invoice_state(self):
        # Correct case: paid invoice
        invoice = fix.LISTINVOICES['invoices'][1]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.PAID)
        # Correct case: unpaid invoice
        reset_mocks(vars())
        invoice = fix.LISTINVOICES['invoices'][3]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.PENDING)
        # Correct case: expired invoice
        reset_mocks(vars())
        invoice = fix.LISTINVOICES['invoices'][2]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.EXPIRED)
        # Invoice with no status case
        reset_mocks(vars())
        invoice = fix.LISTINVOICES['invoices'][0]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.UNKNOWN_INVOICE_STATE)

    @patch(MOD.__name__ + '.Err')
    def test_handle_error(self, mocked_err):
        err_msg = 'clightning error'
        MOD._handle_error(CTX, err_msg)
        mocked_err().report_error.assert_called_once_with(CTX, err_msg)

    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.getattr')
    @patch(MOD.__name__ + '.LightningRpc', autospec=True)
    @patch(MOD.__name__ + '.getLogger', autospec=True)
    def test_ClightningRPC(self, mocked_logger, mocked_lrpc, mocked_getattr,
                           mocked_err):
        mocked_err().node_error.side_effect = Exception()
        logger = mocked_logger.return_value
        # Without data
        rpc_cl = MOD.ClightningRPC()
        mocked_logger.return_value.setLevel.assert_called_once_with(
            MOD.CRITICAL)
        mocked_lrpc.assert_called_once_with(settings.RPC_URL, logger=logger)
        res = rpc_cl.getinfo(CTX)
        self.assertEqual(rpc_cl._session, mocked_lrpc.return_value)
        self.assertEqual(res,
                         (mocked_getattr.return_value.return_value, False))
        mocked_getattr.assert_called_once_with(rpc_cl._session, 'getinfo')
        # With data
        reset_mocks(vars())
        res = rpc_cl.newaddr(CTX, {'addresstype': 'p2sh-segwit'})
        mocked_getattr.assert_called_once_with(rpc_cl._session, 'newaddr')
        mocked_getattr.return_value.assert_called_once_with(
            addresstype='p2sh-segwit')
        self.assertEqual(res,
                         (mocked_getattr.return_value.return_value, False))
        # ClightningRpcError response case
        err_msg = 'error'
        err = MOD.ClightningRpcError(
            'getinfo', 'payload', {'message': err_msg})
        mocked_getattr.side_effect = err
        res = rpc_cl.getinfo(CTX)
        self.assertEqual(res, (err_msg, True))
        # OSError response case
        err = OSError(err_msg)
        mocked_getattr.side_effect = err
        with self.assertRaises(Exception):
            res = rpc_cl.getinfo(CTX)
        mocked_err().node_error.assert_called_once_with(CTX, err_msg)

def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
