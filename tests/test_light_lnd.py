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
""" Tests for light_lnd module """

from codecs import encode
from concurrent.futures import TimeoutError as TimeoutFutError
from importlib import import_module
from unittest import TestCase
from unittest.mock import call, Mock, mock_open, patch

from grpc import FutureTimeoutError, RpcError

from lighter import rpc_pb2 as ln
from lighter import lighter_pb2 as pb
from lighter import settings
from lighter.light_lnd import LND_LN_TX, LND_PAYREQ
from lighter.utils import Enforcer as Enf
from tests import fixtures_lnd as fix

MOD = import_module('lighter.light_lnd')
CTX = 'context'


class LightLndTests(TestCase):
    """ Tests for light_lnd module """

    @patch('lighter.light_lnd.composite_channel_credentials')
    @patch('lighter.light_lnd.metadata_call_credentials')
    @patch('lighter.light_lnd._metadata_callback')
    @patch('lighter.light_lnd.ssl_channel_credentials')
    def test_update_settings(self, mocked_ssl_chan, mocked_callback,
                             mocked_meta_call, mocked_comp_chan):
        # Correct case: with macaroons
        reset_mocks(vars())
        values = {
            'LND_HOST': 'lnd',
            'LND_PORT': '10009',
            'LND_CERT_DIR': '/path',
            'LND_CERT': 'tls.cert',
        }
        mocked_ssl_chan.return_value = 'cert_creds'
        mocked_meta_call.return_value = 'auth_creds'
        mocked_comp_chan.return_value = 'combined_creds'
        mopen = mock_open(read_data='cert')
        with patch.dict('os.environ', values):
            with patch('lighter.light_lnd.open', mopen):
                MOD.update_settings('mac')
        mopen.assert_called_with('/path/tls.cert', 'rb')
        mopen.return_value.read.assert_called_once_with()
        mocked_ssl_chan.assert_called_with('cert')
        mocked_meta_call.assert_called_with(mocked_callback)
        mocked_comp_chan.assert_called_with('cert_creds', 'auth_creds')
        self.assertEqual(
            settings.LND_ADDR, '{}:{}'.format(values['LND_HOST'],
                                              values['LND_PORT']))
        self.assertEqual(settings.LND_CREDS, 'combined_creds')
        # Correct case: without macaroons
        reset_mocks(vars())
        values = {
            'LND_HOST': 'lnd',
            'LND_PORT': '10009',
            'LND_CERT_DIR': '/path',
            'LND_CERT': 'tls.cert',
        }
        mocked_ssl_chan.return_value = 'cert_creds'
        mopen = mock_open(read_data='cert')
        with patch.dict('os.environ', values):
            with patch('lighter.light_lnd.open', mopen):
                MOD.update_settings(None)
        mopen.assert_called_with('/path/tls.cert', 'rb')
        mopen.return_value.read.assert_called_once_with()
        mocked_ssl_chan.assert_called_with('cert')
        assert not mocked_meta_call.called
        assert not mocked_comp_chan.called
        self.assertEqual(
            settings.LND_ADDR, '{}:{}'.format(values['LND_HOST'],
                                              values['LND_PORT']))
        self.assertEqual(settings.LND_CREDS, 'cert_creds')

    def test_metadata_callback(self):
        settings.LND_MAC = b'macaroon_bytes'
        mac = encode(settings.LND_MAC, 'hex')
        mocked_callback = Mock()
        MOD._metadata_callback(CTX, mocked_callback)
        mocked_callback.assert_called_once_with([('macaroon', mac)], None)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    def test_handle_rpc_errors(self, mocked_handle_err):
        # Correct case
        func = Mock()
        func.return_value = '777'
        wrapped = MOD._handle_rpc_errors(func)
        res = wrapped(3)
        self.assertEqual(res, '777')
        self.assertEqual(func.call_count, 1)
        # Error case
        reset_mocks(vars())
        error = RpcError()
        func.side_effect = error
        wrapped = MOD._handle_rpc_errors(func)
        res = wrapped(3, 'context')
        self.assertEqual(res, None)
        self.assertEqual(func.call_count, 1)
        mocked_handle_err.assert_called_once_with('context', error)

    @patch('lighter.light_lnd.lnrpc.LightningStub', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd.channel_ready_future', autospec=True)
    @patch('lighter.light_lnd.secure_channel', autospec=True)
    def test_connect(self, mocked_secure_chan, mocked_future, mocked_err,
                     mocked_stub):
        settings.LND_ADDR = 'lnd:10009'
        settings.LND_CREDS = 'creds'
        mocked_stub.return_value = 'stub'
        # correct case
        with MOD._connect(CTX) as stub:
            self.assertEqual(stub, 'stub')
        mocked_secure_chan.assert_called_once_with('lnd:10009', 'creds')
        mocked_stub.assert_called_once_with(mocked_secure_chan.return_value)
        mocked_secure_chan.return_value.close.assert_called_once_with()
        # error case
        reset_mocks(vars())
        mocked_future.return_value.result.side_effect = FutureTimeoutError()
        mocked_err().node_error.side_effect = Exception()
        with self.assertRaises(Exception):
            with MOD._connect(CTX) as stub:
                self.assertEqual(stub, 'stub')

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_GetInfo(self, mocked_connect, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Testnet case
        lnd_res = fix.GETINFO_TESTNET
        stub.GetInfo.return_value = lnd_res
        res = MOD.GetInfo('request', CTX)
        stub.GetInfo.assert_called_once_with(
            ln.GetInfoRequest(), timeout=settings.IMPL_TIMEOUT)
        lnd_req = ln.NodeInfoRequest(pub_key='asd')
        assert not mocked_handle.called
        self.assertEqual(res.identity_pubkey, 'asd')
        self.assertEqual(res.network, 'testnet')
        self.assertEqual(res.color, '#DCDCDC')
        # Mainnet case
        reset_mocks(vars())
        lnd_res = fix.GETINFO_MAINNET
        stub.GetInfo.return_value = lnd_res
        res = MOD.GetInfo('request', CTX)
        self.assertEqual(res.identity_pubkey, 'asd')
        self.assertEqual(res.network, 'mainnet')
        stub.GetInfo.assert_called_once_with(
            ln.GetInfoRequest(), timeout=settings.IMPL_TIMEOUT)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_NewAddress(self, mocked_connect, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # P2WKH case
        request = pb.NewAddressRequest(type=pb.P2WKH)
        lnd_res = ln.NewAddressResponse(address='addr')
        stub.NewAddress.return_value = lnd_res
        res = MOD.NewAddress(request, CTX)
        stub.NewAddress.assert_called_once_with(
            ln.NewAddressRequest(), timeout=settings.IMPL_TIMEOUT)
        assert not mocked_handle.called
        self.assertEqual(res.address, 'addr')
        # NP2KWH case
        reset_mocks(vars())
        request = pb.NewAddressRequest(type=pb.NP2WKH)
        lnd_res = ln.NewAddressResponse(address='addr')
        stub.NewAddress.return_value = lnd_res
        res = MOD.NewAddress(request, CTX)
        stub.NewAddress.assert_called_with(
            ln.NewAddressRequest(type=1), timeout=settings.IMPL_TIMEOUT)
        assert not mocked_handle.called
        self.assertEqual(res.address, 'addr')

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_WalletBalance(self, mocked_connect, mocked_conv, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Correct case
        lnd_res = ln.WalletBalanceResponse(total_balance=77700)
        stub.WalletBalance.return_value = lnd_res
        mocked_conv.return_value = 777
        res = MOD.WalletBalance('request', CTX)
        stub.WalletBalance.assert_called_once_with(
            ln.WalletBalanceRequest(), timeout=settings.IMPL_TIMEOUT)
        mocked_conv.assert_called_once_with(CTX, Enf.SATS, 77700)
        assert not mocked_handle.called
        self.assertEqual(res.balance, 777)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_ChannelBalance(self, mocked_connect, mocked_conv, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Correct case
        lnd_res = ln.ChannelBalanceResponse(balance=77700)
        stub.ChannelBalance.return_value = lnd_res
        mocked_conv.return_value = 777
        res = MOD.ChannelBalance('request', CTX)
        stub.ChannelBalance.assert_called_once_with(
            ln.ChannelBalanceRequest(), timeout=settings.IMPL_TIMEOUT)
        mocked_conv.assert_called_once_with(CTX, Enf.SATS, 77700)
        assert not mocked_handle.called
        self.assertEqual(res.balance, 777)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._add_channel', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_ListChannels(self, mocked_connect, mocked_add, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Correct case: request.active_only = False
        request = pb.ListChannelsRequest()
        lnd_res_act = ln.ListChannelsResponse()
        lnd_res_act.channels.add()
        stub.ListChannels.return_value = lnd_res_act
        lnd_res_pen = ln.PendingChannelsResponse()
        lnd_res_pen.pending_open_channels.add()
        lnd_res_pen.pending_closing_channels.add()
        lnd_res_pen.pending_force_closing_channels.add()
        lnd_res_pen.waiting_close_channels.add()
        stub.PendingChannels.return_value = lnd_res_pen
        res = MOD.ListChannels(request, CTX)
        calls = [
            call(
                CTX, pb.ListChannelsResponse(), lnd_res_act.channels[0],
                pb.OPEN, active_only=False, open_chan=True),
            call(CTX, pb.ListChannelsResponse(),
                 lnd_res_pen.pending_open_channels[0].channel,
                 pb.PENDING_OPEN),
            call(CTX, pb.ListChannelsResponse(),
                 lnd_res_pen.pending_closing_channels[0].channel,
                 pb.PENDING_MUTUAL_CLOSE),
            call(CTX, pb.ListChannelsResponse(),
                 lnd_res_pen.pending_force_closing_channels[0].channel,
                 pb.PENDING_FORCE_CLOSE),
            call(CTX, pb.ListChannelsResponse(),
                 lnd_res_pen.waiting_close_channels[0].channel,
                 pb.UNKNOWN)
        ]
        mocked_add.assert_has_calls(calls)
        stub.ListChannels.assert_called_once_with(
            ln.ListChannelsRequest(), timeout=settings.IMPL_TIMEOUT)
        lnd_req = ln.PendingChannelsRequest()
        stub.PendingChannels.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        assert not mocked_handle.called
        self.assertEqual(res, pb.ListChannelsResponse())
        # Correct case: request.active_only = True
        reset_mocks(vars())
        request = pb.ListChannelsRequest(active_only=True)
        lnd_res = ln.ListChannelsResponse()
        lnd_res.channels.add(active=True)
        stub.ListChannels.return_value = lnd_res
        res = MOD.ListChannels(request, CTX)
        stub.ListChannels.assert_called_once_with(
            ln.ListChannelsRequest(), timeout=settings.IMPL_TIMEOUT)
        mocked_add.assert_called_once_with(
            CTX, pb.ListChannelsResponse(), lnd_res.channels[0], pb.OPEN,
            active_only=True, open_chan=True)
        assert not stub.PendingChannels.called
        assert not mocked_handle.called
        self.assertEqual(res, pb.ListChannelsResponse())

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._parse_invoices', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_ListInvoices(self, mocked_connect, mocked_parse, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Correct case: with max_items, search_order 1
        max_invoices = 50
        request = pb.ListInvoicesRequest(max_items=max_invoices, search_order=1)
        lnd_res = fix.get_invoices_response(request)
        stub.ListInvoices.return_value = lnd_res
        mocked_parse.side_effect = [False, True]
        res = MOD.ListInvoices(request, CTX)
        self.assertEqual(request.max_items, max_invoices)
        req = ln.ListInvoiceRequest(
            num_max_invoices=max_invoices * settings.INVOICES_TIMES,
            reversed=True,
            index_offset=1)
        stub.ListInvoices.assert_called_with(req, timeout=settings.IMPL_TIMEOUT)
        self.assertEqual(stub.ListInvoices.call_count, 2)
        assert not mocked_handle.called
        # Correct case: without max_items, search_order 0
        reset_mocks(vars())
        request = pb.ListInvoicesRequest()
        mocked_parse.side_effect = [False, True]
        MOD.ListInvoices(request, CTX)
        self.assertEqual(request.max_items, settings.MAX_INVOICES)
        req = ln.ListInvoiceRequest(
            num_max_invoices=settings.MAX_INVOICES * settings.INVOICES_TIMES,
            index_offset=3)
        stub.ListInvoices.assert_called_with(req, timeout=settings.IMPL_TIMEOUT)
        self.assertEqual(stub.ListInvoices.call_count, 2)
        assert not mocked_handle.called
        # Empty response case
        reset_mocks(vars())
        request = pb.ListInvoicesRequest()
        stub.ListInvoices.return_value = ln.ListInvoiceResponse()
        MOD.ListInvoices(request, CTX)
        assert not mocked_parse.called
        assert not mocked_handle.called

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._add_payment', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_ListPayments(self, mocked_connect, mocked_add, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Correct case
        request = pb.ListPaymentsRequest()
        lnd_res = fix.get_listpayments_response()
        stub.ListPayments.return_value = lnd_res
        res = MOD.ListPayments(request, CTX)
        response = pb.ListPaymentsResponse()
        calls = []
        for lnd_payment in lnd_res.payments:
            calls.append(call(CTX, response, lnd_payment))
        mocked_add.assert_has_calls(calls)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_ListPeers(self, mocked_connect, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Filled case
        lnd_res = ln.ListPeersResponse()
        lnd_res.peers.add(pub_key='pubkey', address='address')
        stub.ListPeers.return_value = lnd_res
        lnd_res = ln.NodeInfo(node=ln.LightningNode(alias='alias'))
        stub.GetNodeInfo.return_value = lnd_res
        res = MOD.ListPeers('request', CTX)
        stub.ListPeers.assert_called_once_with(
            ln.ListPeersRequest(), timeout=settings.IMPL_TIMEOUT)
        assert not mocked_handle.called
        self.assertEqual(res.peers[0].pubkey, 'pubkey')
        self.assertEqual(res.peers[0].address, 'address')
        self.assertEqual(res.peers[0].alias, 'alias')
        assert not mocked_handle.called
        # Empty case
        reset_mocks(vars())
        stub.ListPeers.return_value = pb.ListPeersResponse()
        res = MOD.ListPeers('request', CTX)
        stub.ListPeers.assert_called_once_with(
            ln.ListPeersRequest(), timeout=settings.IMPL_TIMEOUT)
        assert not mocked_handle.called
        self.assertEqual(res, pb.ListPeersResponse())

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._add_transaction', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_ListTransactions(self, mocked_connect, mocked_add, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Correct case
        request = pb.ListTransactionsRequest()
        lnd_res = fix.get_transactions_response()
        stub.GetTransactions.return_value = lnd_res
        res = MOD.ListTransactions(request, CTX)
        response = pb.ListTransactionsResponse()
        calls = []
        for lnd_transaction in lnd_res.transactions:
            calls.append(call(CTX, response, lnd_transaction))
        mocked_add.assert_has_calls(calls)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd.Enf.check_value')
    def test_CreateInvoice(self, mocked_check_val, mocked_err, mocked_connect,
                           mocked_conv, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        amt = 7
        desc = "description"
        fa = "fallback_address"
        exp = 3600
        # Correct case: filled
        request = pb.CreateInvoiceRequest(
            amount_bits=amt, description=desc, expiry_time=exp,
            min_final_cltv_expiry=amt, fallback_addr=fa)
        mocked_check_val.return_value = True
        mocked_conv.return_value = amt
        lnd_res = ln.AddInvoiceResponse(r_hash=b'r_hash')
        stub.AddInvoice.return_value = lnd_res
        lnd_res = ln.Invoice(creation_date=1534971310, expiry=exp)
        stub.LookupInvoice.return_value = lnd_res
        res = MOD.CreateInvoice(request, CTX)
        mocked_conv.assert_called_once_with(
            CTX,
            Enf.SATS,
            amt,
            enforce=LND_PAYREQ,
            max_precision=Enf.SATS)
        req = ln.Invoice(
            memo=desc, expiry=exp, fallback_addr=fa, value=amt, cltv_expiry=amt)
        stub.AddInvoice.assert_called_once_with(
            req, timeout=settings.IMPL_TIMEOUT)
        lnd_req = ln.PaymentHash(r_hash_str='725f68617368')
        stub.LookupInvoice.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        assert not mocked_handle.called
        self.assertEqual(res.payment_hash, '725f68617368')
        self.assertEqual(res.expires_at, 1534974910)
        # Correct case: empty request
        reset_mocks(vars())
        mocked_conv.return_value = None
        mocked_check_val.return_value = True
        request = pb.CreateInvoiceRequest()
        lnd_res = ln.AddInvoiceResponse()
        stub.AddInvoice.return_value = lnd_res
        res = MOD.CreateInvoice(request, CTX)
        assert not mocked_conv.called
        stub.AddInvoice.assert_called_once_with(
            ln.Invoice(), timeout=settings.IMPL_TIMEOUT)
        assert not stub.LookupInvoice.called
        assert not mocked_handle.called
        self.assertEqual(res, pb.CreateInvoiceResponse())
        # min_final_cltv_expiry out of range case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(
            amount_bits=amt, min_final_cltv_expiry=amt)
        mocked_check_val.return_value = False
        mocked_err().out_of_range.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.CreateInvoice(request, CTX)
        assert not mocked_connect.called

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd._connect', autospec=True)
    @patch('lighter.light_lnd.check_req_params', autospec=True)
    def test_CheckInvoice(self, mocked_check_par, mocked_connect, mocked_err,
                          mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Filled case
        request = pb.CheckInvoiceRequest(payment_hash='a_payment_hash')
        lnd_res = ln.Invoice(state=1)
        stub.LookupInvoice.return_value = lnd_res
        res = MOD.CheckInvoice(request, CTX)
        assert not mocked_err().missing_parameter.called
        lnd_req = ln.PaymentHash(r_hash_str='a_payment_hash')
        stub.LookupInvoice.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        assert not mocked_handle.called
        self.assertEqual(res.settled, True)
        # Missing parameter case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CheckInvoice(request, CTX)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd.Enf.check_value')
    @patch('lighter.light_lnd.has_amount_encoded', autospec=True)
    @patch('lighter.light_lnd.check_req_params', autospec=True)
    def test_PayInvoice(self, mocked_check_par, mocked_has_amt,
                        mocked_check_val, mocked_err, mocked_conv,
                        mocked_connect, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Amount in invoice but not in request case
        request = pb.PayInvoiceRequest(
            payment_request='something', cltv_expiry_delta=7)
        mocked_has_amt.return_value = True
        mocked_check_val.return_value = True
        lnd_res = ln.SendResponse(payment_preimage=b'a_payment_preimage')
        stub.SendPaymentSync.return_value = lnd_res
        stub.SendPaymentSync.return_value.payment_error = ''
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        lnd_req = ln.SendRequest(
            payment_request='something', final_cltv_delta=7)
        stub.SendPaymentSync.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        assert not mocked_handle.called
        self.assertEqual(res.payment_preimage,
                         '615f7061796d656e745f707265696d616765')
        # Amount in invoice and in request case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='abc', amount_bits=7)
        mocked_has_amt.return_value = True
        mocked_err().unsettable.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='abc')
        mocked_err().unsettable.assert_called_once_with(
            CTX, 'amount_bits')
        assert not mocked_conv.called
        assert not stub.SendPaymentSync.called
        assert not mocked_handle.called
        # Amount in request and not in invoice case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='abc', amount_bits=7)
        mocked_has_amt.return_value = False
        MOD.PayInvoice(request, CTX)
        mocked_conv.assert_called_once_with(
            CTX,
            Enf.SATS,
            request.amount_bits,
            enforce=LND_LN_TX,
            max_precision=Enf.SATS)
        # Amount neither in request or invoice case
        reset_mocks(vars())
        mocked_check_par.side_effect = [None, Exception()]
        request = pb.PayInvoiceRequest(payment_request='random')
        mocked_has_amt.return_value = False
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='random')
        self.assertEqual(mocked_check_par.call_count, 2)
        assert not mocked_conv.called
        assert not mocked_connect.called
        assert not mocked_handle.called
        # cltv_expiry_delta out of range case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.PayInvoiceRequest(
            payment_request='abc', cltv_expiry_delta=7)
        mocked_check_val.return_value = False
        mocked_err().out_of_range.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.PayInvoice(request, CTX)
        assert not mocked_connect.called
        # Error from lnd_res.payment_error case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='something')
        lnd_res = ln.SendResponse(payment_error='some error')
        stub.SendPaymentSync.return_value = lnd_res
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        lnd_req = ln.SendRequest(payment_request='something')
        stub.SendPaymentSync.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        lnd_req = ln.SendRequest(payment_request='something')
        stub.SendPaymentSync.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        mocked_handle.assert_called_once_with(CTX, 'some error')
        # Empty response case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='something')
        stub.SendPaymentSync.return_value.payment_preimage = b''
        stub.SendPaymentSync.return_value.payment_error = ''
        res = MOD.PayInvoice(request, CTX)
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        lnd_req = ln.SendRequest(payment_request='something')
        stub.SendPaymentSync.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        self.assertEqual(res, pb.PayInvoiceResponse())

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd.Enf.check_value')
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    @patch('lighter.light_lnd.check_req_params', autospec=True)
    def test_PayOnChain(self, mocked_check_par, mocked_connect, mocked_conv,
                        mocked_check_val, mocked_err, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        amt = 7
        # Correct case
        mocked_conv.return_value = amt
        request = pb.PayOnChainRequest(
            address=fix.ADDRESS, amount_bits=amt, fee_sat_byte=1)
        stub.SendCoins.return_value = ln.SendCoinsResponse(txid=fix.TXID)
        mocked_check_val.return_value = True
        MOD.PayOnChain(request, CTX)
        # Missing parameter case
        reset_mocks(vars())
        request = pb.PayOnChainRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.PayOnChain(request, CTX)
        # Incorrect fee_sat_byte case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.PayOnChainRequest(
            address=fix.ADDRESS, amount_bits=amt,
            fee_sat_byte=int(2.1e15 / 220 + 1))
        mocked_check_val.return_value = False
        stub.SendCoins.return_value = ln.SendCoinsResponse()
        MOD.PayOnChain(request, CTX)
        mocked_err().out_of_range.assert_called_once_with(CTX, 'fee_sat_byte')

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._add_route_hint', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd._connect', autospec=True)
    @patch('lighter.light_lnd.check_req_params', autospec=True)
    def test_DecodeInvoice(self, mocked_check_par, mocked_connect, mocked_err,
                           mocked_conv, mocked_add, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        # Filled
        request = pb.DecodeInvoiceRequest(payment_request='pay_req')
        mocked_conv.return_value = 7.77
        lnd_res = ln.PayReq(num_satoshis=777)
        route = lnd_res.route_hints.add()
        route.hop_hints.add(node_id='1_id', cltv_expiry_delta=2)
        route.hop_hints.add(node_id='2_id', cltv_expiry_delta=3)
        # lnd_res.route_hints[0].hop_hints.add(node_id = 'a_node_id')
        stub.DecodePayReq.return_value = lnd_res
        res = MOD.DecodeInvoice(request, CTX)
        mocked_conv.assert_called_once_with(CTX, Enf.SATS,
                                            lnd_res.num_satoshis)
        response = pb.DecodeInvoiceResponse(amount_bits=7.77)
        mocked_add.assert_called_once_with(response,
                                           lnd_res.route_hints[0])
        self.assertEqual(res.amount_bits, 7.77)
        # Missing parameter case
        reset_mocks(vars())
        mocked_check_par.side_effect = Exception()
        request = pb.DecodeInvoiceRequest()
        with self.assertRaises(Exception):
            MOD.DecodeInvoice(request, CTX)
        assert not stub.DecodePayReq.called
        assert not mocked_conv.called
        assert not mocked_add.called
        assert not mocked_handle.called

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd.check_req_params', autospec=True)
    def test_OpenChannel(self, mocked_check_par, mocked_err, mocked_connect,
                         mocked_conv, mocked_handle):
        stub = mocked_connect.return_value.__enter__.return_value
        amt = 7
        # Filled
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI, push_bits=amt,
            private=True)
        lnd_res = ln.ChannelPoint(funding_txid_bytes=fix.TXID_BYTES)
        stub.OpenChannelSync.return_value = lnd_res
        mocked_conv.return_value = amt
        MOD.OpenChannel(request, CTX)
        mocked_connect.assert_called_once_with(CTX)
        peer_address = ln.LightningAddress(
            pubkey=fix.NODE_ID, host='{}:{}'.format(fix.HOST, fix.PORT))
        lnd_req = ln.ConnectPeerRequest(addr=peer_address, perm=True)
        stub.ConnectPeer.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        lnd_req = ln.OpenChannelRequest(
            node_pubkey_string=fix.NODE_ID, local_funding_amount=amt,
            push_sat=amt, private=True)
        stub.OpenChannelSync.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        # already connected peer case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI, push_bits=amt,
            private=True)
        stub.ConnectPeer.side_effect = CalledRpcError()
        mocked_err().connect_failed.side_effect = Exception
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_connect.assert_called_once_with(CTX)
        peer_address = ln.LightningAddress(
            pubkey=fix.NODE_ID, host='{}:{}'.format(fix.HOST, fix.PORT))
        lnd_req = ln.ConnectPeerRequest(addr=peer_address, perm=True)
        stub.ConnectPeer.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        assert not stub.OpenChannelSync.called
        # Filled with peer already connected
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI, push_bits=amt,
            private=True)
        stub.ConnectPeer.side_effect = ConnectRpcError()
        mocked_conv.return_value = amt
        MOD.OpenChannel(request, CTX)
        mocked_connect.assert_called_once_with(CTX)
        peer_address = ln.LightningAddress(
            pubkey=fix.NODE_ID, host='{}:{}'.format(fix.HOST, fix.PORT))
        lnd_req = ln.ConnectPeerRequest(addr=peer_address, perm=True)
        stub.ConnectPeer.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        lnd_req = ln.OpenChannelRequest(
            node_pubkey_string=fix.NODE_ID, local_funding_amount=amt,
            push_sat=amt, private=True)
        stub.OpenChannelSync.assert_called_once_with(
            lnd_req, timeout=settings.IMPL_TIMEOUT)
        # invalid node_uri case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(funding_bits=amt, node_uri='wrong')
        mocked_err().invalid.side_effect = Exception
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_err().invalid.assert_called_once_with(CTX, 'node_uri')
        # Missing parameter case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(funding_bits=amt)
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        assert not stub.ConnectPeer.called
        assert not stub.OpenChannelSync.called
        assert not mocked_conv.called
        assert not mocked_handle.called

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.get_thread_timeout', autospec=True)
    @patch('lighter.light_lnd.get_close_timeout', autospec=True)
    @patch('lighter.light_lnd.ThreadPoolExecutor', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd.check_req_params', autospec=True)
    def test_CloseChannel(self, mocked_check_par, mocked_err, mocked_connect,
                          mocked_thread, mocked_close_time, mocked_thread_time,
                          mocked_handle):
        mocked_err().invalid.side_effect = Exception()
        mocked_close_time.return_value = 30
        mocked_thread_time.return_value = 2
        txid = 'closed'
        # Correct case
        stub = mocked_connect.return_value.__enter__.return_value
        stub.GetChanInfo.return_value = ln.ChannelEdge(chan_point='1rtfm:0')
        future = Mock()
        executor = Mock()
        future.result.return_value = ln.ChannelCloseUpdate(
            closing_txid=txid.encode())
        executor.submit.return_value = future
        mocked_thread.return_value = executor
        request = pb.CloseChannelRequest(channel_id='777')
        ctx = Mock()
        ctx.time_remaining.return_value = 300
        res = MOD.CloseChannel(request, ctx)
        self.assertEqual(res.closing_txid, txid)
        mocked_check_par.assert_called_once_with(ctx, request, 'channel_id')
        # Invalid channel_id case
        reset_mocks(vars())
        bad_request = pb.CloseChannelRequest(channel_id='aa7')
        with self.assertRaises(Exception):
            MOD.CloseChannel(bad_request, ctx)
        mocked_err().invalid.assert_called_once_with(ctx, 'channel_id')
        # Result times out
        reset_mocks(vars())
        future.result.side_effect = TimeoutFutError()
        res = MOD.CloseChannel(request, ctx)
        executor.shutdown.assert_called_once_with(wait=False)
        self.assertEqual(res, pb.CloseChannelResponse())
        # Result throws RuntimeError
        # (could be triggered by _connect in _close_channel)
        reset_mocks(vars())
        err = 'err'
        future.result.side_effect = RuntimeError(err)
        MOD.CloseChannel(request, ctx)
        mocked_handle.assert_called_once_with(ctx, err)
        # Result throws RpcError (could be triggered _close_channel)
        reset_mocks(vars())
        error = RpcError(err)
        future.result.side_effect = error
        MOD.CloseChannel(request, ctx)
        mocked_handle.assert_called_once_with(ctx, error)

    @patch('lighter.light_lnd.LOGGER', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_close_channel(self, mocked_connect, mocked_log):
        stub = mocked_connect.return_value.__enter__.return_value
        pending_update = ln.PendingUpdate(txid=b'txid')
        channel_close_update = ln.ChannelCloseUpdate(closing_txid=b'ctxid')
        stub.CloseChannel.return_value = [
            ln.CloseStatusUpdate(close_pending=pending_update),
            ln.CloseStatusUpdate(chan_close=channel_close_update)
        ]
        chan_point = ln.ChannelPoint(funding_txid_str='txid', output_index=0)
        lnd_req = ln.CloseChannelRequest(channel_point=chan_point)
        res = MOD._close_channel(lnd_req, 15)
        self.assertEqual(mocked_log.debug.call_count, 2)
        self.assertEqual(res, channel_close_update)
        # stub throws RpcError
        reset_mocks(vars())
        stub.CloseChannel.side_effect = CalledRpcError()
        with self.assertRaises(CalledRpcError):
            MOD._close_channel(lnd_req, 15)
        assert mocked_log.debug.called
        # _connect throws RuntimeError
        reset_mocks(vars())
        mocked_connect.side_effect = RuntimeError()
        with self.assertRaises(RuntimeError):
            MOD._close_channel(lnd_req, 15)
        assert not mocked_log.called

    @patch('lighter.light_lnd.convert', autospec=True)
    def test_add_channel(self, mocked_conv):
        # Active: empty
        response = pb.ListChannelsResponse()
        lnd_chan = ln.Channel()
        MOD._add_channel(CTX, response, lnd_chan, pb.OPEN, open_chan=True)
        assert not mocked_conv.called
        self.assertEqual(response, pb.ListChannelsResponse())
        # Active: filled
        reset_mocks(vars())
        lnd_chan = ln.Channel(
            chan_id=123,
            capacity=7777777,
            local_balance=6666666,
            remote_balance=1111111)
        MOD._add_channel(CTX, response, lnd_chan, pb.OPEN, open_chan=True)
        calls = [
            call(CTX, Enf.SATS, lnd_chan.capacity),
            call(CTX, Enf.SATS, lnd_chan.local_balance),
            call(CTX, Enf.SATS, lnd_chan.remote_balance)
        ]
        mocked_conv.assert_has_calls(calls)
        self.assertEqual(response.channels[0].channel_id, '123')
        # Pending: empty
        reset_mocks(vars())
        response = pb.ListChannelsResponse()
        lnd_chan = ln.PendingChannelsResponse.PendingChannel()
        MOD._add_channel(CTX, response, lnd_chan, pb.PENDING_MUTUAL_CLOSE)
        assert not mocked_conv.called
        self.assertEqual(response, pb.ListChannelsResponse())
        # Pending: filled
        reset_mocks(vars())
        lnd_chan = ln.PendingChannelsResponse.PendingChannel(
            remote_node_pub='abc',
            capacity=7777777,
            local_balance=6666666,
            remote_balance=1111111)
        MOD._add_channel(CTX, response, lnd_chan, pb.PENDING_MUTUAL_CLOSE)
        calls = [
            call(CTX, Enf.SATS, lnd_chan.capacity),
            call(CTX, Enf.SATS, lnd_chan.local_balance),
            call(CTX, Enf.SATS, lnd_chan.remote_balance)
        ]
        mocked_conv.assert_has_calls(calls)
        self.assertEqual(response.channels[0].remote_pubkey, 'abc')
        # Skip add of inactive channel case
        reset_mocks(vars())
        response = pb.ListChannelsResponse()
        lnd_chan = ln.Channel(
            chan_id=123,
            capacity=7777777,
            local_balance=6666666,
            remote_balance=1111111,
            active=False)
        MOD._add_channel(CTX, response, lnd_chan, pb.OPEN, True)
        self.assertEqual(response, pb.ListChannelsResponse())

    def test_check_timestamp(self):
        # list_order 1, search_order 1: search_timestamp lower than creation_date
        request = pb.ListInvoicesRequest(
            search_timestamp=fix.NOW - 1, list_order=1, search_order=1)
        lnd_invoice = ln.Invoice(creation_date=fix.NOW)
        res = MOD._check_timestamp(request, lnd_invoice)
        self.assertEqual(res, True)
        # list_order 1, search_order 1: search_timestamp higher than creation_date
        request = pb.ListInvoicesRequest(
            search_timestamp=fix.NOW + 1, list_order=1, search_order=1)
        lnd_invoice = ln.Invoice(creation_date=fix.NOW)
        res = MOD._check_timestamp(request, lnd_invoice)
        self.assertEqual(res, False)
        # list_order 1, search_order 0: search_timestamp lower than creation_date
        request = pb.ListInvoicesRequest(
            search_timestamp=fix.NOW - 1, list_order=1, search_order=0)
        lnd_invoice = ln.Invoice(creation_date=fix.NOW)
        res = MOD._check_timestamp(request, lnd_invoice)
        self.assertEqual(res, False)
        # list_order 1, search_order 0: search_timestamp higher than creation_date
        request = pb.ListInvoicesRequest(
            search_timestamp=fix.NOW + 1, list_order=1, search_order=0)
        lnd_invoice = ln.Invoice(creation_date=fix.NOW)
        res = MOD._check_timestamp(request, lnd_invoice)
        self.assertEqual(res, True)
        # list_order 0, search_order 1: search_timestamp lower than creation_date
        request = pb.ListInvoicesRequest(
            search_timestamp=fix.NOW - 1, list_order=0, search_order=1)
        lnd_invoice = ln.Invoice(creation_date=fix.NOW)
        res = MOD._check_timestamp(request, lnd_invoice)
        self.assertEqual(res, True)
        # list_order 0, search_order 1: search_timestamp higher than creation_date
        request = pb.ListInvoicesRequest(
            search_timestamp=fix.NOW + 1, list_order=0, search_order=1)
        lnd_invoice = ln.Invoice(creation_date=fix.NOW)
        res = MOD._check_timestamp(request, lnd_invoice)
        self.assertEqual(res, False)
        # list_order 0, search_order 0: search_timestamp lower than creation_date
        request = pb.ListInvoicesRequest(
            search_timestamp=fix.NOW - 1, list_order=0, search_order=0)
        lnd_invoice = ln.Invoice(creation_date=fix.NOW)
        res = MOD._check_timestamp(request, lnd_invoice)
        self.assertEqual(res, False)
        # list_order 0, search_order 0: search_timestamp higher than creation_date
        request = pb.ListInvoicesRequest(
            search_timestamp=fix.NOW + 1, list_order=0, search_order=0)
        lnd_invoice = ln.Invoice(creation_date=fix.NOW)
        res = MOD._check_timestamp(request, lnd_invoice)
        self.assertEqual(res, True)
        # Empty request
        request = pb.ListInvoicesRequest()
        res = MOD._check_timestamp(request, 'lnd_invoice')
        self.assertEqual(res, False)

    @patch('lighter.light_lnd._add_invoice', autospec=True)
    @patch('lighter.light_lnd._check_timestamp', autospec=True)
    @patch('lighter.light_lnd.datetime', autospec=True)
    def test_parse_invoices(self, mocked_datetime, mocked_check, mocked_add):
        mocked_datetime.now().timestamp.return_value = fix.NOW
        # Correct case: every state is requested
        response = pb.ListInvoicesResponse()
        invoices = fix.INVOICES
        mocked_check.side_effect = [False] * len(invoices)
        request = pb.ListInvoicesRequest(
            paid=True, pending=True, expired=True, max_items=10)
        res = MOD._parse_invoices(CTX, response, invoices, request)
        self.assertEqual(res, False)
        self.assertEqual(mocked_add.call_count, len(invoices))
        # Correct case: no state is requested, should return an empty response
        reset_mocks(vars())
        response = pb.ListInvoicesResponse()
        request = pb.ListInvoicesRequest(paid=True, pending=True, expired=True)
        mocked_check.side_effect = [False] * len(invoices)
        res = MOD._parse_invoices(CTX, response, invoices, request)
        self.assertEqual(res, True)
        # _check_timestamp true
        reset_mocks(vars())
        mocked_check.side_effect = [True] * len(invoices)
        res = MOD._parse_invoices(CTX, response, invoices, request)
        self.assertEqual(mocked_check.call_count, len(invoices))
        self.assertEqual(mocked_add.call_count, 0)
        self.assertEqual(res, False)

    @patch('lighter.light_lnd._add_route_hint', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    def test_add_invoice(self, mocked_conv, mocked_add):
        amt = 7
        # Correct case
        response = pb.ListInvoicesResponse()
        MOD._add_invoice(CTX, response, fix.INVOICE, 2)
        mocked_conv.assert_called_once_with(CTX, Enf.SATS,
                                            fix.INVOICE.value)
        calls = []
        for invoice in response.invoices:
            for route in fix.INVOICE.route_hints:
                calls.append(call(invoice, route))
        mocked_add.assert_has_calls(calls)
        self.assertEqual(response.invoices[0].description, fix.INVOICE.memo)
        # Empty invoice
        reset_mocks(vars())
        response = pb.ListInvoicesResponse()
        invoice = ln.Invoice()
        MOD._add_invoice(CTX, response, invoice, 2)
        assert not mocked_conv.called

    @patch('lighter.light_lnd.convert', autospec=True)
    def test_add_payment(self, mocked_conv):
        # Correct case
        response = pb.ListPaymentsResponse()
        MOD._add_payment(CTX, response, fix.PAYMENT)
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS,
                                            fix.PAYMENT.value_msat)
        self.assertEqual(response.payments[0].payment_hash,
                         fix.PAYMENT.payment_hash)
        # Empty payment
        reset_mocks(vars())
        response = pb.ListPaymentsResponse()
        payment = ln.Payment()
        MOD._add_payment(CTX, response, payment)
        assert not mocked_conv.called

    @patch('lighter.light_lnd.convert', autospec=True)
    def test_add_transaction(self, mocked_conv):
        # Correct case
        response = pb.ListTransactionsResponse()
        MOD._add_transaction(CTX, response, fix.TRANSACTION)
        mocked_conv.assert_called_once_with(CTX, Enf.SATS,
                                            fix.TRANSACTION.amount)
        self.assertEqual(response.transactions[0].txid,
                         fix.TRANSACTION.tx_hash)
        self.assertEqual(response.transactions[0].dest_addresses[1],
                         fix.TRANSACTION.dest_addresses[1])
        # Empty payment
        reset_mocks(vars())
        response = pb.ListTransactionsResponse()
        transaction = ln.Transaction()
        MOD._add_payment(CTX, response, transaction)
        assert not mocked_conv.called

    def test_add_route_hint(self):
        response = pb.DecodeInvoiceResponse()
        lnd_route = ln.RouteHint()
        # Empty
        MOD._add_route_hint(response, lnd_route)
        self.assertEqual(response, pb.DecodeInvoiceResponse())
        # Filled
        reset_mocks(vars())
        lnd_route.hop_hints.add(node_id='id', fee_base_msat=77)
        MOD._add_route_hint(response, lnd_route)
        self.assertEqual(response.route_hints[0].hop_hints[0].pubkey, 'id')

    @patch('lighter.light_lnd.Err')
    def test_handle_error(self, mocked_err):
        # Error string
        MOD._handle_error(CTX, 'an error')
        mocked_err().report_error.assert_called_with(CTX, 'an error')
        # RPC invocation: error object has details method
        reset_mocks(vars())
        error = CalledRpcError()
        MOD._handle_error(CTX, error)
        mocked_err().report_error.assert_called_with(CTX, error.details())
        # Error doesn't have the details method and is not a string
        reset_mocks(vars())
        error = RpcError()
        MOD._handle_error(CTX, error)
        mocked_err().report_error.assert_called_with(
            CTX, 'Could not decode error message')


class CalledRpcError(RpcError):
    def details(self):
        return 'no error message'


class ConnectRpcError(RpcError):
    def details(self):
        return 'already connected to peer'


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
