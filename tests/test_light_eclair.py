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

from concurrent.futures import TimeoutError as TimeoutFutError
from importlib import import_module
from unittest import TestCase
from unittest.mock import call, Mock, patch

from . import fixtures_eclair as fix, proj_root

CTX = 'context'
Enf = getattr(import_module(proj_root + '.utils.bitcoin'), 'Enforcer')
pb = import_module(proj_root + '.lighter_pb2')
settings = import_module(proj_root + '.settings')

MOD = import_module(proj_root + '.light_eclair')


class LightEclairTests(TestCase):
    """ Tests for light_eclair module """

    @patch(MOD.__name__ + '.set_defaults', autospec=True)
    def test_get_settings(self, mocked_set_def):
        # Correct case
        ecl_host = 'eclair'
        ecl_port = '8080'
        config = Mock()
        config.get.side_effect = [ecl_host, ecl_port]
        MOD.get_settings(config, 'eclair')
        ecl_values = ['ECL_HOST', 'ECL_PORT']
        mocked_set_def.assert_called_once_with(config, ecl_values)
        self.assertEqual(settings.IMPL_SEC_TYPE, 'password')
        self.assertEqual(
            settings.RPC_URL, 'http://{}:{}'.format(ecl_host, ecl_port))

    def test_update_settings(self):
        password = b'password'
        # Correct case
        MOD.update_settings(password)
        self.assertEqual(settings.ECL_PASS, password.decode())

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.EclairRPC')
    def test_GetInfo(self, mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Mainnet case
        reset_mocks(vars())
        ses.getinfo.return_value = (fix.GETINFO_MAINNET, False)
        res = MOD.GetInfo('request', CTX)
        ses.getinfo.assert_called_once_with(CTX)
        self.assertEqual(res.network, 'mainnet')
        # Regtest case
        reset_mocks(vars())
        ses.getinfo.return_value = (fix.GETINFO_UNKNOWN, False)
        res = MOD.GetInfo('request', CTX)
        ses.getinfo.assert_called_once_with(CTX)
        self.assertEqual(res.network, 'regtest')
        # Testnet case
        reset_mocks(vars())
        ses.getinfo.return_value = (fix.GETINFO_TESTNET, False)
        res = MOD.GetInfo('request', CTX)
        ses.getinfo.assert_called_once_with(CTX)
        self.assertEqual(res.network, 'testnet')
        self.assertEqual(res.identity_pubkey, fix.GETINFO_TESTNET['nodeId'])
        self.assertEqual(res.alias, fix.GETINFO_TESTNET['alias'])
        self.assertEqual(res.blockheight, fix.GETINFO_TESTNET['blockHeight'])
        # Error case
        reset_mocks(vars())
        ses.getinfo.return_value = (fix.ERR, True)
        with self.assertRaises(Exception):
            res = MOD.GetInfo('request', CTX)
        mocked_handle.assert_called_once_with(CTX, fix.ERR)

    @patch(MOD.__name__ + '.get_channel_balances', autospec=True)
    @patch(MOD.__name__ + '.ListChannels', autospec=True)
    def test_ChannelBalance(self, mocked_ListChannels, mocked_get_chan_bal):
        mocked_get_chan_bal.return_value = pb.ChannelBalanceResponse()
        res = MOD.ChannelBalance('request', CTX)
        self.assertEqual(res, pb.ChannelBalanceResponse())

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.EclairRPC')
    def test_ListPeers(self, mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Correct case
        ses.peers.return_value = (fix.PEERS, False)
        ses.allnodes.return_value = (fix.ALLNODES, False)
        res = MOD.ListPeers('request', CTX)
        ses.peers.assert_called_once_with(CTX)
        ses.allnodes.assert_called_once_with(CTX)
        self.assertEqual(res.peers[0].pubkey, fix.PEERS[0]['nodeId'])
        # Empty case
        reset_mocks(vars())
        ses.peers.return_value = ([], False)
        res = MOD.ListPeers('request', CTX)
        self.assertEqual(res, pb.ListPeersResponse())
        # peers error case
        reset_mocks(vars())
        ses.peers.return_value = (fix.ERR, True)
        with self.assertRaises(Exception):
            res = MOD.ListPeers('request', CTX)
        mocked_handle.assert_called_once_with(CTX, fix.ERR)
        # allnodes error case (ignoring error)
        reset_mocks(vars())
        ses.peers.return_value = (fix.PEERS, False)
        ses.allnodes.return_value = (fix.ERR, True)
        res = MOD.ListPeers('request', CTX)
        assert not mocked_handle.called

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '._add_channel', autospec=True)
    @patch(MOD.__name__ + '.EclairRPC')
    def test_ListChannels(self, mocked_rpcses, mocked_add, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # List all channels
        reset_mocks(vars())
        ses.channels.return_value = (fix.CHANNELS, False)
        request = pb.ListChannelsRequest(active_only=False)
        res = MOD.ListChannels(request, CTX)
        ses.channels.assert_called_once_with(CTX)
        calls = [
            call(CTX, pb.ListChannelsResponse(), fix.CHANNEL_NORMAL, False),
            call(CTX, pb.ListChannelsResponse(), fix.CHANNEL_WAITING_FUNDING,
                 False)]
        mocked_add.assert_has_calls(calls)
        self.assertEqual(res, pb.ListChannelsResponse())
        # Error case
        reset_mocks(vars())
        ses.channels.return_value = (fix.ERR, True)
        with self.assertRaises(Exception):
            res = MOD.ListChannels('request', CTX)
        ses.channels.assert_called_once_with(CTX)
        mocked_handle.assert_called_once_with(CTX, fix.ERR)
        assert not mocked_add.called

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.EclairRPC')
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '.Err')
    def test_CreateInvoice(self, mocked_err, mocked_conv, mocked_rpcses,
                           mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        mocked_err().unimplemented_parameter.side_effect = Exception()
        desc = 'description'
        amt = 7
        etime = 1
        fba = 'fallback_addr'
        pay_req = fix.CREATEINVOICE['serialized']
        pay_hash = fix.CREATEINVOICE['paymentHash']
        expiry_time = fix.CREATEINVOICE['timestamp'] + \
            fix.CREATEINVOICE['expiry']
        # Correct case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(
            description=desc, amount_bits=amt, expiry_time=etime,
            fallback_addr=fba)
        mocked_conv.return_value = amt
        ses.createinvoice.return_value = (fix.CREATEINVOICE, False)
        res = MOD.CreateInvoice(request, CTX)
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
        req = {'description': desc, 'amountMsat': amt, 'expireIn': etime,
                'fallbackAddress': fba}
        ses.createinvoice.assert_called_once_with(
            CTX, req)
        assert not mocked_handle.called
        self.assertEqual(res.payment_request, pay_req)
        self.assertEqual(res.payment_hash, pay_hash)
        self.assertEqual(res.expires_at, expiry_time)
        # Empty request case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest()
        res = MOD.CreateInvoice(request, CTX)
        assert not mocked_err().unsettable.called
        req = {'description': '', 'expireIn': settings.EXPIRY_TIME}
        ses.createinvoice.assert_called_once_with(
            CTX, req)
        assert not mocked_handle.called
        self.assertEqual(res.payment_request, pay_req)
        self.assertEqual(res.payment_hash, pay_hash)
        self.assertEqual(res.expires_at, expiry_time)
        # Error case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest()
        ses.createinvoice.return_value = (fix.ERR, True)
        with self.assertRaises(Exception):
            res = MOD.CreateInvoice(request, CTX)
        mocked_handle.assert_called_with(CTX, fix.ERR)
        # Unimplemented parameter case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest(min_final_cltv_expiry=7)
        with self.assertRaises(Exception):
            MOD.CreateInvoice(request, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'min_final_cltv_expiry')
        assert not mocked_handle.called

    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '._get_invoice_state', autospec=True)
    @patch(MOD.__name__ + '.EclairRPC')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_CheckInvoice(self, mocked_check_par, mocked_rpcses,
                          mocked_inv_st, mocked_err):
        ses = mocked_rpcses.return_value
        pay_hash = 'payment_hash'
        mocked_err().invalid.side_effect = Exception()
        # Correct case
        mocked_inv_st.return_value = pb.PAID
        request = pb.CheckInvoiceRequest(payment_hash=pay_hash)
        ses.getreceivedinfo.return_value = (fix.GETRECEIVEDINFO_PAID, False)
        res = MOD.CheckInvoice(request, CTX)
        req = {}
        ses.getreceivedinfo.assert_called_once_with(
            CTX, {'paymentHash': pay_hash})
        assert not mocked_err().invalid.called
        self.assertEqual(res.state, pb.PAID)
        self.assertEqual(res.settled, True)
        # Missing parameter case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CheckInvoice(request, CTX)
        mocked_check_par.side_effect = None
        # Error case
        reset_mocks(vars())
        ses.getreceivedinfo.return_value = (fix.ERR, True)
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, CTX)
        mocked_err().invalid.assert_called_once_with(CTX, 'payment_hash')

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.EclairRPC')
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '.has_amount_encoded', autospec=True)
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_PayInvoice(self, mocked_check_par, mocked_err, mocked_has_amt,
                        mocked_conv, mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        mocked_err().unimplemented_parameter.side_effect = Exception()
        mocked_err().invalid.side_effect = Exception()
        mocked_err().unsettable.side_effect = Exception()
        mocked_err().payinvoice_failed.side_effect = Exception()
        mocked_err().payinvoice_pending.side_effect = Exception()
        pay_req = 'payment_request'
        amt = 777
        # Correct case: with amount requested
        req = pb.PayInvoiceRequest(
            payment_request=pay_req, amount_bits=amt)
        mocked_has_amt.return_value = False
        ses.payinvoice.return_value = (fix.PAYINVOICE, False)
        ses.getsentinfo.return_value = (fix.GETSENTINFO_SUCCESS, False)
        res = MOD.PayInvoice(req, CTX)
        mocked_conv.assert_called_once_with(
            CTX, Enf.MSATS, req.amount_bits, enforce=Enf.LN_TX)
        req = {'invoice': pay_req, 'amountMsat': mocked_conv.return_value}
        ses.payinvoice.assert_called_once_with(CTX, req)
        ses.getsentinfo.assert_called_once_with(CTX, {'id': fix.PAYINVOICE})
        self.assertEqual(
            res.payment_preimage, fix.GETSENTINFO_SUCCESS[0]['preimage'])
        # Correct case: no amount requested
        reset_mocks(vars())
        req = pb.PayInvoiceRequest(payment_request=pay_req)
        mocked_has_amt.return_value = False
        res = MOD.PayInvoice(req, CTX)
        ses.payinvoice.assert_called_once_with(CTX, {'invoice': pay_req})
        ses.getsentinfo.assert_called_once_with(CTX, {'id': fix.PAYINVOICE})
        self.assertEqual(
            res.payment_preimage, fix.GETSENTINFO_SUCCESS[0]['preimage'])
        # Missing parameter payment_request case
        reset_mocks(vars())
        req = pb.PayInvoiceRequest()
        mocked_check_par.side_effect = [Exception(), None]
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        mocked_check_par.assert_called_once_with(CTX, req, 'payment_request')
        # Unimplemented parameter case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        request = pb.PayInvoiceRequest(cltv_expiry_delta=7)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'cltv_expiry_delta')
        # Unsettable parameter amount_bits case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(
            payment_request=pay_req, amount_bits=77.7)
        mocked_has_amt.return_value = True
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        mocked_err().unsettable.assert_called_once_with(CTX, 'amount_bits')
        # Missing parameter amount_bits case
        reset_mocks(vars())
        mocked_check_par.side_effect = [None, Exception()]
        request = pb.PayInvoiceRequest(payment_request=pay_req)
        mocked_has_amt.return_value = False
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        self.assertEqual(mocked_check_par.call_count, 2)
        mocked_check_par.side_effect = None
        # Parameter payment_request not valid case
        reset_mocks(vars())
        mocked_has_amt.return_value = False
        ses.payinvoice.return_value = (fix.PAYINVOICE_ERROR, True)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        mocked_err().invalid.assert_called_once_with(CTX, 'payment_request')
        # Payment failed case
        reset_mocks(vars())
        mocked_has_amt.return_value = False
        ses.payinvoice.return_value = (fix.PAYINVOICE, False)
        ses.getsentinfo.return_value = (fix.GETSENTINFO_FAIL, True)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        mocked_err().payinvoice_failed.assert_called_once_with(CTX)
        # Payment pending case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request=pay_req)
        mocked_has_amt.return_value = False
        ses.getsentinfo.return_value = (fix.GETSENTINFO_PENDING, False)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        mocked_err().payinvoice_pending.assert_called_once_with(CTX)
        # getsentinfo error case
        reset_mocks(vars())
        mocked_has_amt.return_value = False
        ses.getsentinfo.return_value = (fix.ERR, True)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        mocked_handle.assert_called_once_with(CTX, fix.ERR)
        # payinvoice error case
        reset_mocks(vars())
        ses.payinvoice.return_value = (fix.ERR, True)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, CTX)
        mocked_handle.assert_called_once_with(CTX, fix.ERR)
        assert not ses.getsentinfo.called

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '._is_description_hash', autospec=True)
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '.EclairRPC')
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_DecodeInvoice(self, mocked_check_par, mocked_err, mocked_rpcses,
                           mocked_conv, mocked_d_hash, mocked_handle):
        cmd = 'parseinvoice'
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        mocked_err().invalid.side_effect = Exception()
        pay_req = 'payment_request'
        # Correct case: with description hash
        req = pb.DecodeInvoiceRequest(payment_request=pay_req)
        ses.parseinvoice.return_value = (fix.PARSEINVOICE_D_HASH, False)
        mocked_conv.return_value = 7.77
        mocked_d_hash.return_value = True
        res = MOD.DecodeInvoice(req, CTX)
        ses.parseinvoice.assert_called_once_with(CTX, {'invoice': pay_req})
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
        req = pb.DecodeInvoiceRequest(payment_request='random')
        ses.parseinvoice.return_value = (fix.PARSEINVOICE, False)
        mocked_conv.return_value = 20000
        res = MOD.DecodeInvoice(req, CTX)
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS,
                                            fix.PARSEINVOICE['amount'])
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
        req = pb.DecodeInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(req, CTX)
        mocked_check_par.assert_called_once_with(CTX, req, 'payment_request')
        # Incorrect invoice case
        reset_mocks(vars())
        mocked_check_par.side_effect = None
        req = pb.DecodeInvoiceRequest(payment_request=pay_req)
        ses.parseinvoice.return_value = ('aa invalid payment request zz', True)
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(req, CTX)
        mocked_err().invalid.assert_called_once_with(CTX, 'payment_request')
        # Error case
        reset_mocks(vars())
        ses.parseinvoice.return_value = (fix.ERR, True)
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(req, CTX)
        mocked_handle.assert_called_once_with(CTX, fix.ERR)

    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.EclairRPC')
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_OpenChannel(self, mocked_check_par, mocked_err, mocked_rpcses,
                         mocked_handle, mocked_conv):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        amt = 7
        mocked_err().invalid.side_effect = Exception()
        mocked_err().connect_failed.side_effect = Exception()
        mocked_handle.side_effect = Exception()
        # Filled
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI, push_bits=77,
            private=True)
        ses.connect.return_value = (fix.CONNECT, False)
        ses.open.return_value = (fix.OPEN, False)
        ses.channel.return_value = (fix.CHANNEL_NORMAL, False)
        res = MOD.OpenChannel(request, CTX)
        self.assertEqual(res.funding_txid,
            '53a2466cc224937a4ef91a69fed27dac24831c53b2a0a64bf484ec587d851543')
        # Error in opening channel case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI)
        ses.open.return_value = (fix.ERR, True)
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_handle.assert_called_once_with(CTX, fix.ERR)
        # Connect failed case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI)
        ses.connect.return_value = (fix.ERR, True)
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_err().connect_failed.assert_called_once_with(CTX)
        # invalid node_uri case
        reset_mocks(vars())
        request = pb.OpenChannelRequest(funding_bits=amt, node_uri='wrong')
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        mocked_err().invalid.assert_called_once_with(CTX, 'node_uri')
        assert not ses.connect.called
        # Missing parameter case
        reset_mocks(vars())
        request = pb.OpenChannelRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.OpenChannel(request, CTX)
        assert not ses.connect.called
        mocked_check_par.side_effect = None
        # Error in retrieving channel info (should not happen)
        reset_mocks(vars())
        request = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODE_URI)
        ses.connect.return_value = (fix.CONNECT, False)
        ses.open.return_value = (fix.ERROR_CHANNEL, False)
        res = MOD.OpenChannel(request, CTX)
        self.assertEqual(res, pb.OpenChannelResponse())

    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.get_thread_timeout', autospec=True)
    @patch(MOD.__name__ + '.get_node_timeout', autospec=True)
    @patch(MOD.__name__ + '.ThreadPoolExecutor', autospec=True)
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_CloseChannel(self, mocked_check_par, mocked_thread,
                          mocked_get_time, mocked_thread_time,
                          mocked_handle, mocked_err):
        mocked_handle.side_effect = Exception()
        mocked_err().report_error.side_effect = Exception()
        mocked_get_time.return_value = 30
        mocked_thread_time.return_value = 2
        txid = 'txid'
        # Correct case
        future = Mock()
        executor = Mock()
        future.result.return_value = txid
        executor.submit.return_value = future
        mocked_thread.return_value = executor
        request = pb.CloseChannelRequest(channel_id='777', force=True)
        ctx = Mock()
        ctx.time_remaining.return_value = 10
        res = MOD.CloseChannel(request, ctx)
        self.assertEqual(res.closing_txid, txid)
        mocked_check_par.assert_called_once_with(ctx, request, 'channel_id')
        # Result times out
        reset_mocks(vars())
        future.result.side_effect = TimeoutFutError()
        res = MOD.CloseChannel(request, ctx)
        executor.shutdown.assert_called_once_with(wait=False)
        self.assertEqual(res, pb.CloseChannelResponse())
        # Result throws RuntimeError
        reset_mocks(vars())
        future.result.side_effect = RuntimeError(fix.BADRESPONSE)
        with self.assertRaises(Exception):
            MOD.CloseChannel(request, ctx)
        mocked_handle.assert_called_once_with(ctx, fix.BADRESPONSE)
        # literal_eval throws SyntaxError
        reset_mocks(vars())
        err = 'err'
        future.result.side_effect = RuntimeError(err)
        with self.assertRaises(Exception):
            MOD.CloseChannel(request, ctx)
        assert not mocked_handle.called
        mocked_err().report_error.assert_called_once_with(ctx, err)
        future.result.side_effect = None

    def test_def(self):
        """
        This method is so simple that it will not be mocked in other tests
        """
        # Correct case
        data = {'key': 'value'}
        res = MOD._def(data, 'key')
        self.assertEqual(res, True)
        # None case
        data = {'key': None}
        res = MOD._def(data, 'key')
        self.assertEqual(res, False)
        # Unexistent key case
        res = MOD._def(data, 'not a key')
        self.assertEqual(res, False)

    def test_is_description_hash(self):
        res = MOD._is_description_hash(fix.PARSEINVOICE_D_HASH['description'])
        self.assertEqual(res, True)
        res = MOD._is_description_hash(fix.PARSEINVOICE['description'])
        self.assertEqual(res, False)

    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '._get_channel_state', autospec=True)
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

    @patch(MOD.__name__ + '.sleep', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.FakeContext', autospec=True)
    @patch(MOD.__name__ + '.EclairRPC')
    @patch(MOD.__name__ + '.time', autospec=True)
    def test_close_channel(self, mocked_time, mocked_rpcses, mocked_ctx,
                           mocked_log, mocked_sleep):
        ses = mocked_rpcses.return_value
        client_time = 1
        time = 1563205664.6555452
        mocked_time.return_value = time
        ecl_req = {'channelId': 'aa7cc'}
        ctx = mocked_ctx.return_value
        # Correct case: mutual close, client_time is not enough
        ses.close.return_value = (fix.CLOSE, False)
        ses.channel.return_value = (fix.CHANNEL_MUTUAL, False)
        res = MOD._close_channel(ecl_req, False, client_time, time + 3)
        assert mocked_log.debug.called
        ses.close.assert_called_once_with(
            ctx, ecl_req, settings.IMPL_MIN_TIMEOUT)
        self.assertEqual(
            res, fix.CHANNEL_MUTUAL['data']['mutualClosePublished'][0]['txid'])
        # Correct case: force close
        reset_mocks(vars())
        client_time = 12
        ses.forceclose.return_value = (fix.FORCECLOSE, False)
        res = MOD._close_channel(ecl_req, True, client_time, time + 3)
        ses.forceclose.assert_called_once_with(
            ctx, ecl_req, client_time - settings.IMPL_MIN_TIMEOUT)
        # Error response case
        reset_mocks(vars())
        ses.close.return_value = (fix.ERR, True)
        with self.assertRaises(RuntimeError):
            res = MOD._close_channel(ecl_req, False, client_time, time + 3)
            self.assertEqual(res, None)
        assert mocked_log.debug.called
        # RuntimeError case
        reset_mocks(vars())
        err = 'err'
        ses.close.side_effect = RuntimeError(err)
        with self.assertRaises(RuntimeError):
            res = MOD._close_channel(ecl_req, False, client_time, time + 3)
        assert mocked_log.debug.called
        ses.close.side_effect = None
        # No data field in first response from channel call
        reset_mocks(vars())
        ses.close.return_value = (fix.CLOSE, False)
        ses.channel.side_effect = \
            [(fix.ERR, True), (fix.CHANNEL_UNILATERAL, False)]
        res = MOD._close_channel(ecl_req, False, client_time, time + 3)
        assert mocked_sleep.called
        self.assertEqual(ses.channel.call_count, 2)
        self.assertEqual(
            res, fix.CHANNEL_UNILATERAL['data']['localCommitPublished']\
                ['commitTx']['txid'])

    def test_get_channel_state(self):
        res = MOD._get_channel_state(fix.CHANNEL_WAITING_FUNDING)
        self.assertEqual(res, pb.PENDING_OPEN)
        res = MOD._get_channel_state(fix.CHANNEL_NORMAL)
        self.assertEqual(res, pb.OPEN)
        res = MOD._get_channel_state(fix.CHANNEL_OFFLINE)
        self.assertEqual(res, pb.OPEN)
        res = MOD._get_channel_state(fix.CHANNEL_UNKNOWN)
        self.assertEqual(res, pb.UNKNOWN)
        res = MOD._get_channel_state(fix.CHANNEL_MUTUAL)
        self.assertEqual(res, pb.PENDING_MUTUAL_CLOSE)
        res = MOD._get_channel_state(fix.CHANNEL_UNILATERAL)
        self.assertEqual(res, pb.PENDING_FORCE_CLOSE)
        res = MOD._get_channel_state(fix.CHANNEL_CLOSED)
        self.assertEqual(res, -1)

    def test_get_invoice_state(self):
        # Correct case: paid invoice
        invoice = fix.GETRECEIVEDINFO_PAID
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.PAID)
        # Correct case: unpaid invoice
        reset_mocks(vars())
        invoice = fix.GETRECEIVEDINFO_PENDING
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.PENDING)
        # Correct case: expired invoice
        reset_mocks(vars())
        invoice = fix.GETRECEIVEDINFO_EXPIRED
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.EXPIRED)
        # Invoice with no status case
        reset_mocks(vars())
        invoice = fix.GETRECEIVEDINFO_UNKNOWN
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.PENDING)

    @patch(MOD.__name__ + '.Err')
    def test_handle_error(self, mocked_err):
        mocked_err().report_error.side_effect = Exception()
        # Key 'failures' in ecl_res
        reset_mocks(vars())
        with self.assertRaises(Exception):
            MOD._handle_error(CTX, fix.BADRESPONSE)
        error = 'unmapped error + extra error'
        mocked_err().report_error.assert_called_once_with(CTX, error)
        # No key 'failures', report_error finds error
        reset_mocks(vars())
        ecl_res = 'strange error'
        with self.assertRaises(Exception):
            MOD._handle_error(CTX, ecl_res)
        mocked_err().report_error.assert_called_once_with(CTX, ecl_res)

    @patch(MOD.__name__ + '.RPCSession.call', autospec=True)
    @patch(MOD.__name__ + '.HTTPBasicAuth', autospec=True)
    def test_EclairRPC(self, mocked_auth, mocked_call):
        settings.ECL_PASS = 'pass'
        # Without data and timeout case
        url = settings.RPC_URL + '/getinfo'
        rpc_ecl = MOD.EclairRPC()
        self.assertEqual(rpc_ecl._auth, mocked_auth.return_value)
        res = rpc_ecl.getinfo(CTX)
        self.assertEqual(res, mocked_call.return_value)
        mocked_call.assert_called_once_with(rpc_ecl, CTX, {}, url, None)
        # With data and timeout case
        reset_mocks(vars())
        url = settings.RPC_URL + '/getreceivedinfo'
        data = {'paymentHash': 'payment_hash'}
        timeout = 7
        res = rpc_ecl.getreceivedinfo(CTX, data, timeout)
        mocked_call.assert_called_once_with(rpc_ecl, CTX, data, url, timeout)
        settings.ECL_PASS = ''


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
