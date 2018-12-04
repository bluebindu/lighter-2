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
from importlib import import_module
from unittest import TestCase
from unittest.mock import call, Mock, mock_open, patch

from grpc import RpcError

from lighter import rpc_pb2 as ln
from lighter import lighter_pb2 as pb
from lighter import light_lnd, settings
from lighter.light_lnd import ERRORS, LND_LN_TX, LND_PAYREQ
from lighter.utils import Enforcer as Enf

MOD = import_module('lighter.light_lnd')


class LightLndTests(TestCase):
    """ Tests for light_lnd module """

    @patch('lighter.light_lnd.grpc.composite_channel_credentials')
    @patch('lighter.light_lnd.grpc.metadata_call_credentials')
    @patch('lighter.light_lnd._metadata_callback')
    @patch('lighter.light_lnd.grpc.ssl_channel_credentials')
    def test_update_settings(self, mocked_ssl_chan, mocked_callback,
                             mocked_meta_call, mocked_comp_chan):
        # Correct case: with macaroons
        reset_mocks(vars())
        values = {
            'LND_HOST': 'lnd',
            'LND_PORT': '10009',
            'LND_CERT_DIR': '/path',
            'LND_CERT': 'tls.cert',
            'LND_MACAROON_DIR': '/macaroon/path',
            'LND_MACAROON': 'admin.macaroon'
        }
        mocked_ssl_chan.return_value = 'cert_creds'
        mocked_meta_call.return_value = 'auth_creds'
        mocked_comp_chan.return_value = 'combined_creds'
        mopen = mock_open(read_data='cert')
        with patch.dict('os.environ', values):
            with patch('lighter.light_lnd.open', mopen):
                MOD.update_settings()
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
            'LND_MACAROON_DIR': ''
        }
        mocked_ssl_chan.return_value = 'cert_creds'
        mopen = mock_open(read_data='cert')
        with patch.dict('os.environ', values):
            with patch('lighter.light_lnd.open', mopen):
                MOD.update_settings()
        mopen.assert_called_with('/path/tls.cert', 'rb')
        mopen.return_value.read.assert_called_once_with()
        mocked_ssl_chan.assert_called_with('cert')
        assert not mocked_meta_call.called
        assert not mocked_comp_chan.called
        self.assertEqual(
            settings.LND_ADDR, '{}:{}'.format(values['LND_HOST'],
                                              values['LND_PORT']))
        self.assertEqual(settings.LND_CREDS, 'cert_creds')
        # Error case: missing variable
        reset_mocks(vars())
        settings.LND_ADDR = ''
        settings.LND_CREDS = ''
        values = {}
        with patch.dict('os.environ', values):
            with self.assertRaises(KeyError):
                MOD.update_settings()
        assert not mocked_ssl_chan.called
        assert not mocked_meta_call.called
        assert not mocked_comp_chan.called
        self.assertEqual(settings.LND_ADDR, '')
        self.assertEqual(settings.LND_CREDS, '')

    def test_metadata_callback(self):
        mac_bytes = b'macaroon_bytes'
        mac = encode(mac_bytes, 'hex')
        mopen = mock_open(read_data=mac_bytes)
        mocked_callback = Mock()
        values = {'LND_MACAROON': 'macaroon', 'LND_MACAROON_DIR': '/path'}
        with patch.dict('os.environ', values):
            with patch('lighter.light_lnd.open', mopen):
                MOD._metadata_callback('context', mocked_callback)
        mopen.assert_called_once_with('/path/macaroon', 'rb')
        mopen.return_value.read.assert_called_once_with()
        mocked_callback.assert_called_once_with([('macaroon', mac)], None)

    @patch('lighter.light_lnd.lnrpc.LightningStub', autospec=True)
    @patch('lighter.light_lnd.grpc.secure_channel', autospec=True)
    def test_connect(self, mocked_secure_chan, mocked_stub):
        settings.LND_ADDR = 'lnd:10009'
        settings.LND_CREDS = 'creds'
        mocked_stub.return_value = 'stub'
        with MOD._connect() as stub:
            self.assertEqual(stub, 'stub')
        mocked_secure_chan.assert_called_once_with('lnd:10009', 'creds')
        mocked_stub.assert_called_once_with(mocked_secure_chan.return_value)
        mocked_secure_chan.return_value.close.assert_called_once_with()

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_GetInfo(self, mocked_connect, mocked_report):
        stub = mocked_connect.return_value.__enter__.return_value
        # Testnet case
        lnd_res = ln.GetInfoResponse(identity_pubkey='asd', testnet=True)
        stub.GetInfo.return_value = lnd_res
        node = ln.LightningNode(color='#DCDCDC')
        stub.GetNodeInfo.return_value = ln.NodeInfo(node=node)
        res = MOD.GetInfo('request', 'context')
        stub.GetInfo.assert_called_once_with(ln.GetInfoRequest())
        lnd_req = ln.NodeInfoRequest(pub_key='asd')
        stub.GetNodeInfo.assert_called_once_with(lnd_req)
        assert not mocked_report.called
        self.assertEqual(res.identity_pubkey, 'asd')
        self.assertEqual(res.network, 'testnet')
        self.assertEqual(res.color, '#DCDCDC')
        # Mainnet case
        reset_mocks(vars())
        lnd_res = ln.GetInfoResponse(identity_pubkey='asd', testnet=False)
        stub.GetInfo.return_value = lnd_res
        node = ln.LightningNode(color='#DCDCDC')
        stub.GetNodeInfo.return_value = ln.NodeInfo(node=node)
        res = MOD.GetInfo('request', 'context')
        self.assertEqual(res.identity_pubkey, 'asd')
        self.assertEqual(res.network, 'mainnet')
        self.assertEqual(res.color, '#DCDCDC')
        stub.GetInfo.assert_called_once_with(ln.GetInfoRequest())
        lnd_req = ln.NodeInfoRequest(pub_key='asd')
        stub.GetNodeInfo.assert_called_once_with(lnd_req)
        # Error case
        reset_mocks(vars())
        error = RpcError()
        stub.GetInfo.side_effect = error
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.GetInfo('request', 'context')
        stub.GetInfo.assert_called_once_with(ln.GetInfoRequest())
        assert not stub.GetNodeInfo.called
        mocked_report.assert_called_once_with('context', error)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_NewAddress(self, mocked_connect, mocked_report):
        stub = mocked_connect.return_value.__enter__.return_value
        # P2WKH case
        request = pb.NewAddressRequest(type=pb.P2WKH)
        lnd_res = ln.NewAddressResponse(address='addr')
        stub.NewAddress.return_value = lnd_res
        res = MOD.NewAddress(request, 'context')
        stub.NewAddress.assert_called_once_with(ln.NewAddressRequest(type=0))
        assert not mocked_report.called
        self.assertEqual(res.address, 'addr')
        # NP2KWH case
        reset_mocks(vars())
        request = pb.NewAddressRequest(type=pb.NP2WKH)
        lnd_res = ln.NewAddressResponse(address='addr')
        stub.NewAddress.return_value = lnd_res
        res = MOD.NewAddress(request, 'context')
        stub.NewAddress.assert_called_with(ln.NewAddressRequest(type=1))
        assert not mocked_report.called
        self.assertEqual(res.address, 'addr')
        # Error case
        reset_mocks(vars())
        request = pb.NewAddressRequest(type=pb.P2WKH)
        lnd_res = ln.NewAddressResponse(address='addr')
        error = RpcError()
        stub.NewAddress.side_effect = error
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.NewAddress(request, 'context')
        stub.NewAddress.assert_called_once_with(ln.NewAddressRequest(type=0))
        mocked_report.assert_called_once_with('context', error)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_WalletBalance(self, mocked_connect, mocked_conv, mocked_report):
        stub = mocked_connect.return_value.__enter__.return_value
        # Correct case
        lnd_res = ln.WalletBalanceResponse(total_balance=77700)
        stub.WalletBalance.return_value = lnd_res
        mocked_conv.return_value = 777
        res = MOD.WalletBalance('request', 'context')
        stub.WalletBalance.assert_called_once_with(ln.WalletBalanceRequest())
        mocked_conv.assert_called_once_with('context', Enf.SATS, 77700)
        assert not mocked_report.called
        self.assertEqual(res.balance, 777)
        # Error case
        reset_mocks(vars())
        error = RpcError()
        stub.WalletBalance.side_effect = error
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.WalletBalance('request', 'context')
        stub.WalletBalance.assert_called_once_with(ln.WalletBalanceRequest())
        assert not mocked_conv.called
        mocked_report.assert_called_once_with('context', error)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_ChannelBalance(self, mocked_connect, mocked_conv, mocked_report):
        stub = mocked_connect.return_value.__enter__.return_value
        # Correct case
        lnd_res = ln.ChannelBalanceResponse(balance=77700)
        stub.ChannelBalance.return_value = lnd_res
        mocked_conv.return_value = 777
        res = MOD.ChannelBalance('request', 'context')
        stub.ChannelBalance.assert_called_once_with(ln.ChannelBalanceRequest())
        mocked_conv.assert_called_once_with('context', Enf.SATS, 77700)
        assert not mocked_report.called
        self.assertEqual(res.balance, 777)
        # Error case
        reset_mocks(vars())
        error = RpcError()
        stub.ChannelBalance.side_effect = error
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.ChannelBalance('request', 'context')
        stub.ChannelBalance.assert_called_once_with(ln.ChannelBalanceRequest())
        assert not mocked_conv.called
        mocked_report.assert_called_once_with('context', error)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_ListPeers(self, mocked_connect, mocked_report):
        stub = mocked_connect.return_value.__enter__.return_value
        # Filled case
        lnd_res = ln.ListPeersResponse()
        lnd_res.peers.add(pub_key='pubkey', address='address')
        stub.ListPeers.return_value = lnd_res
        res = MOD.ListPeers('request', 'context')
        stub.ListPeers.assert_called_once_with(ln.ListPeersRequest())
        assert not mocked_report.called
        self.assertEqual(res.peers[0].pubkey, 'pubkey')
        self.assertEqual(res.peers[0].address, 'address')
        assert not mocked_report.called
        # Empty case
        reset_mocks(vars())
        stub.ListPeers.return_value = pb.ListPeersResponse()
        res = MOD.ListPeers('request', 'context')
        stub.ListPeers.assert_called_once_with(ln.ListPeersRequest())
        assert not mocked_report.called
        self.assertEqual(res, pb.ListPeersResponse())
        # Error case
        reset_mocks(vars())
        error = RpcError()
        stub.ListPeers.side_effect = error
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.ListPeers('request', 'context')
        stub.ListPeers.assert_called_once_with(ln.ListPeersRequest())
        mocked_report.assert_called_once_with('context', error)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._add_channel', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_ListChannels(self, mocked_connect, mocked_add, mocked_report):
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
        res = MOD.ListChannels(request, 'context')
        calls = [
            call(
                'context',
                pb.ListChannelsResponse(),
                lnd_res_act.channels[0],
                active=True),
            call('context', pb.ListChannelsResponse(),
                 lnd_res_pen.pending_open_channels[0].channel),
            call('context', pb.ListChannelsResponse(),
                 lnd_res_pen.pending_closing_channels[0].channel),
            call('context', pb.ListChannelsResponse(),
                 lnd_res_pen.pending_force_closing_channels[0].channel),
            call('context', pb.ListChannelsResponse(),
                 lnd_res_pen.waiting_close_channels[0].channel)
        ]
        mocked_add.assert_has_calls(calls)
        stub.ListChannels.assert_called_once_with(ln.ListChannelsRequest())
        lnd_req = ln.PendingChannelsRequest()
        stub.PendingChannels.assert_called_once_with(lnd_req)
        assert not mocked_report.called
        self.assertEqual(res, pb.ListChannelsResponse())
        # Correct case: request.active_only = True
        reset_mocks(vars())
        request = pb.ListChannelsRequest(active_only=True)
        lnd_res = ln.ListChannelsResponse()
        lnd_res.channels.add()
        stub.ListChannels.return_value = lnd_res
        res = MOD.ListChannels(request, 'context')
        stub.ListChannels.assert_called_once_with(ln.ListChannelsRequest())
        mocked_add.assert_called_once_with(
            'context',
            pb.ListChannelsResponse(),
            lnd_res.channels[0],
            active=True)
        assert not stub.PendingChannels.called
        assert not mocked_report.called
        self.assertEqual(res, pb.ListChannelsResponse())
        # Error case
        reset_mocks(vars())
        error = RpcError()
        stub.ListChannels.side_effect = error
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.ListChannels('request', 'context')
        mocked_connect.assert_called_with()
        stub.ListChannels.assert_called_once_with(ln.ListChannelsRequest())
        assert not mocked_add.called
        assert not stub.PendingChannels.called
        mocked_report.assert_called_once_with('context', error)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_CreateInvoice(self, mocked_connect, mocked_conv, mocked_report):
        stub = mocked_connect.return_value.__enter__.return_value
        # Correct case: filled
        request = pb.CreateInvoiceRequest(amount_bits=7.77)
        lnd_res = ln.AddInvoiceResponse(r_hash=b'r_hash')
        stub.AddInvoice.return_value = lnd_res
        lnd_res = ln.Invoice(creation_date=1534971310, expiry=3600)
        stub.LookupInvoice.return_value = lnd_res
        mocked_conv.return_value = 777
        res = MOD.CreateInvoice(request, 'context')
        mocked_conv.assert_called_once_with(
            'context',
            Enf.SATS,
            7.77,
            enforce=LND_PAYREQ,
            max_precision=Enf.SATS)
        stub.AddInvoice.assert_called_once_with(ln.Invoice(value=777))
        lnd_req = ln.PaymentHash(r_hash_str='725f68617368')
        stub.LookupInvoice.assert_called_once_with(lnd_req)
        assert not mocked_report.called
        self.assertEqual(res.payment_hash, '725f68617368')
        self.assertEqual(res.expires_at, 1534974910)
        # Correct case: empty request
        reset_mocks(vars())
        mocked_conv.return_value = None
        request = pb.CreateInvoiceRequest()
        lnd_res = ln.AddInvoiceResponse()
        stub.AddInvoice.return_value = lnd_res
        res = MOD.CreateInvoice(request, 'context')
        assert not mocked_conv.called
        stub.AddInvoice.assert_called_once_with(ln.Invoice())
        assert not stub.LookupInvoice.called
        assert not mocked_report.called
        self.assertEqual(res, pb.CreateInvoiceResponse())
        # Error case
        reset_mocks(vars())
        request = pb.CreateInvoiceRequest()
        error = RpcError()
        stub.AddInvoice.side_effect = error
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CreateInvoice(request, 'context')
        assert not mocked_conv.called
        stub.AddInvoice.assert_called_once_with(ln.Invoice())
        assert not stub.LookupInvoice.called
        mocked_report.assert_called_once_with('context', error)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_CheckInvoice(self, mocked_connect, mocked_err, mocked_report):
        stub = mocked_connect.return_value.__enter__.return_value
        # Filled case
        request = pb.CheckInvoiceRequest(payment_hash='a_payment_hash')
        lnd_res = ln.Invoice(settled=True)
        stub.LookupInvoice.return_value = lnd_res
        res = MOD.CheckInvoice(request, 'context')
        assert not mocked_err().missing_parameter.called
        lnd_req = ln.PaymentHash(r_hash_str='a_payment_hash')
        stub.LookupInvoice.assert_called_once_with(lnd_req)
        assert not mocked_report.called
        self.assertEqual(res.settled, True)
        # Missing parameter payment_hash case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest()
        mocked_err.return_value.missing_parameter.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CheckInvoice(request, 'context')
        mocked_err().missing_parameter.assert_called_once_with(
            'context', 'payment_hash')
        # Error case
        reset_mocks(vars())
        request = pb.CheckInvoiceRequest(payment_hash='a_payment_hash')
        error = RpcError()
        stub.LookupInvoice.side_effect = error
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.CheckInvoice(request, 'context')
        lnd_req = ln.PaymentHash(r_hash_str='a_payment_hash')
        stub.LookupInvoice.assert_called_once_with(lnd_req)
        mocked_report.assert_called_once_with('context', error)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._connect', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd.Enf.check_value')
    @patch('lighter.light_lnd.DecodeInvoice', autospec=True)
    def test_PayInvoice(self, mocked_decode, mocked_check_val, mocked_err,
                        mocked_conv, mocked_connect, mocked_report):
        stub = mocked_connect.return_value.__enter__.return_value
        # Amount in invoice but not in request case
        request = pb.PayInvoiceRequest(payment_request='something')
        mocked_decode.return_value = pb.DecodeInvoiceResponse(amount_bits=9)
        mocked_check_val.return_value = 0
        lnd_res = ln.SendResponse(payment_preimage=b'a_payment_preimage')
        stub.SendPaymentSync.return_value = lnd_res
        stub.SendPaymentSync.return_value.payment_error = ''
        res = MOD.PayInvoice(request, 'context')
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        mocked_decode.assert_called_once_with(dec_req, 'context')
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        lnd_req = ln.SendRequest(payment_request='something')
        stub.SendPaymentSync.assert_called_once_with(lnd_req)
        assert not mocked_report.called
        self.assertEqual(res.payment_preimage,
                         '615f7061796d656e745f707265696d616765')
        # Amount in invoice and in request case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='abc', amount_bits=7)
        mocked_decode.return_value = pb.DecodeInvoiceResponse(amount_bits=9)
        mocked_err.return_value.unsettable.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, 'context')
        dec_req = pb.DecodeInvoiceRequest(payment_request='abc')
        mocked_decode.assert_called_once_with(dec_req, 'context')
        mocked_err().unsettable.assert_called_once_with(
            'context', 'amount_bits')
        assert not mocked_conv.called
        assert not stub.SendPaymentSync.called
        assert not mocked_report.called
        # Amount in request and not in invoice case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='abc', amount_bits=7)
        mocked_decode.return_value = pb.DecodeInvoiceResponse()
        MOD.PayInvoice(request, 'context')
        mocked_conv.assert_called_once_with(
            'context',
            Enf.SATS,
            request.amount_bits,
            enforce=LND_LN_TX,
            max_precision=Enf.SATS)
        # Error from lnd_res.payment_error case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='something')
        lnd_res = ln.SendResponse(payment_error='some error')
        stub.SendPaymentSync.return_value = lnd_res
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(request, 'context')
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        mocked_decode.assert_called_once_with(dec_req, 'context')
        lnd_req = ln.SendRequest(payment_request='something')
        stub.SendPaymentSync.assert_called_once_with(lnd_req)
        assert not mocked_err().unsettable.called
        assert not mocked_conv.called
        lnd_req = ln.SendRequest(payment_request='something')
        stub.SendPaymentSync.assert_called_once_with(lnd_req)
        mocked_report.assert_called_once_with('context', 'some error')
        # Empty response case
        reset_mocks(vars())
        request = pb.PayInvoiceRequest(payment_request='something')
        stub.SendPaymentSync.return_value.payment_preimage = b''
        stub.SendPaymentSync.return_value.payment_error = ''
        res = MOD.PayInvoice(request, 'context')
        dec_req = pb.DecodeInvoiceRequest(payment_request='something')
        mocked_decode.assert_called_once_with(dec_req, 'context')
        lnd_req = ln.SendRequest(payment_request='something')
        stub.SendPaymentSync.assert_called_once_with(lnd_req)
        self.assertEqual(res, pb.PayInvoiceResponse())
        # RpcError case
        reset_mocks(vars())
        error = RpcError()
        stub.SendPaymentSync.side_effect = error
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.PayInvoice(pb.PayInvoiceRequest(), 'context')
        stub.SendPaymentSync.assert_called_once_with(ln.SendRequest())
        mocked_report.assert_called_once_with('context', error)

    @patch('lighter.light_lnd._handle_error', autospec=True)
    @patch('lighter.light_lnd._add_route_hint', autospec=True)
    @patch('lighter.light_lnd.convert', autospec=True)
    @patch('lighter.light_lnd.Err')
    @patch('lighter.light_lnd._connect', autospec=True)
    def test_DecodeInvoice(self, mocked_connect, mocked_err, mocked_conv,
                           mocked_add, mocked_report):
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
        res = MOD.DecodeInvoice(request, 'context')
        mocked_conv.assert_called_once_with('context', Enf.SATS,
                                            lnd_res.num_satoshis)
        response = pb.DecodeInvoiceResponse(amount_bits=7.77)
        mocked_add.assert_called_once_with('context', response,
                                           lnd_res.route_hints[0])
        self.assertEqual(res.amount_bits, 7.77)
        # self.assertEqual(res.route_hints[0].hop_hints[0].node_id, '1_id')
        # Missing parameter payment_request case
        reset_mocks(vars())
        request = pb.DecodeInvoiceRequest()
        mocked_err.return_value.missing_parameter.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.DecodeInvoice(request, 'context')
        assert not stub.DecodePayReq.called
        assert not mocked_conv.called
        assert not mocked_add.called
        mocked_err().missing_parameter.called
        assert not mocked_report.called
        # Error case
        reset_mocks(vars())
        request = pb.DecodeInvoiceRequest(payment_request='pay_req')
        error = RpcError()
        stub.DecodePayReq.side_effect = error
        mocked_report.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.DecodeInvoice(request, 'context')
        lnd_req = ln.PayReqString(pay_req='pay_req')
        stub.DecodePayReq.assert_called_once_with(lnd_req)
        mocked_report.assert_called_once_with('context', error)

    @patch('lighter.light_lnd.convert', autospec=True)
    def test_add_channel(self, mocked_conv):
        # Active: empty
        response = pb.ListChannelsResponse()
        lnd_chan = ln.Channel()
        MOD._add_channel('context', response, lnd_chan, active=True)
        assert not mocked_conv.called
        self.assertEqual(response, pb.ListChannelsResponse())
        # Active: filled
        reset_mocks(vars())
        lnd_chan = ln.Channel(
            chan_id=123,
            capacity=7777777,
            local_balance=6666666,
            remote_balance=1111111)
        MOD._add_channel('context', response, lnd_chan, active=True)
        calls = [
            call('context', Enf.SATS, lnd_chan.capacity),
            call('context', Enf.SATS, lnd_chan.local_balance),
            call('context', Enf.SATS, lnd_chan.remote_balance)
        ]
        mocked_conv.assert_has_calls(calls)
        self.assertEqual(response.channels[0].channel_id, '123')
        # Pending: empty
        reset_mocks(vars())
        response = pb.ListChannelsResponse()
        lnd_chan = ln.PendingChannelsResponse.PendingChannel()
        MOD._add_channel('context', response, lnd_chan)
        assert not mocked_conv.called
        self.assertEqual(response, pb.ListChannelsResponse())
        # Pending: filled
        reset_mocks(vars())
        lnd_chan = ln.PendingChannelsResponse.PendingChannel(
            remote_node_pub='abc',
            capacity=7777777,
            local_balance=6666666,
            remote_balance=1111111)
        MOD._add_channel('context', response, lnd_chan)
        calls = [
            call('context', Enf.SATS, lnd_chan.capacity),
            call('context', Enf.SATS, lnd_chan.local_balance),
            call('context', Enf.SATS, lnd_chan.remote_balance)
        ]
        mocked_conv.assert_has_calls(calls)
        self.assertEqual(response.channels[0].remote_pubkey, 'abc')

    @patch('lighter.light_lnd.convert', autospec=True)
    def test_add_route_hint(self, mocked_conv):
        response = pb.DecodeInvoiceResponse()
        lnd_route = ln.RouteHint()
        # Empty
        MOD._add_route_hint('context', response, lnd_route)
        assert not mocked_conv.called
        self.assertEqual(response, pb.DecodeInvoiceResponse())
        # Filled
        reset_mocks(vars())
        lnd_route.hop_hints.add(node_id='id', fee_base_msat=77)
        MOD._add_route_hint('context', response, lnd_route)
        mocked_conv.assert_called_once_with('context', Enf.MSATS, 77)
        self.assertEqual(response.route_hints[0].hop_hints[0].pubkey, 'id')

    @patch('lighter.light_lnd.Err')
    def test_handle_error(self, mocked_err):
        # Error string
        MOD._handle_error('context', 'an error')
        mocked_err().report_error.assert_called_with('context', 'an error')
        # RPC invocation: error object has details method
        reset_mocks(vars())
        error = CalledRpcError()
        MOD._handle_error('context', error)
        mocked_err().report_error.assert_called_with('context',
                                                     error.details())
        # Error doesn't have the details method and is not a string
        reset_mocks(vars())
        error = RpcError()
        MOD._handle_error('context', error)
        mocked_err().report_error.assert_called_with(
            'context', 'Could not decode error message')


class CalledRpcError(RpcError):
    def details(self):
        return 'no error message'


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
