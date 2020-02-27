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

""" Tests for light_electrum module """

from importlib import import_module
from unittest import TestCase
from unittest.mock import call, Mock, patch

from . import fixtures_electrum as fix, proj_root

CTX = 'context'
Enf = getattr(import_module(proj_root + '.utils.bitcoin'), 'Enforcer')
pb = import_module(proj_root + '.lighter_pb2')
settings = import_module(proj_root + '.settings')

MOD = import_module(proj_root + '.light_electrum')


class LightElectrumTests(TestCase):
    """ Tests for light_electrum module """

    @patch(MOD.__name__ + '.set_defaults', autospec=True)
    def test_get_settings(self, mocked_set_def):
        ele_host = 'electrum'
        ele_port = '7777'
        ele_user = 'user'
        config = Mock()
        config.get.side_effect = [ele_host, ele_port, ele_user]
        MOD.get_settings(config, 'electrum')
        ele_values = ['ELE_HOST', 'ELE_PORT', 'ELE_USER']
        mocked_set_def.assert_called_once_with(config, ele_values)
        self.assertEqual(settings.ELE_HOST, ele_host)
        self.assertEqual(settings.ELE_PORT, ele_port)
        self.assertEqual(settings.ELE_USER, ele_user)
        self.assertEqual(settings.IMPL_SEC_TYPE, 'password')

    def test_update_settings(self):
        # Correct case
        pwd = 'password'
        MOD.update_settings(pwd.encode())
        self.assertEqual(
            settings.RPC_URL, 'http://{}:{}@{}:{}'.format(
            settings.ELE_USER, pwd, settings.ELE_HOST, settings.ELE_PORT))

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    def test_GetInfo(self, mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        err_msg = 'electrum error'
        # Correct case
        ses.nodeid.return_value = (fix.NODEID, False)
        ses.getinfo.return_value = (fix.GETINFO, False)
        res = MOD.GetInfo('req', CTX)
        self.assertEqual(res.blockheight, fix.GETINFO['blockchain_height'])
        self.assertEqual(res.identity_pubkey, fix.NODEID_INCOMPLETE)
        self.assertEqual(res.network, 'regtest')
        self.assertEqual(res.node_uri, fix.NODEID)
        self.assertEqual(res.version, fix.GETINFO['version'])
        # With incomplete nodeid and on mainnet
        reset_mocks(vars())
        ses.nodeid.return_value = (fix.NODEID_INCOMPLETE, False)
        ses.getinfo.return_value = (fix.GETINFO_MAINNET, False)
        res = MOD.GetInfo('req', CTX)
        self.assertEqual(res.node_uri, '')
        self.assertEqual(res.identity_pubkey, fix.NODEID_INCOMPLETE)
        self.assertEqual(res.network, 'mainnet')
        # getinfo error case
        reset_mocks(vars())
        ses.nodeid.return_value = (fix.NODEID, False)
        ses.getinfo.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            res = MOD.GetInfo('req', CTX)
        mocked_handle.assert_called_once_with(CTX, err_msg)
        # nodeid error case
        reset_mocks(vars())
        ses.nodeid.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            res = MOD.GetInfo('req', CTX)
        mocked_handle.assert_called_once_with(CTX, err_msg)

    @patch(MOD.__name__ + '.get_address_type', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    def test_NewAddress(self, mocked_rpcses, mocked_handle, mocked_err,
                        mocked_log, mocked_addr_type):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        mocked_err().unimplemented_param_value.side_effect = Exception()
        mocked_addr_type.return_value = pb.P2WKH
        # Segwit case: request.type = 1 = P2WKH = BECH32
        ses.listaddresses.return_value = (fix.LISTADDRESSES, False)
        req = pb.NewAddressRequest(type=pb.P2WKH)
        res = MOD.NewAddress(req, CTX)
        self.assertEqual(res.address, fix.LISTADDRESSES[0])
        mocked_addr_type.assert_called_once_with(fix.LISTADDRESSES[0])
        # Second address request (must be different from before)
        reset_mocks(vars())
        res = MOD.NewAddress(req, CTX)
        self.assertEqual(res.address, fix.LISTADDRESSES[1])
        mocked_addr_type.assert_called_once_with(fix.LISTADDRESSES[0])
        # Legacy case: request.type = 0 = NP2WKH = P2SH_SEGWIT (not supported)
        reset_mocks(vars())
        req = pb.NewAddressRequest()
        with self.assertRaises(Exception):
            res = MOD.NewAddress(req, CTX)
        mocked_err().unimplemented_param_value.assert_called_once_with(
            CTX, 'type', pb.AddressType.Name(0))
        # Exhausted list case
        reset_mocks(vars())
        req = pb.NewAddressRequest(type=pb.P2WKH)
        settings.ELE_RELEASED_ADDRESSES = fix.LISTADDRESSES
        res = MOD.NewAddress(req, CTX)
        self.assertEqual(res.address, fix.LISTADDRESSES[0])
        # Error case
        reset_mocks(vars())
        err_msg = 'electrum error'
        ses.listaddresses.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            res = MOD.NewAddress(req, CTX)
        mocked_handle.assert_called_once_with(CTX, err_msg)

    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    def test_WalletBalance(self, mocked_rpcses, mocked_handle, mocked_conv):
        ses = mocked_rpcses.return_value
        ses.getbalance.return_value = (fix.GETBALANCE, False)
        mocked_handle.side_effect = Exception()
        mocked_conv.return_value = 7
        # Correct case
        res = MOD.WalletBalance('req', CTX)
        self.assertEqual(res.balance_confirmed, mocked_conv.return_value)
        self.assertEqual(res.balance, mocked_conv.return_value)
        self.assertEqual(mocked_conv.call_count, 2)
        # Correct case: with no unconfirmed balance
        reset_mocks(vars())
        ses.getbalance.return_value = (fix.GETBALANCE_NO_UCONFIRMED, False)
        res = MOD.WalletBalance('req', CTX)
        self.assertEqual(res.balance_confirmed, mocked_conv.return_value)
        self.assertEqual(res.balance, mocked_conv.return_value)
        self.assertEqual(mocked_conv.call_count, 1)
        # No balance case
        reset_mocks(vars())
        ses.getbalance.return_value = (fix.GETBALANCE_EMPTY, False)
        res = MOD.WalletBalance('req', CTX)
        self.assertEqual(mocked_conv.call_count, 1)
        # Error case
        reset_mocks(vars())
        err_msg = 'electrum error'
        ses.getbalance.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            res = MOD.WalletBalance('req', CTX)
        mocked_handle.assert_called_once_with(CTX, err_msg)

    @patch(MOD.__name__ + '.get_channel_balances', autospec=True)
    @patch(MOD.__name__ + '.ListChannels')
    def test_ChannelBalance(self, mocked_ListChannels, mocked_get_chan_bal):
        mocked_get_chan_bal.return_value = pb.ChannelBalanceResponse()
        res = MOD.ChannelBalance('request', CTX)
        self.assertEqual(res, pb.ChannelBalanceResponse())

    @patch(MOD.__name__ + '._add_channel', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    @patch(MOD.__name__ + '.Err')
    def test_ListChannels(self, mocked_err, mocked_rpcses, mocked_handle,
                          mocked_add):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        mocked_err().unimplemented_param_value.side_effect = Exception()
        # Correct case
        ses.list_channels.return_value = (fix.LIST_CHANNELS, False)
        req = pb.ListChannelsRequest()
        res = MOD.ListChannels(req, CTX)
        self.assertNotEqual(res, None)
        self.assertEqual(mocked_add.call_count, len(fix.LIST_CHANNELS))
        # Active only case
        reset_mocks(vars())
        req = pb.ListChannelsRequest(active_only=True)
        with self.assertRaises(Exception):
            res = MOD.ListChannels(req, CTX)
        mocked_err().unimplemented_param_value.assert_called_once_with(
            CTX, 'active_only', 'True')
        req = pb.ListChannelsRequest()
        # Error case
        reset_mocks(vars())
        err_msg = 'electrum error'
        ses.list_channels.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            res = MOD.ListChannels(req, CTX)
        mocked_handle.assert_called_once_with(CTX, err_msg)

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_CreateInvoice(self, mocked_check_par, mocked_err, mocked_conv,
                           mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        mocked_err().unimplemented_parameter.side_effect = Exception()
        desc = 'description'
        etime = 666
        # Correct case
        ses.add_lightning_request.return_value = \
            (fix.ADD_LIGHTNING_REQUEST, False)
        req = pb.CreateInvoiceRequest(amount_bits=7, description=desc,
                                      expiry_time=etime)
        res = MOD.CreateInvoice(req, CTX)
        self.assertEqual(res.payment_request, fix.ADD_LIGHTNING_REQUEST)
        mocked_check_par.assert_called_once_with(CTX, req, 'amount_bits')
        params = {'memo': desc, 'expiration': etime,
                  'amount': mocked_conv.return_value}
        ses.add_lightning_request.assert_called_once_with(CTX, params)
        # Correct case without expiry_time
        reset_mocks(vars())
        ses.add_lightning_request.return_value = \
            (fix.ADD_LIGHTNING_REQUEST, False)
        req = pb.CreateInvoiceRequest(amount_bits=7, description=desc)
        res = MOD.CreateInvoice(req, CTX)
        params = {'memo': desc, 'expiration': settings.EXPIRY_TIME,
                  'amount': mocked_conv.return_value}
        ses.add_lightning_request.assert_called_once_with(CTX, params)
        # Missing amount case
        reset_mocks(vars())
        mocked_check_par.side_effect = Exception()
        req = pb.CreateInvoiceRequest()
        with self.assertRaises(Exception):
            res = MOD.CreateInvoice(req, CTX)
        assert not ses.add_lightning_request.called
        mocked_check_par.side_effect = None
        # Request with min_final_cltv_expiry case
        reset_mocks(vars())
        req = pb.CreateInvoiceRequest(amount_bits=7, min_final_cltv_expiry=1)
        with self.assertRaises(Exception):
            res = MOD.CreateInvoice(req, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'min_final_cltv_expiry')
        # Request with fallback_addr case
        reset_mocks(vars())
        req = pb.CreateInvoiceRequest(amount_bits=7, fallback_addr='f')
        with self.assertRaises(Exception):
            res = MOD.CreateInvoice(req, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'fallback_addr')
        # Error case
        reset_mocks(vars())
        req = pb.CreateInvoiceRequest(amount_bits=7)
        err_msg = 'electrum error'
        ses.add_lightning_request.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            res = MOD.CreateInvoice(req, CTX)
        mocked_handle.assert_called_once_with(CTX, err_msg)

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.has_amount_encoded', autospec=True)
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_PayInvoice(self, mocked_check_par, mocked_has_amt, mocked_err,
                        mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_err().amount_required.side_effect = Exception()
        mocked_err().unimplemented_parameter.side_effect = Exception()
        mocked_err().unsettable.side_effect = Exception()
        mocked_err().payinvoice_failed.side_effect = Exception()
        mocked_handle.side_effect = Exception()
        # Successful payment case
        ses.lnpay.return_value = (True, False)
        mocked_has_amt.return_value = True
        req = pb.PayInvoiceRequest(payment_request='p')
        res = MOD.PayInvoice(req, CTX)
        self.assertEqual(res, pb.PayInvoiceResponse())
        # Missing payment request case
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        assert not mocked_err().unsettable.called
        assert not mocked_err().unimplemented_parameter.called
        assert not mocked_err().amount_required.called
        mocked_check_par.side_effect = None
        # Unsettable amount case
        reset_mocks(vars())
        req = pb.PayInvoiceRequest(payment_request='p', amount_bits=7)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        mocked_err().unsettable.assert_called_once_with(CTX, 'amount_bits')
        # Amount required case
        mocked_has_amt.return_value = False
        req = pb.PayInvoiceRequest(payment_request='p')
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        mocked_err().amount_required.assert_called_once_with(CTX)
        # Unimplemented amount_bits case
        reset_mocks(vars())
        req = pb.PayInvoiceRequest(payment_request='p', amount_bits=7)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'amount_bits')
        mocked_has_amt.return_value = True
        # Unimplemented description case
        reset_mocks(vars())
        req = pb.PayInvoiceRequest(payment_request='p', description='d')
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'description')
        # Unimplemented cltv_expiry_delta case
        reset_mocks(vars())
        req = pb.PayInvoiceRequest(payment_request='p', cltv_expiry_delta=1)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        mocked_err().unimplemented_parameter.assert_called_once_with(
            CTX, 'cltv_expiry_delta')
        # Unsuccessful payment case
        reset_mocks(vars())
        ses.lnpay.return_value = (False, False)
        req = pb.PayInvoiceRequest(payment_request='p')
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        mocked_err().payinvoice_failed.assert_called_once_with(CTX)
        # Error case
        reset_mocks(vars())
        req = pb.PayInvoiceRequest(payment_request='p')
        ses.lnpay.return_value = (False, True)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        mocked_handle.assert_called_once_with(CTX, False)

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.Enf.check_value')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_PayOnChain(self, mocked_check_par, mocked_check_val, mocked_err,
                        mocked_conv, mocked_rpcses, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_err().out_of_range.side_effect = Exception()
        mocked_handle.side_effect = Exception()
        amt = 7
        fsb = 1
        addr = 'address'
        err_msg = 'electrum error'
        # Missing amount_bits case
        req = pb.PayOnChainRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD.PayOnChain(req, CTX)
        mocked_check_par.side_effect = None
        mocked_check_par.assert_called_once_with(
            CTX, req, 'address', 'amount_bits')
        # Incorrect fee case
        reset_mocks(vars())
        req = pb.PayOnChainRequest(
            amount_bits=amt, address=addr, fee_sat_byte=fsb)
        mocked_check_val.return_value = False
        with self.assertRaises(Exception):
            MOD.PayOnChain(req, CTX)
        # Correct case
        reset_mocks(vars())
        mocked_check_val.return_value = True
        ses.payto.return_value = (fix.PAYTO, False)
        ses.broadcast.return_value = (fix.BROADCAST, False)
        res = MOD.PayOnChain(req, CTX)
        params = {'feerate': fsb, 'destination': addr,
                  'amount': mocked_conv.return_value}
        ses.payto.assert_called_once_with(CTX, params)
        params = {'tx': ses.payto.return_value[0]}
        ses.broadcast.assert_called_once_with(CTX, params)
        self.assertEqual(res.txid, fix.BROADCAST)
        # Error on payto case
        reset_mocks(vars())
        req = pb.PayOnChainRequest(address=addr, amount_bits=amt)
        ses.payto.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            MOD.PayOnChain(req, CTX)
        # Error on broadcast case
        reset_mocks(vars())
        req = pb.PayOnChainRequest(address=addr, amount_bits=amt)
        ses.payto.return_value = (fix.PAYTO, False)
        ses.broadcast.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            MOD.PayOnChain(req, CTX)

    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.ElectrumRPC')
    def test_OpenChannel(self, mocked_rpcses, mocked_err, mocked_handle,
                         mocked_conv):
        ses = mocked_rpcses.return_value
        mocked_err().unimplemented_param_value.side_effect = Exception()
        mocked_handle.side_effect = Exception()
        amt = 7
        ses.open_channel.return_value = (fix.OPEN_CHANNEL, False)
        # Correct case
        req = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODEID, private=True,
            push_bits=amt)
        res = MOD.OpenChannel(req, CTX)
        self.assertEqual(res.funding_txid, fix.OPEN_CHANNEL.split(':')[0])
        # Error if private=False
        reset_mocks(vars())
        req = pb.OpenChannelRequest(funding_bits=amt, node_uri=fix.NODEID)
        with self.assertRaises(Exception):
            res = MOD.OpenChannel(req, CTX)
        mocked_err().unimplemented_param_value.assert_called_once_with(
            CTX, 'private', 'False')
        # Error case
        reset_mocks(vars())
        req = pb.OpenChannelRequest(
            funding_bits=amt, node_uri=fix.NODEID, private=True,
            push_bits=amt)
        err_msg = 'electrum error'
        ses.open_channel.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            res = MOD.OpenChannel(req, CTX)
        mocked_handle.assert_called_once_with(CTX, err_msg)

    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '._get_channel_state', autospec=True)
    def test_add_channel(self, mocked_state, mocked_conv):
        # Add channel case
        response = pb.ListChannelsResponse()
        mocked_conv.return_value = 7
        ele_chan = fix.CHANNEL_OPEN
        mocked_state.return_value = pb.OPEN
        res = MOD._add_channel(CTX, response, ele_chan, False)
        self.assertEqual(mocked_conv.call_count, 2)
        self.assertEqual(res, None)
        self.assertEqual(response.channels[0].remote_pubkey,
                         ele_chan['remote_pubkey'])
        self.assertEqual(response.channels[0].short_channel_id,
                         ele_chan['channel_id'])
        self.assertEqual(response.channels[0].channel_id,
                         ele_chan['full_channel_id'])
        self.assertEqual(response.channels[0].funding_txid,
                         ele_chan['channel_point'].split(':')[0])
        self.assertEqual(response.channels[0].local_balance,
                         mocked_conv.return_value)
        self.assertEqual(response.channels[0].remote_balance,
                         mocked_conv.return_value)
        calls = [call(CTX, Enf.SATS, ele_chan['local_balance']),
                 call(CTX, Enf.SATS, ele_chan['remote_balance'])]
        mocked_conv.assert_has_calls(calls)
        self.assertEqual(response.channels[0].capacity,
                         mocked_conv.return_value * 2)
        self.assertEqual(response.channels[0].to_self_delay, 0)
        # Skip add of inactive channel case
        reset_mocks(vars())
        response = pb.ListChannelsResponse()
        mocked_state.return_value = pb.PENDING_OPEN
        res = MOD._add_channel(CTX, response, fix.CHANNEL_OPENING, True)
        self.assertEqual(response, pb.ListChannelsResponse())
        assert not mocked_conv.called

    def test_get_channel_state(self):
        res = MOD._get_channel_state(fix.CHANNEL_CLOSED)
        self.assertEqual(res, -1)
        res = MOD._get_channel_state(fix.CHANNEL_OPEN)
        self.assertEqual(res, pb.OPEN)
        res = MOD._get_channel_state(fix.CHANNEL_OPENING)
        self.assertEqual(res, pb.PENDING_OPEN)
        res = MOD._get_channel_state(fix.CHANNEL_FUNDED)
        self.assertEqual(res, pb.PENDING_OPEN)
        res = MOD._get_channel_state(fix.CHANNEL_FORCE_CLOSING)
        self.assertEqual(res, pb.PENDING_FORCE_CLOSE)
        res = MOD._get_channel_state(fix.CHANNEL_CLOSING)
        self.assertEqual(res, pb.PENDING_MUTUAL_CLOSE)
        res = MOD._get_channel_state(fix.CHANNEL_UNKNOWN)
        self.assertEqual(res, pb.UNKNOWN)

    @patch(MOD.__name__ + '.Err')
    def test_handle_error(self, mocked_err):
        err_msg = 'electrum_error'
        MOD._handle_error(CTX, err_msg)
        mocked_err().report_error.assert_called_once_with(CTX, err_msg)

    @patch(MOD.__name__ + '.RPCSession.call', autospec=True)
    def test_ElectrumRPC(self, mocked_call):
        settings.ECL_PASS = 'pass'
        # Without params and timeout case
        rpc_ele = MOD.ElectrumRPC()
        self.assertEqual(rpc_ele._headers,
                         {'content-type': 'application/json'})
        res = rpc_ele.getinfo(CTX)
        self.assertEqual(res, mocked_call.return_value)
        payload = MOD.dumps(
            {"id": rpc_ele._id_count, "method": 'getinfo',
             "params": {}, "jsonrpc": '2.0'})
        mocked_call.assert_called_once_with(
            rpc_ele, CTX, payload, timeout=None)
        # With params and timeout case
        reset_mocks(vars())
        params = {'unused': True}
        timeout = 7
        res = rpc_ele.listaddresses(CTX,params, timeout)
        payload = MOD.dumps(
            {"id": rpc_ele._id_count, "method": 'listaddresses',
             "params": params, "jsonrpc": '2.0'})
        mocked_call.assert_called_once_with(
            rpc_ele, CTX, payload, timeout=timeout)


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
