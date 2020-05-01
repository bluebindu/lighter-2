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

from concurrent.futures import TimeoutError as TimeoutFutError
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
    @patch(MOD.__name__ + '.update_settings', autospec=True)
    @patch(MOD.__name__ + '.get_secret', autospec=True)
    @patch(MOD.__name__ + '.session_scope', autospec=True)
    @patch(MOD.__name__ + '.ExitStack', autospec=True)
    def test_unlock_node(self, mocked_stack, mocked_ses, mocked_get_sec,
                         mocked_update, mocked_rpcses, mocked_handle):
        pwd = 'password'
        ses = mocked_rpcses.return_value
        ele_pwd = b'ele_password'
        mocked_get_sec.return_value = ele_pwd
        mocked_handle.side_effect = Exception()
        ses.load_wallet.return_value = (True, False)
        # with no session, correct password or already unlocked
        MOD.unlock_node(CTX, pwd)
        mocked_rpcses.assert_called_once_with()
        mocked_update.assert_called_once_with(ele_pwd)
        mocked_ses.assert_called_once_with(CTX)
        assert not mocked_stack.called
        assert not mocked_handle.called
        # with no session, incorrect password
        reset_mocks(vars())
        err_msg = 'Whatever'
        ses.load_wallet.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            MOD.unlock_node(CTX, pwd)
        mocked_handle.assert_called_once_with(CTX, err_msg)
        # with passed session, no password stored
        reset_mocks(vars())
        session = 'session'
        ses.load_wallet.return_value = ('foo', True)
        mocked_get_sec.return_value = None
        with self.assertRaises(Exception):
            MOD.unlock_node(CTX, pwd, session=session)
        mocked_update.assert_called_once_with(None)
        assert not mocked_ses.called
        mocked_handle.assert_called_once_with(CTX, 'foo')
        mocked_stack.assert_called_once_with()

    @patch(MOD.__name__ + '.unlock_node', autospec=True)
    @patch(MOD.__name__ + '.check_password', autospec=True)
    @patch(MOD.__name__ + '.session_scope', autospec=True)
    def test_UnlockNode(self, mocked_ses, mocked_check, mocked_unlock):
        pwd = 'password'
        req = pb.UnlockNodeRequest(password=pwd)
        res = MOD.UnlockNode(req, CTX)
        self.assertEqual(res, pb.UnlockNodeResponse())
        mocked_ses.assert_called_once_with(CTX)
        mocked_check.assert_called_once_with(
            CTX, mocked_ses.return_value.__enter__.return_value, pwd)
        mocked_unlock.assert_called_once_with(
            CTX, pwd, session=mocked_ses.return_value.__enter__.return_value)

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
        res = MOD.ListChannels(req, CTX)
        assert not mocked_handle.called
        ses.list_channels.assert_called_once_with(CTX)
        # Error case
        req = pb.ListChannelsRequest()
        reset_mocks(vars())
        err_msg = 'electrum error'
        ses.list_channels.return_value = (err_msg, True)
        with self.assertRaises(Exception):
            res = MOD.ListChannels(req, CTX)
        mocked_handle.assert_called_once_with(CTX, err_msg)

    @patch(MOD.__name__ + '._get_invoice_state', autospec=True)
    @patch(MOD.__name__ + '._add_invoice', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    def test_ListInvoices(self, mocked_rpcses, mocked_handle, mocked_add,
                          mocked_state):
        ses = mocked_rpcses.return_value
        ele_res = fix.LIST_INVOICES
        ses.list_requests.return_value = ele_res, False
        mocked_handle.side_effect = Exception()

        def add_invoice(*args):
            args[1].invoices.add()

        mocked_add.side_effect = add_invoice
        # Correct case: with max_items
        max_invoices = 4
        request = pb.ListInvoicesRequest(max_items=max_invoices, paid=True,
                                         pending=True)
        res = MOD.ListInvoices(request, CTX)
        self.assertEqual(max_invoices, len(res.invoices))
        self.assertEqual(mocked_add.call_count, max_invoices)
        self.assertEqual(request.max_items, max_invoices)
        # Correct case, filtering and sorting by timestamp
        reset_mocks(vars())
        ts = 1584269382
        mocked_state.return_value = pb.PENDING
        request = pb.ListInvoicesRequest(
            search_order=1, search_timestamp=ts, list_order=0, paid=True)
        res = MOD.ListInvoices(request, CTX)
        self.assertEqual(request.max_items, settings.MAX_INVOICES)
        self.assertTrue(mocked_add.call_count <= settings.MAX_INVOICES)
        assert not mocked_add.called
        # Correct case, filtering and sorting by timestamp
        reset_mocks(vars())
        mocked_state.return_value = pb.PAID
        request = pb.ListInvoicesRequest(
            search_order=0, search_timestamp=ts, list_order=1, expired=True,
            pending=True)
        res = MOD.ListInvoices(request, CTX)
        self.assertEqual(request.max_items, settings.MAX_INVOICES)
        self.assertTrue(mocked_add.call_count <= settings.MAX_INVOICES)
        assert not mocked_add.called
        # Correct case, filtering and sorting by timestamp
        reset_mocks(vars())
        mocked_state.return_value = pb.EXPIRED
        request = pb.ListInvoicesRequest(
            search_order=0, search_timestamp=ts, list_order=1, paid=True,
            pending=True, unknown=True)
        res = MOD.ListInvoices(request, CTX)
        self.assertEqual(request.max_items, settings.MAX_INVOICES)
        self.assertTrue(mocked_add.call_count <= settings.MAX_INVOICES)
        assert not mocked_add.called
        # Correct case, filtering and sorting by timestamp
        reset_mocks(vars())
        mocked_state.return_value = pb.UNKNOWN
        request = pb.ListInvoicesRequest(
            search_order=0, search_timestamp=ts, list_order=1, paid=True,
            pending=True, expired=True)
        res = MOD.ListInvoices(request, CTX)
        self.assertEqual(request.max_items, settings.MAX_INVOICES)
        self.assertTrue(mocked_add.call_count <= settings.MAX_INVOICES)
        assert not mocked_add.called
        # Empty response case
        reset_mocks(vars())
        request = pb.ListInvoicesRequest(paid=True)
        ses.list_requests.return_value = ([], False)
        MOD.ListInvoices(request, CTX)
        assert not mocked_handle.called
        assert not mocked_add.called
        # Error case
        reset_mocks(vars())
        request = pb.ListInvoicesRequest(paid=True)
        ele_res = 'Whatever random string'
        ses.list_requests.return_value = ele_res, True
        with self.assertRaises(Exception):
            MOD.ListInvoices(request, CTX)
        mocked_handle.assert_called_once_with(CTX, ele_res)
        assert not mocked_add.called
        # No filter requested case return all of them
        reset_mocks(vars())
        request = pb.ListInvoicesRequest()
        ses.list_requests.return_value = fix.LIST_INVOICES, False
        MOD.ListInvoices(request, CTX)
        assert not mocked_handle.called
        assert mocked_add.call_count == min(len(fix.LIST_INVOICES),
                                            settings.MAX_INVOICES)

    @patch(MOD.__name__ + '._add_payment', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    def test_ListPayments(self, mocked_rpcses, mocked_handle, mocked_add):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        # Correct case
        request = pb.ListPaymentsRequest()
        ses.lightning_history.return_value = (fix.PAYMENTS, False)
        res = MOD.ListPayments(request, CTX)
        ses.lightning_history.assert_called_once_with(CTX)
        assert mocked_add.called
        # Error case
        reset_mocks(vars())
        ses.lightning_history.return_value = (fix.BADRESPONSE, True)
        with self.assertRaises(Exception):
            res = MOD.ListPayments('request', CTX)
        ses.lightning_history.assert_called_once_with(CTX)
        assert not mocked_add.called
        mocked_handle.assert_called_once_with(CTX, fix.BADRESPONSE)

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    def test_ListPeers(self, mocked_ses, mocked_handle):
        ses = mocked_ses.return_value
        mocked_handle.side_effect = Exception()
        response = pb.ListPeersResponse()
        # Correct case
        request = pb.ListPeersRequest()
        ses.list_peers.return_value = (fix.LIST_PEERS, False)
        res = MOD.ListPeers(request, CTX)
        assert not mocked_handle.called
        self.assertEqual(res.peers[0].pubkey, fix.LIST_PEERS[0]['node_id'])
        self.assertEqual(res.peers[0].address, fix.LIST_PEERS[0]['address'])
        # Empty case
        reset_mocks(vars())
        request = pb.ListPeersRequest()
        ses.list_peers.return_value = ([], False)
        res = MOD.ListPeers(request, CTX)
        assert not mocked_handle.called
        self.assertEqual(res, pb.ListPeersResponse())
        # Error case
        reset_mocks(vars())
        error = 'Some error string'
        ses.list_peers.return_value = (error, True)
        with self.assertRaises(Exception):
            MOD.ListPeers('request', CTX)
        ses.list_peers.assert_called_once_with(CTX)
        mocked_handle.assert_called_once_with(CTX, error)

    @patch(MOD.__name__ + '._add_transaction', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    def test_ListTransactions(self, mocked_rpcses, mocked_handle, mocked_add):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        response = pb.ListTransactionsResponse()
        # Correct case
        request = pb.ListTransactionsRequest()
        ses.onchain_history.return_value = (fix.LIST_TRANSACTIONS, False)
        res = MOD.ListTransactions(request, CTX)
        calls = []
        for ele_transaction in fix.LIST_TRANSACTIONS['transactions']:
            calls.append(call(CTX, response, ele_transaction))
        mocked_add.assert_has_calls(calls)
        # Error case
        reset_mocks(vars())
        ele_res = "Strange string"
        ses.onchain_history.return_value = (ele_res, True)
        with self.assertRaises(Exception):
            res = MOD.ListTransactions(request, CTX)
        assert not mocked_add.called
        mocked_handle.assert_called_once_with(CTX, ele_res)

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

    @patch(MOD.__name__ + '._get_invoice_state', autospec=True)
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_CheckInvoice(self, mocked_check_par, mocked_rpcses,
                          mocked_handle, mocked_inv_st):
        ses = mocked_rpcses.return_value
        pay_hash = 'payment_hash'
        mocked_handle.side_effect = Exception()
        # Correct case
        mocked_inv_st.return_value = pb.PAID
        request = pb.CheckInvoiceRequest(payment_hash=pay_hash)
        ses.getrequest.return_value = (fix.LIST_INVOICES[3], False)
        res = MOD.CheckInvoice(request, CTX)
        req = {}
        ses.getrequest.assert_called_once_with(
            CTX, {'key': pay_hash})
        assert not mocked_handle.called
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
        err = 'Whatever error string'
        ses.getrequest.return_value = (err, True)
        with self.assertRaises(Exception):
            res = MOD.CheckInvoice(request, CTX)
        mocked_handle.assert_called_once_with(CTX, err)

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
        ses.lnpay.return_value = (fix.LNPAY_SUCCESS, False)
        mocked_has_amt.return_value = True
        req = pb.PayInvoiceRequest(payment_request='p')
        res = MOD.PayInvoice(req, CTX)
        response = pb.PayInvoiceResponse()
        response.payment_preimage = fix.LNPAY_SUCCESS['preimage']
        self.assertEqual(res, response)
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
        ses.lnpay.return_value = (fix.LNPAY_EXPIRED, False)
        req = pb.PayInvoiceRequest(payment_request='p')
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        mocked_err().payinvoice_failed.assert_called_once_with(CTX)
        # Error case
        reset_mocks(vars())
        req = pb.PayInvoiceRequest(payment_request='p')
        ses.lnpay.return_value = (fix.LNPAY_EXPIRED, True)
        with self.assertRaises(Exception):
            res = MOD.PayInvoice(req, CTX)
        mocked_handle.assert_called_once_with(CTX, fix.LNPAY_EXPIRED)

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

    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_DecodeInvoice(self, mocked_check_par, mocked_rpcses,
                           mocked_conv, mocked_handle):
        ses = mocked_rpcses.return_value
        mocked_handle.side_effect = Exception()
        pay_req = 'payment_request'
        # Correct case: with description hash
        req = pb.DecodeInvoiceRequest(payment_request=pay_req)
        ses.decode_invoice.return_value = (fix.DECODE_INVOICE, False)
        mocked_conv.return_value = 7.77
        res = MOD.DecodeInvoice(req, CTX)
        ses.decode_invoice.assert_called_once_with(CTX, {'invoice': pay_req})
        self.assertEqual(res.amount_bits, 7.77)
        self.assertEqual(res.timestamp, fix.DECODE_INVOICE['time'])
        self.assertEqual(res.payment_hash, fix.DECODE_INVOICE['rhash'])
        self.assertEqual(res.description, fix.DECODE_INVOICE['message'])
        self.assertEqual(res.destination_pubkey, fix.DECODE_INVOICE['pubkey'])
        self.assertEqual(res.expiry_time, fix.DECODE_INVOICE['exp'])
        # Default values for unavailable information
        self.assertEqual(res.description_hash, '')
        self.assertEqual(res.min_final_cltv_expiry, 0)
        self.assertEqual(res.fallback_addr, '')
        # Missing parameter case
        reset_mocks(vars())
        req = pb.DecodeInvoiceRequest()
        mocked_check_par.side_effect = Exception()
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(req, CTX)
        mocked_check_par.assert_called_once_with(CTX, req, 'payment_request')
        mocked_check_par.side_effect = None
        # Error case
        reset_mocks(vars())
        error = 'Some error string'
        ses.decode_invoice.return_value = (error, True)
        with self.assertRaises(Exception):
            res = MOD.DecodeInvoice(req, CTX)
        mocked_handle.assert_called_once_with(CTX, error)


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

    @patch(MOD.__name__ + '._close_channel', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '._handle_error', autospec=True)
    @patch(MOD.__name__ + '.get_thread_timeout', autospec=True)
    @patch(MOD.__name__ + '.ThreadPoolExecutor', autospec=True)
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_CloseChannel(self, mocked_check_par, mocked_thread,
                          mocked_thread_time, mocked_handle, mocked_err,
                          mocked_rpcses, mocked_close):
        ses = mocked_rpcses.return_value
        chan = fix.CHANNEL_OPEN
        ses.list_channels.return_value = (fix.LIST_CHANNELS, False)
        mocked_handle.side_effect = Exception()
        mocked_err().closechannel_failed.side_effect = Exception()
        mocked_err().report_error.side_effect = Exception()
        mocked_thread_time.return_value = 2
        txid = 'txid'
        # Correct case, force close
        future = Mock()
        executor = Mock()
        future.result.return_value = txid
        executor.submit.return_value = future
        mocked_thread.return_value = executor
        channel_id = chan['channel_id']
        request = pb.CloseChannelRequest(channel_id=channel_id, force=True)
        ctx = Mock()
        ctx.time_remaining.return_value = 10
        res = MOD.CloseChannel(request, ctx)
        executor.submit.assert_called_once_with(
            mocked_close,
            {'channel_point': chan['channel_point'], 'force': True})
        self.assertEqual(res.closing_txid, txid)
        mocked_check_par.assert_called_once_with(ctx, request, 'channel_id')
        # Correct case, mutual close
        reset_mocks(vars())
        request = pb.CloseChannelRequest(channel_id=channel_id)
        ctx = Mock()
        ctx.time_remaining.return_value = 10
        res = MOD.CloseChannel(request, ctx)
        self.assertEqual(res.closing_txid, txid)
        executor.submit.assert_called_once_with(
            mocked_close, {'channel_point': chan['channel_point']})
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
        # requested channel_id not found
        reset_mocks(vars())
        channel_id = fix.UNKNOWN_CHANNEL_ID
        request = pb.CloseChannelRequest(channel_id=channel_id)
        with self.assertRaises(Exception):
            MOD.CloseChannel(request, ctx)
        mocked_err().closechannel_failed.assert_called_once_with(ctx)
        assert not mocked_thread.called
        # list_channels fails
        reset_mocks(vars())
        err = 'error'
        ses.list_channels.return_value = err, True
        with self.assertRaises(Exception):
            MOD.CloseChannel(request, ctx)
        mocked_handle.assert_called_once_with(ctx, err)

    @patch(MOD.__name__ + '._get_channel_active', autospec=True)
    @patch(MOD.__name__ + '.convert', autospec=True)
    @patch(MOD.__name__ + '._get_channel_state', autospec=True)
    def test_add_channel(self, mocked_state, mocked_conv, mocked_act):
        # Add channel case
        response = pb.ListChannelsResponse()
        mocked_conv.return_value = 7
        ele_chan = fix.CHANNEL_OPEN
        mocked_state.return_value = pb.OPEN
        mocked_act.return_value = True
        res = MOD._add_channel(CTX, response, ele_chan, False)
        self.assertEqual(mocked_conv.call_count, 2)
        self.assertEqual(res, None)
        self.assertEqual(response.channels[0].remote_pubkey,
                         ele_chan['remote_pubkey'])
        self.assertEqual(response.channels[0].short_channel_id,
                         ele_chan['short_channel_id'])
        self.assertEqual(response.channels[0].channel_id,
                         ele_chan['channel_id'])
        self.assertEqual(response.channels[0].funding_txid,
                         ele_chan['channel_point'].split(':')[0])
        self.assertEqual(response.channels[0].local_balance,
                         mocked_conv.return_value)
        self.assertEqual(response.channels[0].remote_balance,
                         mocked_conv.return_value)
        self.assertEqual(response.channels[0].local_reserve_sat,
                         int(ele_chan['local_reserve']))
        self.assertEqual(response.channels[0].remote_reserve_sat,
                         int(ele_chan['remote_reserve']))
        self.assertEqual(response.channels[0].active, True)
        calls = [call(CTX, Enf.SATS, ele_chan['local_balance']),
                 call(CTX, Enf.SATS, ele_chan['remote_balance'])]
        mocked_conv.assert_has_calls(calls)
        self.assertEqual(response.channels[0].capacity,
                         mocked_conv.return_value * 2)
        self.assertEqual(response.channels[0].to_self_delay, 0)
        # edge cases
        reset_mocks(vars())
        response = pb.ListChannelsResponse()
        ele_chan = fix.CHANNEL_FORCE_CLOSING
        mocked_state.return_value = pb.PENDING_FORCE_CLOSE
        mocked_act.return_value = False
        res = MOD._add_channel(CTX, response, ele_chan, False)
        self.assertEqual(mocked_conv.call_count, 2)
        self.assertEqual(res, None)
        self.assertEqual(response.channels[0].short_channel_id, '')
        self.assertEqual(response.channels[0].channel_id,
                         ele_chan['channel_id'])
        self.assertEqual(response.channels[0].local_reserve_sat, 0)
        self.assertEqual(response.channels[0].remote_reserve_sat, 0)
        self.assertEqual(response.channels[0].active, False)
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

    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.ElectrumRPC')
    def test_close_channel(self, mocked_rpcses, mocked_log):
        ses = mocked_rpcses.return_value
        txid = 'txid'
        # Correct case
        ses.close_channel.return_value = txid, False
        ele_req = {'channel_point': 'cp'}
        res = MOD._close_channel(ele_req)
        self.assertEqual(res, txid)
        # Error response case
        reset_mocks(vars())
        ses.close_channel.return_value = fix.BADRESPONSE, True
        with self.assertRaises(RuntimeError):
            res = MOD._close_channel(ele_req)
            self.assertEqual(res, None)
        assert mocked_log.debug.called
        # RuntimeError case
        reset_mocks(vars())
        err = 'err'
        ses.close_channel.side_effect = RuntimeError(err)
        with self.assertRaises(RuntimeError):
            res = MOD._close_channel(ele_req)
        assert mocked_log.debug.called

    @patch(MOD.__name__ + '._get_invoice_state', autospec=True)
    @patch(MOD.__name__ + '.convert', autospec=True)
    def test_add_invoice(self, mocked_conv, mocked_get_state):
        # Correct case
        response = pb.ListInvoicesResponse()
        ele_inv = fix.LIST_INVOICES[0]
        MOD._add_invoice(CTX, response, ele_inv)
        mocked_conv.assert_called_once_with(CTX, Enf.SATS, ele_inv['amount'],
                                            max_precision=Enf.MSATS)
        mocked_get_state.assert_called_once_with(ele_inv)
        self.assertEqual(response.invoices[0].description, ele_inv['message'])
        # Invoice with no status
        reset_mocks(vars())
        response = pb.ListInvoicesResponse()
        ele_inv = fix.LIST_INVOICES[7]
        MOD._add_invoice(CTX, response, ele_inv)
        mocked_conv.assert_called_once_with(CTX, Enf.SATS, ele_inv['amount'],
                                            max_precision=Enf.MSATS)
        mocked_get_state.assert_called_once_with(ele_inv)
        # Empty invoice
        reset_mocks(vars())
        response = pb.ListInvoicesResponse()
        ele_inv = fix.EMPTY_INVOICE
        MOD._add_invoice(CTX, response, ele_inv)
        assert not mocked_conv.called
        mocked_get_state.assert_called_once_with(ele_inv)

    @patch(MOD.__name__ + '.convert', autospec=True)
    def test_add_payment(self, mocked_conv):
        # Full response
        response = pb.ListPaymentsResponse()
        ele_payment = fix.PAYMENTS[0]
        MOD._add_payment(CTX, response, ele_payment)
        self.assertEqual(response.payments[0].payment_hash,
                         ele_payment['payment_hash'])
        mocked_conv.assert_called_once_with(CTX, Enf.MSATS,
                                            -ele_payment['amount_msat'],
                                            max_precision=Enf.MSATS)
        # Non-ln payment case
        reset_mocks(vars())
        response = pb.ListPaymentsResponse()
        ele_payment = fix.PAYMENTS[1]
        MOD._add_payment(CTX, response, ele_payment)
        self.assertNotIn(fix.PAYMENTS[1]['type'],
                         [p['type'] for p in response.payments])
        assert not mocked_conv.called
        self.assertEqual(len(response.payments), 0)
        # Non outgoing payment case
        reset_mocks(vars())
        response = pb.ListPaymentsResponse()
        ele_payment = fix.PAYMENTS[2]
        MOD._add_payment(CTX, response, ele_payment)
        self.assertNotIn(fix.PAYMENTS[1]['direction'],
                         [p['direction'] for p in response.payments])
        assert not mocked_conv.called
        self.assertEqual(len(response.payments), 0)

    @patch(MOD.__name__ + '.convert', autospec=True)
    def test_add_transaction(self, mocked_conv):
        # Correct case
        response = pb.ListTransactionsResponse()
        tx = fix.LIST_TRANSACTIONS['transactions'][0]
        MOD._add_transaction(CTX, response, tx)
        mocked_conv.assert_called_once_with(CTX, Enf.BTC, tx['bc_value'],
                                            max_precision=Enf.SATS)
        self.assertEqual(response.transactions[0].txid, tx['txid'])
        # Empty payment
        reset_mocks(vars())
        response = pb.ListTransactionsResponse()
        MOD._add_transaction(CTX, response, fix.EMPTY_TX)
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

    @patch(MOD.__name__ + '._get_channel_state', autospec=True)
    def test_get_channel_active(self, mocked_state):
        # active case
        mocked_state.return_value = pb.OPEN
        ele_chan = fix.CHANNEL_OPEN
        res = MOD._get_channel_active(ele_chan)
        self.assertTrue(res)
        mocked_state.assert_called_once_with(ele_chan)
        # non-active case -- opening
        reset_mocks(vars())
        mocked_state.return_value = pb.PENDING_OPEN
        res = MOD._get_channel_active(ele_chan)
        assert not res
        mocked_state.assert_called_once_with(ele_chan)
        # non-active case -- peer disonnected
        reset_mocks(vars())
        mocked_state.return_value = pb.OPEN
        ele_chan = fix.CHANNEL_FORCE_CLOSING
        res = MOD._get_channel_active(ele_chan)
        assert not res
        assert not mocked_state.called
        # error case -- unknown peer state
        reset_mocks(vars())
        ele_chan['peer_state'] = "SOMETHING_WEIRD"
        res = MOD._get_channel_active(ele_chan)
        assert not res
        assert not mocked_state.called
        # error case -- lacking peer state
        reset_mocks(vars())
        ele_chan = {'foo': 'bar'}
        res = MOD._get_channel_active(ele_chan)
        assert not res
        assert not mocked_state.called

    def test_get_invoice_state(self):
        # Correct case: pending invoice
        invoice = fix.LIST_INVOICES[0]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.PENDING)
        # Correct case: expired invoice
        reset_mocks(vars())
        invoice = fix.LIST_INVOICES[1]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.EXPIRED)
        # Correct case: unknown state (sent but not propagated) -> pending
        reset_mocks(vars())
        invoice = fix.LIST_INVOICES[2]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.PENDING)
        # Correct case: paid invoice
        reset_mocks(vars())
        invoice = fix.LIST_INVOICES[3]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.PAID)
        # Correct case: invoice in flight -> pending
        reset_mocks(vars())
        invoice = fix.LIST_INVOICES[4]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.PENDING)
        # Correct case: invoice failed -> pending
        reset_mocks(vars())
        invoice = fix.LIST_INVOICES[5]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.UNKNOWN_INVOICE_STATE)
        # Correct case: invoice routing -> pending
        reset_mocks(vars())
        invoice = fix.LIST_INVOICES[6]
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.PENDING)
        # Invoice with no status case
        reset_mocks(vars())
        invoice = {'status': None}
        res = MOD._get_invoice_state(invoice)
        self.assertEqual(res, pb.UNKNOWN_INVOICE_STATE)

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
