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

""" Implementation of lighter.proto defined methods for electrum """

from ast import literal_eval
from decimal import Decimal
from json import dumps
from concurrent.futures import TimeoutError as TimeoutFutError, \
    ThreadPoolExecutor
from contextlib import ExitStack
from logging import getLogger

from . import lighter_pb2 as pb, settings
from .errors import Err
from .utils.bitcoin import convert, Enforcer as Enf, get_address_type, \
    get_channel_balances, has_amount_encoded
from .utils.db import session_scope
from .utils.misc import handle_thread, set_defaults
from .utils.network import check_req_params, get_thread_timeout, RPCSession, \
    FakeContext
from .utils.security import check_password, get_secret

LOGGER = getLogger(__name__)

ERRORS = {
    'Bad bech32 checksum': {
        'fun': 'invalid',
        'params': 'payment_request'
    },
    'Forbidden': {
        'fun': 'wrong_node_password'
    },
    'Invalid node ID, must be 33 bytes and hexadecimal': {
        'fun': 'invalid',
        'params': 'node_uri'
    },
    'wallet not loaded': {
        'fun': 'node_error'
    }
}

ELE_LN_TX = {'min_value': 1, 'max_value': 2**32, 'unit': Enf.SATS}


def get_settings(config, sec):
    """ Gets electrum settings """
    ele_values = ['ELE_HOST', 'ELE_PORT', 'ELE_USER']
    set_defaults(config, ele_values)
    settings.ELE_HOST = config.get(sec, 'ELE_HOST')
    settings.ELE_PORT = config.get(sec, 'ELE_PORT')
    settings.ELE_USER = config.get(sec, 'ELE_USER')
    settings.IMPL_SEC_TYPE = 'password'


def update_settings(password):
    """ Updates electrum specific settings """
    ele_pass = password.decode()
    settings.RPC_URL = 'http://{}:{}@{}:{}'.format(
        settings.ELE_USER, ele_pass, settings.ELE_HOST, settings.ELE_PORT)


def unlock_node(ctx, password, session=None):
    """ Unlocks node with password saved in lighter's DB """
    with ExitStack() if session else session_scope(ctx) as ses:
        if session:
            ses = session
        ele_pass = get_secret(ctx, ses, password, 'electrum', 'password')
        # update password, allowing to change it during lighter execution
        update_settings(ele_pass)
        rpc_ele = ElectrumRPC()
        ele_res, is_err = rpc_ele.load_wallet(ctx)
        if is_err:
            _handle_error(ctx, ele_res)


def UnlockNode(request, context):
    """ Tries to unlock node """
    check_req_params(context, request, 'password')
    response = pb.UnlockNodeResponse()
    with session_scope(context) as session:
        check_password(context, session, request.password)
        unlock_node(context, request.password, session=session)
    return response


def GetInfo(request, context):  # pylint: disable=unused-argument
    """ Returns info about the running LN node """
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.nodeid(context)
    if is_err:
        _handle_error(context, ele_res)
    response = pb.GetInfoResponse()
    if ele_res:
        if '@' in ele_res:
            response.node_uri = ele_res
            response.identity_pubkey = ele_res.split('@')[0]
        else:
            response.identity_pubkey = ele_res
    ele_res, is_err = rpc_ele.getinfo(context)
    if is_err:
        _handle_error(context, ele_res)
    if 'version' in ele_res:
        response.version = ele_res['version']
    if 'blockchain_height' in ele_res and ele_res['blockchain_height'] > 0:
        response.blockheight = ele_res['blockchain_height']
    if 'path' in ele_res and ele_res['path']:
        network = ele_res['path'].split('/')[-1]
        if network not in ('testnet', 'regtest', 'simnet'):
            response.network = 'mainnet'
        else:
            response.network = network
    return response


def NewAddress(request, context):
    """ Creates a new bitcoin address under control of the running LN node """
    rpc_ele = ElectrumRPC()
    response = pb.NewAddressResponse()
    ele_req = {'unused': True, 'receiving': True}
    ele_res, is_err = rpc_ele.listaddresses(context, ele_req)
    if is_err:
        _handle_error(context, ele_res)
    LOGGER.debug("Listaddress response: %s, %s", ele_res, is_err)
    if ele_res:
        addr_type = get_address_type(ele_res[0])
        LOGGER.debug("The address types are: %s, %s", addr_type, request.type)
        if addr_type != request.type:
            Err().unimplemented_param_value(
                context, 'type', pb.AddressType.Name(request.type))
        for addr in ele_res:
            if addr not in settings.ELE_RELEASED_ADDRESSES:
                settings.ELE_RELEASED_ADDRESSES.append(addr)
                response.address = addr
                break
    if not response.address:  # pylint: disable=no-member
        LOGGER.info("The list of addresses provided by the listaddresses "
                    "API is exhausted, re-using existing ones")
        settings.ELE_RELEASED_ADDRESSES = [ele_res[0]]
        response.address = ele_res[0]
    return response


def WalletBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the on-chain balance in bits of the running LN node """
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.getbalance(context)
    if is_err:
        _handle_error(context, ele_res)
    response = pb.WalletBalanceResponse()
    if 'confirmed' in ele_res:
        response.balance_confirmed = convert(
            context, Enf.BTC, ele_res['confirmed'])
        # pylint: disable=no-member
        response.balance = response.balance_confirmed
        # pylint: disable=no-member
        if 'unconfirmed' in ele_res:
            balance_btc = Decimal(ele_res['confirmed']) + \
                          Decimal(ele_res['unconfirmed'])
            response.balance = convert(context, Enf.BTC, balance_btc)
    return response


def ChannelBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the off-chain balance in bits available across all channels """
    # pylint: disable=no-member
    channels = ListChannels(pb.ListChannelsRequest(), context).channels
    # pylint: enable=no-member
    return get_channel_balances(context, channels)


def ListChannels(request, context):
    """ Returns a list of channels of the running LN node """
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.list_channels(context)
    if is_err:
        _handle_error(context, ele_res)
    response = pb.ListChannelsResponse()
    for ele_chan in ele_res:
        _add_channel(context, response, ele_chan, request.active_only)
    return response


# pylint: disable=too-many-branches
def ListInvoices(request, context):
    """ Returns a list of lightning invoices created by the running LN node """
    if not request.max_items:
        request.max_items = settings.MAX_INVOICES
    response = pb.ListInvoicesResponse()
    ele_req = {}
    ele_req['paid'] = request.paid
    ele_req['pending'] = request.pending
    ele_req['expired'] = request.expired
    filter_inv = True
    # Return unfiltered invoices list if no filter parameter is given
    if not any((getattr(request, f) for f in ('paid', 'pending', 'expired',
                                              'unknown'))):
        filter_inv = False
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.list_requests(context, ele_req)
    if is_err:
        _handle_error(context, ele_res)
    ele_res = sorted(
        ele_res, reverse=request.search_order, key=lambda t: t['time'])
    for ele_inv in ele_res:
        if request.search_timestamp and 'time' in ele_inv:
            inv_ts = ele_inv['time']
            if request.search_order and inv_ts > request.search_timestamp:
                continue
            if not request.search_order and inv_ts < request.search_timestamp:
                continue
        state = _get_invoice_state(ele_inv)
        if filter_inv:
            if not request.paid and state == pb.PAID:
                continue
            if not request.pending and state == pb.PENDING:
                continue
            if not request.expired and state == pb.EXPIRED:
                continue
            if not request.unknown and state == pb.UNKNOWN:
                continue
        _add_invoice(context, response, ele_inv)
        # pylint: disable=no-member
        if len(response.invoices) == request.max_items:
            break
    if request.list_order != request.search_order:
        # pylint: disable=no-member
        response.CopyFrom(pb.ListInvoicesResponse(
            invoices=reversed(response.invoices)))
    return response
# pylint: enable=too-many-branches


def ListPayments(_request, context):
    """ Returns a list of lightning invoices paid by the running LN node """
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.lightning_history(context)
    if is_err:
        _handle_error(context, ele_res)
    response = pb.ListPaymentsResponse()
    for ele_payment in ele_res:
        _add_payment(context, response, ele_payment)
    return response


def ListPeers(_request, context):
    """ Returns a list of peers connected to the running LN node """
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.list_peers(context)
    if is_err:
        _handle_error(context, ele_res)
    # pylint: disable=no-member
    response = pb.ListPeersResponse()
    for ele_peer in ele_res:
        peer = response.peers.add()
        if _def(ele_peer, 'address'):
            peer.address = ele_peer['address']
        if _def(ele_peer, 'node_id'):
            peer.pubkey = ele_peer['node_id']
        # alias and RGB color not available in electrum response
    return response


def ListTransactions(_request, context):
    """ Returns a list of on-chain transactions of the running LN node """
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.onchain_history(context)
    if is_err:
        _handle_error(context, ele_res)
    response = pb.ListTransactionsResponse()
    for ele_tx in ele_res['transactions']:
        _add_transaction(context, response, ele_tx)
    return response


def CreateInvoice(request, context):
    """ Creates a LN invoice (bolt 11 standard) """
    check_req_params(context, request, 'amount_bits')
    if request.min_final_cltv_expiry:
        Err().unimplemented_parameter(context, 'min_final_cltv_expiry')
    if request.fallback_addr:
        Err().unimplemented_parameter(context, 'fallback_addr')
    ele_req = {}
    if request.description:
        ele_req['memo'] = request.description
    ele_req['expiration'] = settings.EXPIRY_TIME
    if request.expiry_time:
        ele_req['expiration'] = request.expiry_time
    amount_btc = convert(context, Enf.BTC, request.amount_bits,
                         enforce=ELE_LN_TX)
    ele_req['amount'] = amount_btc
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.add_lightning_request(context, ele_req)
    if is_err:
        _handle_error(context, ele_res)
    response = pb.CreateInvoiceResponse()
    response.payment_request = ele_res
    return response


def CheckInvoice(request, context):
    """ Checks if a LN invoice has been paid """
    check_req_params(context, request, 'payment_hash')
    rpc_ele = ElectrumRPC()
    ele_req = {'key': request.payment_hash}
    ele_res, is_err = rpc_ele.getrequest(context, ele_req)
    if is_err:
        _handle_error(context, ele_res)
    response = pb.CheckInvoiceResponse()
    # pylint: disable=no-member
    response.state = _get_invoice_state(ele_res)
    if response.state == pb.PAID:
        response.settled = True
    return response


def PayInvoice(request, context):
    """
    Tries to pay a LN invoice from its payment request (bolt 11 standard)
    Electrum doesn't currently support the payment of invoices:
    - with amount not set (or 0)
    - with description_hash encoded (description needed to decode/pay invoice)
    - that set a custom expiry (cltv_expiry_delta) for the payment
    """
    check_req_params(context, request, 'payment_request')
    amount_encoded = has_amount_encoded(request.payment_request)
    if amount_encoded and request.amount_bits:
        Err().unsettable(context, 'amount_bits')
    if request.amount_bits:
        Err().unimplemented_parameter(context, 'amount_bits')
    if not amount_encoded:
        Err().amount_required(context)
    if request.description:
        Err().unimplemented_parameter(context, 'description')
    if request.cltv_expiry_delta:
        Err().unimplemented_parameter(context, 'cltv_expiry_delta')
    rpc_ele = ElectrumRPC()
    ele_req = {'invoice': request.payment_request}
    ele_res, is_err = rpc_ele.lnpay(context, ele_req)
    if is_err:
        _handle_error(context, ele_res)
    elif not _def(ele_res, 'success'):
        Err().payinvoice_failed(context)
    response = pb.PayInvoiceResponse()
    response.payment_preimage = ele_res['preimage']
    return response


def PayOnChain(request, context):
    """ Tries to pay a bitcoin address """
    check_req_params(context, request, 'address', 'amount_bits')
    ele_req = {'destination': request.address}
    ele_req['amount'] = convert(context, Enf.BTC, request.amount_bits,
                                enforce=Enf.OC_TX)
    if request.fee_sat_byte:
        if Enf.check_value(context, request.fee_sat_byte, enforce=Enf.OC_FEE):
            ele_req['feerate'] = request.fee_sat_byte
        else:
            Err().out_of_range(context, 'fee_sat_byte')
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.payto(context, ele_req)
    if is_err:
        _handle_error(context, ele_res)
    ele_req = {'tx': ele_res}
    ele_res, is_err = rpc_ele.broadcast(context, ele_req)
    if is_err:
        _handle_error(context, ele_res)
    response = pb.PayOnChainResponse()
    response.txid = ele_res
    return response


def DecodeInvoice(request, context):
    """ Tries to return information of a LN invoice from its payment request
        (bolt 11 standard) """
    check_req_params(context, request, 'payment_request')
    ele_req = {'invoice': request.payment_request}
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.decode_invoice(context, ele_req)
    if is_err:
        _handle_error(context, ele_res)
    response = pb.DecodeInvoiceResponse()
    if _def(ele_res, 'amount'):
        response.amount_bits = convert(context, Enf.SATS, ele_res['amount'])
    if _def(ele_res, 'time'):
        response.timestamp = ele_res['time']
    if _def(ele_res, 'rhash'):
        response.payment_hash = ele_res['rhash']
    if _def(ele_res, 'pubkey'):
        response.destination_pubkey = ele_res['pubkey']
    if _def(ele_res, 'message'):
        response.description = ele_res['message']
    if _def(ele_res, 'exp'):
        response.expiry_time = ele_res['exp']
    return response


def OpenChannel(request, context):
    """ Tries to connect and open a channel with a peer """
    check_req_params(context, request, 'node_uri', 'funding_bits')
    if not request.private:
        Err().unimplemented_param_value(context, 'private', 'False')
    rpc_ele = ElectrumRPC()
    response = pb.OpenChannelResponse()
    ele_req = {"connection_string": request.node_uri}
    amount_btc = convert(context, Enf.BTC, request.funding_bits,
                         enforce=Enf.FUNDING_SATOSHIS)
    ele_req["amount"] = amount_btc
    if request.push_bits:
        if request.push_bits >= request.funding_bits:
            Err().value_too_high(context, 'push_bits', request.push_bits)
        push_btc = convert(context, Enf.BTC, request.push_bits,
                           enforce=Enf.PUSH_MSAT, max_precision=Enf.SATS)
        ele_req["push_amount"] = push_btc
    ele_res, is_err = rpc_ele.open_channel(context, ele_req)
    if is_err:
        _handle_error(context, ele_res)
    response.funding_txid = ele_res.split(":")[0]
    return response


def CloseChannel(request, context):
    """ Tries to close a LN channel """
    check_req_params(context, request, 'channel_id')
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.list_channels(context)
    if is_err:
        _handle_error(context, ele_res)
    ele_req = {}
    for ele_chan in ele_res:
        if ('channel_id' in ele_chan
                and ele_chan['channel_id'] == request.channel_id):
            ele_req['channel_point'] = ele_chan['channel_point']
    if 'channel_point' not in ele_req:
        Err().closechannel_failed(context)
    if request.force:
        ele_req['force'] = True
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_close_channel, ele_req)
    response = pb.CloseChannelResponse()
    try:
        ele_res = future.result(timeout=get_thread_timeout(context))
        if ele_res:
            response.closing_txid = ele_res
            return response
    except RuntimeError as ele_err:
        try:
            error = literal_eval(str(ele_err))
            _handle_error(context, error)
        except (SyntaxError, ValueError):
            Err().report_error(context, str(ele_err))
    except TimeoutFutError:
        executor.shutdown(wait=False)
    return response


def _add_channel(context, response, ele_chan, active_only):
    """ Adds a channel to a ListChannelsResponse """
    state = _get_channel_state(ele_chan)
    if active_only and state != pb.OPEN:
        return
    grpc_chan = response.channels.add()
    grpc_chan.state = state
    if 'remote_pubkey' in ele_chan:
        grpc_chan.remote_pubkey = ele_chan['remote_pubkey']
    if _def(ele_chan, 'short_channel_id'):
        grpc_chan.short_channel_id = ele_chan['short_channel_id']
    if _def(ele_chan, 'channel_id'):
        grpc_chan.channel_id = ele_chan['channel_id']
    if 'channel_point' in ele_chan:
        grpc_chan.funding_txid = ele_chan['channel_point'].split(':')[0]
    if 'local_balance' in ele_chan:
        grpc_chan.local_balance = convert(
            context, Enf.SATS, ele_chan['local_balance'])
    if 'remote_balance' in ele_chan:
        grpc_chan.remote_balance = convert(
            context, Enf.SATS, ele_chan['remote_balance'])
    if 'local_balance' in ele_chan and 'remote_balance' in ele_chan:
        grpc_chan.capacity = grpc_chan.remote_balance + grpc_chan.local_balance
    if _def(ele_chan, 'local_reserve'):
        grpc_chan.local_reserve_sat = int(ele_chan['local_reserve'])
    if _def(ele_chan, 'remote_reserve'):
        grpc_chan.remote_reserve_sat = int(ele_chan['remote_reserve'])
    if _def(ele_chan, 'peer_state'):
        grpc_chan.active = _get_channel_active(ele_chan)


def _add_invoice(context, response, ele_inv):
    """ Adds an invoice to a ListInvoicesResponse """
    invoice = response.invoices.add()
    if 'amount' in ele_inv:
        invoice.amount_bits = convert(
            context, Enf.SATS, ele_inv['amount'], max_precision=Enf.MSATS)
    if 'time' in ele_inv:
        invoice.timestamp = ele_inv['time']
        if 'exp' in ele_inv:
            invoice.expiry_time = ele_inv['time'] + ele_inv['exp']
    if 'rhash' in ele_inv:
        invoice.payment_hash = ele_inv['rhash']
    if 'message' in ele_inv:
        invoice.description = ele_inv['message']
    invoice.state = _get_invoice_state(ele_inv)
    if 'invoice' in ele_inv:
        invoice.payment_request = ele_inv['invoice']


def _add_payment(context, response, ele_payment):
    """ Adds a payment to a ListPaymentsResponse """
    if (ele_payment['type'] == 'payment'
            and ele_payment['direction'] == 'sent'):
        grpc_payment = response.payments.add()
        if 'payment_hash' in ele_payment:
            grpc_payment.payment_hash = ele_payment['payment_hash']
        if 'amount_msat' in ele_payment:
            grpc_payment.amount_bits = convert(
                context, Enf.MSATS, -ele_payment['amount_msat'],
                max_precision=Enf.MSATS)
        if "timestamp" in ele_payment:
            grpc_payment.timestamp = ele_payment['timestamp']
        if 'fee_msat' in ele_payment:
            grpc_payment.fee_base_msat = ele_payment['fee_msat']
        if 'preimage' in ele_payment:
            grpc_payment.payment_preimage = ele_payment['preimage']


def _add_transaction(context, response, ele_tx):
    """ Adds a transaction to a ListTransactionsResponse """
    transaction = response.transactions.add()
    if 'txid' in ele_tx:
        transaction.txid = ele_tx['txid']
    if 'bc_value' in ele_tx:
        transaction.amount_bits = convert(
            context, Enf.BTC, ele_tx['bc_value'], max_precision=Enf.SATS)
    if 'confirmations' in ele_tx:
        transaction.num_confirmations = ele_tx['confirmations']
    if 'height' in ele_tx:
        blockheight = ele_tx['height']
        transaction.blockheight = blockheight if blockheight > 0 else 0
    if _def(ele_tx, 'timestamp'):
        transaction.timestamp = ele_tx['timestamp']
    if 'fee_sat' in ele_tx:
        transaction.fee_sat = ele_tx['fee_sat'] if ele_tx['fee_sat'] is int \
                              else 0


def _def(dictionary, key):
    """ Checks if key is in dictionary and that it's not None """
    return key in dictionary and dictionary[key] is not None


@handle_thread
def _close_channel(ele_req):
    """ Returns close channel response or raises exception to caller """
    rpc_ele = ElectrumRPC()
    ele_res = error = None
    try:
        ele_res, is_err = rpc_ele.close_channel(FakeContext(), ele_req)
        if is_err:
            error = ele_res
        else:
            LOGGER.debug('[ASYNC] CloseChannel terminated with response: %s',
                         ele_res)
    except RuntimeError as err:
        error = str(err)
    if error:
        LOGGER.debug('[ASYNC] CloseChannel terminated with error: %s', error)
        raise RuntimeError(error)
    return ele_res


def _get_channel_state(ele_chan):  # pylint: disable=too-many-return-statements
    """
    Maps implementation's channel state to lighter's channel state definition
    """
    if 'state' in ele_chan:
        ele_state = ele_chan['state']
        if ele_state in ('CLOSED', 'REDEEMED', 'PREOPENING',):
            return -1
        if ele_state in ('OPENING', 'FUNDED',):
            return pb.PENDING_OPEN
        if ele_state in ('OPEN',):
            return pb.OPEN
        if ele_state in ('FORCE_CLOSING',):
            return pb.PENDING_FORCE_CLOSE
        if ele_state in ('CLOSING',):
            return pb.PENDING_MUTUAL_CLOSE
    return pb.UNKNOWN


def _get_channel_active(ele_chan):
    """
    Maps implementation's peer state to lighter's active field
    """
    return (_def(ele_chan, 'peer_state') and
            ele_chan['peer_state'] == 'GOOD' and
            _get_channel_state(ele_chan) == pb.OPEN)


def _get_invoice_state(ele_inv):
    """
    Maps electrum invoice state to the InvoiceState proto enum

    States of electrum payment requests:
    PR_UNPAID   = 0
    PR_EXPIRED  = 1
    PR_UNKNOWN  = 2     # sent but not propagated
    PR_PAID     = 3     # send and propagated
    PR_INFLIGHT = 4     # unconfirmed
    PR_FAILED   = 5
    PR_ROUTING  = 6
    """
    if _def(ele_inv, 'status'):
        state = ele_inv['status']
        if state in (3,):
            return pb.PAID
        if state in (0, 2, 4, 6,):
            return pb.PENDING
        if state in (1,):
            return pb.EXPIRED
    return pb.UNKNOWN_INVOICE_STATE


def _handle_error(context, ele_res):
    """ Reports errors of an electrum rpc response """
    Err().report_error(context, ele_res)


class ElectrumRPC(RPCSession):
    """ Creates and mantains an RPC session with electrum """

    def __init__(self):
        super().__init__(headers={'content-type': 'application/json'})

    def __getattr__(self, name):

        def call_adapter(context, params=None, timeout=None):
            if not params:
                params = {}
            payload = dumps(
                {"id": self._id_count, "method": name,
                 "params": params, "jsonrpc": self._jsonrpc_ver})
            LOGGER.debug("RPC req: %s", payload)
            return super(ElectrumRPC, self).call(context, payload,
                                                 timeout=timeout)

        return call_adapter
