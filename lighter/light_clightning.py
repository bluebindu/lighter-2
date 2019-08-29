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

""" Implementation of lighter.proto defined methods for c-lightning """

from ast import literal_eval
from concurrent.futures import TimeoutError as TimeoutFutError, \
    ThreadPoolExecutor
from datetime import datetime
from logging import getLogger
from os import environ, path

from . import lighter_pb2 as pb
from . import settings
from .utils import check_req_params, command, convert, Enforcer as Enf, \
    FakeContext, get_channel_balances, get_thread_timeout, get_node_timeout, \
    handle_thread, has_amount_encoded
from .errors import Err

LOGGER = getLogger(__name__)

ERRORS = {
    'Bad bech32 string': {
        'fun': 'invalid',
        'params': 'payment_request'
    },
    'Cannot afford transaction': {
        'fun': 'insufficient_funds'
    },
    'Channel ID not found': {
        'fun': 'invalid',
        'params': 'channel_id'
    },
    'Connection refused': {
        'fun': 'node_error'
    },
    'Could not find a route': {
        'fun': 'route_not_found'
    },
    'does not match description': {
        'fun': 'incorrect_description'
    },
    'Exchanging init messages: Operation now in progress': {
        'fun': 'connect_failed'
    },
    'Fallback address does not match our network': {
        'fun': 'invalid',
        'params': 'fallback_addr'
    },
    'Fallback address not valid': {
        'fun': 'invalid',
        'params': 'fallback_addr'
    },
    'Given id is not a channel ID or short channel ID': {
        'fun': 'invalid',
        'params': 'channel_id'
    },
    # this error happens when giving a short fallback address (e.g. "sd")
    'Incorrect \'id\' in response': {
        'fun': 'invalid',
        'params': 'fallback_addr'
    },
    'Invoice expired': {
        'fun': 'invoice_expired',
    },
    'msatoshi parameter required': {
        'fun': 'amount_required'
    },
    'no description to check': {
        'fun': 'missing_parameter',
        'params': 'description'
    },
    'Parsing accept_channel': {
        'fun': 'openchannel_failed'
    },
    'Peer already': {
        'fun': 'openchannel_failed'
    },
    'They sent error': {
        'fun': 'openchannel_failed'
    }
}


def update_settings(_dummy):
    """
    Updates c-lightning specific settings

    KeyError exception raised by missing dictionary keys in environ
    are left unhandled on purpose and later catched by lighter.start()
    """
    cl_cli_dir = environ['CL_CLI_DIR']
    cl_cli = environ['CL_CLI']
    cl_cli_path = path.join(cl_cli_dir, cl_cli)
    cl_rpc_dir = environ['CL_RPC_DIR']
    cl_rpc = environ['CL_RPC']
    cl_options = [
        '--lightning-dir={}'.format(cl_rpc_dir),
        '--rpc-file={}'.format(cl_rpc), '-k'
    ]
    settings.CMD_BASE = [cl_cli_path] + cl_options


def GetInfo(request, context):  # pylint: disable=unused-argument
    """ Returns info about the running LN node """
    cl_req = ['getinfo']
    cl_res = command(context, *cl_req)
    response = pb.GetInfoResponse()
    if 'id' in cl_res:
        response.identity_pubkey = cl_res['id']
        if 'address' in cl_res:
            address = cl_res['address'][0]
            if 'address' in address and 'port' in address:
                response.node_uri = '{}@{}:{}'.format(
                    cl_res['id'], address['address'], address['port'])
    if 'alias' in cl_res:
        response.alias = cl_res['alias']
    if 'color' in cl_res:
        response.color = '#{}'.format(cl_res['color'])
    if 'version' in cl_res:
        response.version = cl_res['version']
    if 'blockheight' in cl_res:
        response.blockheight = int(cl_res['blockheight'])
    if 'network' in cl_res:
        response.network = cl_res['network']
        if cl_res['network'] == 'bitcoin':
            response.network = 'mainnet'
    _handle_error(context, cl_res, always_abort=False)
    return response


def NewAddress(request, context):
    """ Creates a new bitcoin address under control of the running LN node """
    cl_req = ['newaddr']
    response = pb.NewAddressResponse()
    # If request has no addresstype, default for c-lightning is p2sh-segwit
    if request.type == 0:
        cl_req.append('addresstype=p2sh-segwit')
    elif request.type == 1:
        cl_req.append('addresstype=bech32')
    cl_res = command(context, *cl_req)
    if 'p2sh-segwit' in cl_res:
        response.address = cl_res['p2sh-segwit']
    if 'bech32' in cl_res:
        response.address = cl_res['bech32']
    _handle_error(context, cl_res, always_abort=False)
    return response


def WalletBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the on-chain balance in bits of the running LN node """
    cl_req = ['listfunds']
    cl_res = command(context, *cl_req)
    _handle_error(context, cl_res, always_abort=False)
    tot_funds = 0.0
    conf_funds = 0.0
    if 'outputs' in cl_res:
        for output in cl_res['outputs']:
            if 'value' in output:
                tot_funds += output['value']
            if 'value' in output and 'status' in output and \
                    output['status'] == 'confirmed':
                conf_funds += output['value']
    return pb.WalletBalanceResponse(
        balance=convert(context, Enf.SATS, tot_funds),
        balance_confirmed=convert(context, Enf.SATS, conf_funds))


def ChannelBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the off-chain balance in bits available across all channels """
    # pylint: disable=no-member
    channels = ListChannels(pb.ListChannelsRequest(), context).channels
    return get_channel_balances(context, channels)


def ListChannels(request, context):
    """ Returns a list of channels of the running LN node """
    cl_req = ['listpeers']
    cl_res = command(context, *cl_req)
    response = pb.ListChannelsResponse()
    if 'peers' in cl_res:  # pylint: disable=too-many-nested-blocks
        for cl_peer in cl_res['peers']:
            if 'channels' in cl_peer:
                for cl_chan in cl_peer['channels']:
                    state = None
                    if 'state' in cl_chan and 'status' in cl_chan:
                        state = _get_state(cl_chan)
                        if state < 0:
                            continue
                    _add_channel(context, response, cl_peer, cl_chan,
                                 state, request.active_only)
    _handle_error(context, cl_res, always_abort=False)
    return response


def ListPayments(request, context):  # pylint: disable=unused-argument
    """ Returns a list of lightning invoices paid by the running LN node """
    cl_req = ['listsendpays']
    cl_res = command(context, *cl_req)
    response = pb.ListPaymentsResponse()
    if 'payments' in cl_res:
        for cl_payment in cl_res['payments']:
            _add_payment(context, response, cl_payment)
    _handle_error(context, cl_res, always_abort=False)
    return response


def ListPeers(request, context):  # pylint: disable=unused-argument
    """ Returns a list of peers connected to the running LN node """
    cl_req = ['listpeers']
    cl_res = command(context, *cl_req)
    _handle_error(context, cl_res, always_abort=False)
    response = pb.ListPeersResponse()
    if 'peers' in cl_res:
        for peer in cl_res['peers']:
            # Filtering disconnected peers
            if 'connected' in peer and peer['connected'] is False:
                continue
            grpc_peer = response.peers.add()  # pylint: disable=no-member
            if 'id' in peer:
                grpc_peer.pubkey = peer['id']
                cl_req = ['listnodes', 'id={}'.format(peer['id'])]
                cl_res = command(context, *cl_req)
                if 'nodes' in cl_res:
                    node = cl_res['nodes'][0]
                    if 'alias' in node:
                        grpc_peer.alias = node['alias']
                    if 'color' in node:
                        grpc_peer.color = '#{}'.format(node['color'])
            if 'netaddr' in peer:
                address = []
                for addr in peer['netaddr']:
                    address.append(addr)
                grpc_peer.address = ' + '.join(address)
    return response


def CreateInvoice(request, context):
    """ Creates a LN invoice (bolt 11 standard) """
    cl_req = ['invoice']
    if request.min_final_cltv_expiry:
        Err().unimplemented_parameter(context, 'min_final_cltv_expiry')
    if request.amount_bits:
        cl_req.append('msatoshi="{}"'.format(
            convert(
                context, Enf.MSATS, request.amount_bits,
                enforce=Enf.LN_PAYREQ)))
    else:
        cl_req.append('msatoshi="any"')
    description = ''
    if request.description:
        description = request.description
    cl_req.append('description="{}"'.format(description))
    label = _create_label()
    cl_req.append('label="{}"'.format(label))
    if request.expiry_time:
        cl_req.append('expiry="{}"'.format(request.expiry_time))
    if request.fallback_addr:
        cl_req.append('fallbacks=["{}"]'.format(request.fallback_addr))
    cl_res = command(context, *cl_req)
    response = pb.CreateInvoiceResponse()
    if 'payment_hash' in cl_res:
        response.payment_hash = cl_res['payment_hash']
    if 'bolt11' in cl_res:
        response.payment_request = cl_res['bolt11']
    if 'expires_at' in cl_res:
        response.expires_at = cl_res['expires_at']
    _handle_error(context, cl_res, always_abort=False)
    return response


def CheckInvoice(request, context):
    """ Checks if a LN invoice has been paid """
    cl_req = ['listinvoices']
    check_req_params(context, request, 'payment_hash')
    settled = False
    invoice = None
    cl_res = command(context, *cl_req)
    if 'invoices' in cl_res:
        for inv in cl_res['invoices']:
            if 'payment_hash' in inv \
                    and inv['payment_hash'] == request.payment_hash:
                invoice = inv
    if not invoice:
        _handle_error(context, cl_res, always_abort=False)
        Err().invoice_not_found(context)
    response = pb.CheckInvoiceResponse()
    if 'status' in invoice:
        if invoice['status'] == "paid":
            settled = True
        response.settled = settled
    return response


def PayInvoice(request, context):
    """
    Tries to pay a LN invoice from its payment request (bolt 11 standard)
    An amount can be specified if the invoice doesn't already have it included
    If a description hash is included in the invoice, its preimage must be
    included in the request
    """
    cl_req = ['pay']
    check_req_params(context, request, 'payment_request')
    cl_req.append('bolt11="{}"'.format(request.payment_request))
    amount_encoded = has_amount_encoded(request.payment_request)
    # pylint: disable=no-member
    if amount_encoded and request.amount_bits:
        Err().unsettable(context, 'amount_bits')
    elif request.amount_bits and not amount_encoded:
        cl_req.append('msatoshi="{}"'.format(
            convert(
                context, Enf.MSATS, request.amount_bits,
                enforce=Enf.LN_TX)))
    elif not amount_encoded:
        check_req_params(context, request, 'amount_bits')
    # pylint: enable=no-member
    if request.description:
        cl_req.append('description="{}"'.format(request.description))
    if request.cltv_expiry_delta:
        if Enf.check_value(
                context, request.cltv_expiry_delta,
                enforce=Enf.CLTV_EXPIRY_DELTA):
            cl_req.append('maxdelay="{}"'.format(request.cltv_expiry_delta))
        else:
            Err().out_of_range(context, 'cltv_expiry_delta')
    cl_res = command(context, *cl_req)
    response = pb.PayInvoiceResponse()
    if 'payment_preimage' in cl_res:
        response.payment_preimage = cl_res['payment_preimage']
    _handle_error(context, cl_res, always_abort=False)
    return response


def PayOnChain(request, context):
    """ Tries to pay a bitcoin address """
    cl_req = ['withdraw']
    check_req_params(context, request, 'address', 'amount_bits')
    cl_req.append('destination="{}"'.format(request.address))
    cl_req.append('satoshi="{}"'.format(
        convert(context, Enf.SATS, request.amount_bits, enforce=Enf.OC_TX,
                max_precision=Enf.SATS)))
    if request.fee_sat_byte:
        if Enf.check_value(
                context, request.fee_sat_byte, enforce=Enf.OC_FEE):
            cl_req.append(
                'feerate="{}perkb"'.format(request.fee_sat_byte * 1000))
        else:
            Err().out_of_range(context, 'fee_sat_byte')
    cl_res = command(context, *cl_req)
    response = pb.PayOnChainResponse()
    if 'txid' in cl_res:
        response.txid = cl_res['txid']
    _handle_error(context, cl_res, always_abort=False)
    return response


def DecodeInvoice(request, context):  # pylint: disable=too-many-branches
    """
    Tries to return information of a LN invoice from its payment request
    (bolt 11 standard)
    """
    cl_req = ['decodepay']
    response = pb.DecodeInvoiceResponse()
    check_req_params(context, request, 'payment_request')
    cl_req.append('bolt11="{}"'.format(request.payment_request))
    if request.description:
        cl_req.append('description="{}"'.format(request.description))
    cl_res = command(context, *cl_req)
    response = pb.DecodeInvoiceResponse()
    if 'msatoshi' in cl_res:
        response.amount_bits = convert(context, Enf.MSATS, cl_res['msatoshi'])
    if 'created_at' in cl_res:
        response.timestamp = cl_res['created_at']
    if 'payment_hash' in cl_res:
        response.payment_hash = cl_res['payment_hash']
    if 'description' in cl_res:
        response.description = cl_res['description']
    if 'payee' in cl_res:
        response.destination_pubkey = cl_res['payee']
    if 'description_hash' in cl_res:
        response.description_hash = cl_res['description_hash']
    if 'expiry' in cl_res:
        response.expiry_time = cl_res['expiry']
    if 'min_final_cltv_expiry' in cl_res:
        response.min_final_cltv_expiry = cl_res['min_final_cltv_expiry']
    if 'fallbacks' in cl_res and 'addr' in cl_res['fallbacks'][0]:
        response.fallback_addr = cl_res['fallbacks'][0]['addr']
    if 'routes' in cl_res:
        for cl_route in cl_res['routes']:
            _add_route_hint(response, cl_route)
    _handle_error(context, cl_res, always_abort=False)
    return response


def OpenChannel(request, context):
    """ Tries to connect and open a channel with a peer """
    cl_req = ['connect']
    response = pb.OpenChannelResponse()
    check_req_params(context, request, 'node_uri', 'funding_bits')
    if request.push_bits:
        Err().unimplemented_parameter(context, 'push_bits')
    try:
        pubkey, _host = request.node_uri.split("@")
    except ValueError:
        Err().invalid(context, 'node_uri')
    cl_req.append('id="{}"'.format(request.node_uri))
    cl_res = command(context, *cl_req)
    if 'id' not in cl_res:
        Err().connect_failed(context)
    cl_req = ['fundchannel']
    cl_req.append('id="{}"'.format(pubkey))
    cl_req.append('satoshi="{}"'.format(
        convert(context, Enf.SATS, request.funding_bits,
                enforce=Enf.FUNDING_SATOSHIS, max_precision=Enf.SATS)))
    if request.private:
        cl_req.append('announce=false')
    cl_res = command(context, *cl_req)
    if 'txid' in cl_res:
        response.funding_txid = cl_res['txid']
    _handle_error(context, cl_res, always_abort=False)
    return response


def CloseChannel(request, context):
    """ Tries to close a LN chanel """
    cl_req = ['close']
    check_req_params(context, request, 'channel_id')
    cl_req.append('id="{}"'.format(request.channel_id))
    response = pb.CloseChannelResponse()
    close_timeout = get_node_timeout(
        context, min_time=settings.CLOSE_TIMEOUT_NODE)
    if request.force:
        cl_req.append('force=true')
        # setting a zero timeout to force an immediate unilateral close
        cl_req.append('timeout=0')
    else:
        cl_req.append('timeout={}'.format(close_timeout))
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_close_channel, cl_req, close_timeout)
    try:
        cl_res = future.result(timeout=get_thread_timeout(context))
        if cl_res:
            if 'txid' in cl_res:
                response.closing_txid = cl_res['txid']
            return response
    except RuntimeError as cl_err:
        try:
            error = literal_eval(str(cl_err))
            _handle_error(context, error)
        except (SyntaxError, ValueError):
            Err().report_error(context, str(cl_err))
    except TimeoutFutError:
        executor.shutdown(wait=False)
    return pb.CloseChannelResponse()


# pylint: disable=too-many-arguments,too-many-branches
def _add_channel(context, response, cl_peer, cl_chan, state, active_only):
    """ Adds a channel to a ListChannelsResponse """
    connected = True
    if 'connected' in cl_peer:
        connected = cl_peer['connected']
    if active_only and (not connected or state != pb.OPEN):
        return
    grpc_chan = response.channels.add()
    grpc_chan.active = connected and state == pb.OPEN
    if state:
        grpc_chan.state = state
    if 'id' in cl_peer:
        grpc_chan.remote_pubkey = cl_peer['id']
    if 'short_channel_id' in cl_chan:
        grpc_chan.short_channel_id = cl_chan['short_channel_id']
    if 'channel_id' in cl_chan:
        grpc_chan.channel_id = cl_chan['channel_id']
    if 'funding_txid' in cl_chan:
        grpc_chan.funding_txid = cl_chan['funding_txid']
    if 'our_to_self_delay' in cl_chan:
        grpc_chan.to_self_delay = int(cl_chan['our_to_self_delay'])
    if 'msatoshi_total' in cl_chan:
        grpc_chan.capacity = convert(context, Enf.MSATS,
                                     cl_chan['msatoshi_total'])
    if 'msatoshi_to_us' in cl_chan:
        grpc_chan.local_balance = convert(context, Enf.MSATS,
                                          cl_chan['msatoshi_to_us'])
    if grpc_chan.capacity and grpc_chan.local_balance is not None:
        grpc_chan.remote_balance = grpc_chan.capacity - grpc_chan.local_balance
    if 'private' in cl_chan:
        grpc_chan.private = cl_chan['private']
    if 'our_channel_reserve_satoshis' in cl_chan:
        grpc_chan.local_reserve_sat = cl_chan['our_channel_reserve_satoshis']
    if 'their_channel_reserve_satoshis' in cl_chan:
        grpc_chan.remote_reserve_sat = \
            cl_chan['their_channel_reserve_satoshis']
    # pylint: enable=too-many-arguments


def _add_payment(context, response, cl_payment):
    """ Adds a payment to a ListPaymentsResponse """
    if 'status' in cl_payment and cl_payment['status'] == 'failed':
        return
    grpc_payment = response.payments.add()
    if 'payment_hash' in cl_payment:
        grpc_payment.payment_hash = cl_payment['payment_hash']
    if 'msatoshi_sent' in cl_payment:
        grpc_payment.amount_bits = convert(
            context, Enf.MSATS, cl_payment['msatoshi_sent'])
    if 'created_at' in cl_payment:
        grpc_payment.timestamp = cl_payment['created_at']
    if 'msatoshi' in cl_payment and 'msatoshi_sent' in cl_payment:
        grpc_payment.fee_base_msat = \
            cl_payment['msatoshi_sent'] - cl_payment['msatoshi']
    if 'payment_preimage' in cl_payment:
        grpc_payment.payment_preimage = cl_payment['payment_preimage']


def _add_route_hint(response, cl_route):
    """ Adds a route hint and its hop hints to a DecodeInvoiceResponse """
    grpc_route = response.route_hints.add()
    for cl_hop in cl_route:
        grpc_hop = grpc_route.hop_hints.add()
        if 'pubkey' in cl_hop:
            grpc_hop.pubkey = cl_hop['pubkey']
        if 'short_channel_id' in cl_hop:
            grpc_hop.short_channel_id = cl_hop['short_channel_id']
        if 'fee_base_msat' in cl_hop:
            grpc_hop.fee_base_msat = cl_hop['fee_base_msat']
        if 'fee_proportional_millionths' in cl_hop:
            grpc_hop.fee_proportional_millionths = cl_hop[
                'fee_proportional_millionths']
        if 'cltv_expiry_delta' in cl_hop:
            grpc_hop.cltv_expiry_delta = cl_hop['cltv_expiry_delta']


@handle_thread
def _close_channel(cl_req, close_timeout):
    """ Returns close channel response or raises exception to caller """
    cl_res = error = None
    try:
        # adding a little delay to allow implementation to answer before
        # command times out
        cl_res = command(FakeContext(), *cl_req, timeout=close_timeout + 0.1)
        if 'message' in cl_res and 'code' in cl_res:
            error = cl_res['message']
        else:
            LOGGER.debug('[ASYNC] CloseChannel terminated with response: %s',
                         cl_res)
    except RuntimeError as err:
        error = str(err)
    if error:
        LOGGER.debug('[ASYNC] CloseChannel terminated with error: %s', error)
        raise RuntimeError(error)
    return cl_res


def _create_label():
    """ Creates a label using microseconds (c-lightning specific) """
    microseconds = datetime.now().timestamp() * 1e6
    return '{}'.format(int(microseconds))


def _get_state(cl_chan):  # pylint: disable=too-many-return-statements
    """
    Maps implementation's channel state to lighter's channel state definition
    """
    cl_state = cl_chan['state']
    cl_status = cl_chan['status']
    if cl_state in ('CLOSED',):
        return -1
    for detail in cl_status:
        if 'ONCHAIN:All outputs resolved:' in detail:
            return -1
    if cl_state in ('CHANNELD_AWAITING_LOCKIN',):
        return pb.PENDING_OPEN
    if cl_state in ('CHANNELD_NORMAL',):
        return pb.OPEN
    for detail in cl_status:
        if 'ONCHAIN:Tracking mutual close transaction' in detail:
            return pb.PENDING_MUTUAL_CLOSE
        if 'ONCHAIN:Tracking our own unilateral close' in detail or \
                'ONCHAIN:2 outputs unresolved:' in detail or \
                'ONCHAIN:1 outputs unresolved:' in detail or \
                'ONCHAIN:Tracking their unilateral close' in detail:
            return pb.PENDING_FORCE_CLOSE
    if cl_state in ('CHANNELD_SHUTTING_DOWN', 'CLOSINGD_SIGEXCHANGE',
                    'CLOSINGD_COMPLETE'):
        return pb.PENDING_MUTUAL_CLOSE
    if cl_state in ('ONCHAIN', 'AWAITING_UNILATERAL', 'FUNDING_SPEND_SEEN'):
        return pb.PENDING_FORCE_CLOSE
    return pb.UNKNOWN


def _handle_error(context, cl_res, always_abort=True):
    """ Checks for errors in a c-lightning cli response """
    if 'code' in cl_res and 'message' in cl_res:
        Err().report_error(context, cl_res['message'])
    if always_abort:
        Err().unexpected_error(context, cl_res)
