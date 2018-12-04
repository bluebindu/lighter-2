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

from datetime import datetime
from os import environ, path

from . import lighter_pb2 as pb
from . import settings
from .utils import command, convert, Enforcer as Enf
from .errors import Err

ERRORS = {
    'Bad bech32 string': {
        'fun': 'incorrect_invoice',
        'params': None
    },
    'Connection refused': {
        'fun': 'node_error',
        'params': 'Connection refused (hint: check node connection)'
    },
    'Could not find a route': {
        'fun': 'route_not_found',
        'params': None
    },
    'does not match description': {
        'fun': 'incorrect_description',
        'params': None
    },
    'Fallback address does not match our network': {
        'fun': 'incorrect_fallback',
        'params': None
    },
    'Fallback address not valid': {
        'fun': 'incorrect_fallback',
        'params': None
    },
    # this error happens when giving a short fallback address (e.g. "sd")
    'Incorrect \'id\' in response': {
        'fun': 'incorrect_fallback',
        'params': None
    },
    'Invoice expired': {
        'fun': 'invoice_expired',
        'params': None
    },
    'msatoshi parameter required': {
        'fun': 'amount_required',
        'params': None
    },
    'no description to check': {
        'fun': 'missing_parameter',
        'params': 'description'
    }
}


def update_settings():
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
    if 'alias' in cl_res:
        response.alias = cl_res['alias']
    if 'color' in cl_res:
        response.color = cl_res['color']
    if 'version' in cl_res:
        response.version = cl_res['version']
    if 'blockheight' in cl_res:
        response.blockheight = int(cl_res['blockheight'])
    if 'network' in cl_res:
        response.network = cl_res['network']
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
    if 'address' in cl_res:
        response.address = cl_res['address']
    _handle_error(context, cl_res, always_abort=False)
    return response


def WalletBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the on-chain balance in bits of the running LN node """
    cl_req = ['listfunds']
    cl_res = command(context, *cl_req)
    _handle_error(context, cl_res, always_abort=False)
    funds = 0.0
    if 'outputs' in cl_res:
        for output in cl_res['outputs']:
            if 'value' in output:
                funds += output['value']
    return pb.WalletBalanceResponse(balance=convert(context, Enf.SATS, funds))


def ChannelBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the off-chain balance in bits available across all channels """
    cl_req = ['listfunds']
    cl_res = command(context, *cl_req)
    _handle_error(context, cl_res, always_abort=False)
    funds = 0.0
    if 'channels' in cl_res:
        for channel in cl_res['channels']:
            if 'channel_sat' in channel:
                funds += channel['channel_sat']
    return pb.ChannelBalanceResponse(balance=convert(context, Enf.SATS, funds))


def ListPeers(request, context):  # pylint: disable=unused-argument
    """ Returns a list of peers connected to the running LN node """
    cl_req = ['listpeers']
    cl_res = command(context, *cl_req)
    response = pb.ListPeersResponse()
    if 'peers' in cl_res:
        for peer in cl_res['peers']:
            # Filtering disconnected peers
            if 'connected' in peer and peer['connected'] is False:
                continue
            grpc_peer = response.peers.add()  # pylint: disable=no-member
            if 'id' in peer:
                grpc_peer.pubkey = peer['id']
            if 'alias' in peer:
                grpc_peer.alias = peer['alias']
            if 'netaddr' in peer:
                address = []
                for addr in peer['netaddr']:
                    address.append(addr)
                grpc_peer.address = ' + '.join(address)
    _handle_error(context, cl_res, always_abort=False)
    return response


def ListChannels(request, context):
    """ Returns a list of channels of the running LN node """
    cl_req = ['listpeers']
    cl_res = command(context, *cl_req)
    response = pb.ListChannelsResponse()
    if 'peers' in cl_res:
        for cl_peer in cl_res['peers']:
            if 'channels' in cl_peer:
                for cl_chan in cl_peer['channels']:
                    # False if not specified in request
                    if request.active_only and 'state' in cl_chan \
                            and cl_chan['state'] == 'CHANNELD_NORMAL':
                        _add_channel(context, response, cl_peer, cl_chan)
                    elif not request.active_only:
                        _add_channel(context, response, cl_peer, cl_chan)
    _handle_error(context, cl_res, always_abort=False)
    return response


def CreateInvoice(request, context):
    """ Creates a LN invoice (bolt 11 standard) """
    cl_req = ['invoice']
    if request.min_final_cltv_expiry:
        Err().unsettable(context, 'min_final_cltv_expiry')
    if request.amount_bits:
        cl_req.append('msatoshi="{}"'.format(
            convert(
                context, Enf.MSATS, request.amount_bits,
                enforce=Enf.LN_PAYREQ)))
    else:
        cl_req.append('msatoshi="any"')
    if request.description:
        cl_req.append('description="{}"'.format(request.description))
    else:
        cl_req.append('description="{}"'.format(settings.DEFAULT_DESCRIPTION))
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
    if not request.payment_hash:
        Err().missing_parameter(context, 'payment_hash')
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
    if not request.payment_request:
        Err().missing_parameter(context, 'payment_request')
    cl_req.append('bolt11="{}"'.format(request.payment_request))
    if request.amount_bits:
        dec_req = pb.DecodeInvoiceRequest(
            payment_request=request.payment_request)
        invoice = DecodeInvoice(dec_req, context)
        if invoice.amount_bits:  # pylint: disable=no-member
            Err().unsettable(context, 'amount_bits')
        else:
            cl_req.append('msatoshi="{}"'.format(
                convert(
                    context, Enf.MSATS, request.amount_bits,
                    enforce=Enf.LN_TX)))
    if request.description:
        cl_req.append('description="{}"'.format(request.description))
    if Enf.check_value(
            context, request.cltv_expiry_delta, enforce=Enf.CLTV_EXPIRY_DELTA):
        cl_req.append('maxdelay="{}"'.format(request.cltv_expiry_delta))
    cl_res = command(context, *cl_req)
    response = pb.PayInvoiceResponse()
    if 'payment_preimage' in cl_res:
        response.payment_preimage = cl_res['payment_preimage']
    _handle_error(context, cl_res, always_abort=False)
    return response


def DecodeInvoice(request, context):  # pylint: disable=too-many-branches
    """
    Tries to return information of a LN invoice from its payment request
    (bolt 11 standard)
    """
    cl_req = ['decodepay']
    response = pb.DecodeInvoiceResponse()
    if request.payment_request:
        cl_req.append('bolt11="{}"'.format(request.payment_request))
    else:
        Err().missing_parameter(context, 'payment_request')
    if request.description:
        cl_req.append('description="{}"'.format(request.description))
    cl_res = command(context, *cl_req)
    response = pb.DecodeInvoiceResponse()
    if 'msatoshi' in cl_res:
        response.amount_bits = convert(context, Enf.MSATS, cl_res['msatoshi'])
    if 'timestamp' in cl_res:
        response.timestamp = cl_res['timestamp']
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
    if 'fallback' in cl_res and 'addr' in cl_res['fallback']:
        response.fallback_addr = cl_res['fallback']['addr']
    if 'routes' in cl_res:
        for cl_route in cl_res['routes']:
            _add_route_hint(context, response, cl_route)
    _handle_error(context, cl_res, always_abort=False)
    return response


def _add_channel(context, response, cl_peer, cl_chan):
    """ Adds a channel to a ListChannelsResponse """
    grpc_chan = response.channels.add()
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
    if grpc_chan.capacity and grpc_chan.local_balance:
        grpc_chan.remote_balance = grpc_chan.capacity - grpc_chan.local_balance


def _add_route_hint(context, response, cl_route):
    """ Adds a route hint and its hop hints to a DecodeInvoiceResponse """
    grpc_route = response.route_hints.add()
    for cl_hop in cl_route:
        grpc_hop = grpc_route.hop_hints.add()
        if 'pubkey' in cl_hop:
            grpc_hop.pubkey = cl_hop['pubkey']
        if 'short_channel_id' in cl_hop:
            grpc_hop.short_channel_id = cl_hop['short_channel_id']
        if 'fee_base_msat' in cl_hop:
            grpc_hop.fee_base_bits = convert(context, Enf.MSATS,
                                             cl_hop['fee_base_msat'])
        if 'fee_proportional_millionths' in cl_hop:
            grpc_hop.fee_proportional_millionths = cl_hop[
                'fee_proportional_millionths']
        if 'cltv_expiry_delta' in cl_hop:
            grpc_hop.cltv_expiry_delta = cl_hop['cltv_expiry_delta']


def _create_label():
    """ Creates a label using microseconds (c-lightning specific) """
    microseconds = datetime.now().timestamp() * 1e6
    return '{}'.format(int(microseconds))


def _handle_error(context, cl_res, always_abort=True):
    """ Checks for errors in a c-lightning cli response """
    if 'code' in cl_res and 'message' in cl_res:
        Err().report_error(context, cl_res['message'])
    if always_abort:
        Err().unexpected_error(context, cl_res)
