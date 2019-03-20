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

""" Implementation of lighter.proto _defined methods for eclair """

from fileinput import FileInput
from os import environ, path
from re import sub

from . import lighter_pb2 as pb
from . import settings
from .errors import Err
from .utils import check_req_params, command, convert, Enforcer as Enf

ERRORS = {
    'cannot route to self': {
        'fun': 'route_not_found'
    },
    'Connection refused': {
        'fun': 'node_error'
    },
    'Could not resolve host': {
        'fun': 'node_error'
    },
    'insufficient funds': {
        'fun': 'insufficient_funds'
    },
    'manually specify an amount': {
        'fun': 'amount_required'
    },
    'route not found': {
        'fun': 'route_not_found'
    }
}


def update_settings(password):
    """
    Updates eclair specific settings

    KeyError exception raised by missing dictionary keys in environ
    are left unhandled on purpose and later catched by lighter.start()
    """
    ecl_host = environ.get('ECL_HOST', settings.ECL_HOST)
    ecl_port = environ.get('ECL_PORT', settings.ECL_PORT)
    ecl_pass = password.decode()
    settings.ECL_ENV = {'PASSWORD': ecl_pass}
    ecl_url = '{}:{}'.format(ecl_host, ecl_port)
    ecl_cli = path.abspath('lighter/eclair-cli')
    ecl_options = ['-a', ecl_url]
    with FileInput(files=(ecl_cli), inplace=1) as file:
        for line in file:
            line = sub('^PASSWORD=.*', "PASSWORD=$PASSWORD",
                       line.rstrip())
            print(line)
    settings.CMD_BASE = [ecl_cli] + ecl_options


def GetInfo(request, context):  # pylint: disable=unused-argument
    """ Returns info about the running LN node """
    ecl_req = ['getinfo']
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    response = pb.GetInfoResponse()
    if _defined(ecl_res, 'nodeId'):
        response.identity_pubkey = ecl_res['nodeId']
    if _defined(ecl_res, 'alias'):
        response.alias = ecl_res['alias']
    if _defined(ecl_res, 'blockHeight'):
        response.blockheight = ecl_res['blockHeight']
    if _defined(ecl_res, 'chainHash'):
        if ecl_res['chainHash'] == settings.TEST_HASH:
            network = 'testnet'
        elif ecl_res['chainHash'] == settings.MAIN_HASH:
            network = 'mainnet'
        else:
            network = 'unknown'
        response.network = network
    _handle_error(context, ecl_res, always_abort=False)
    return response


def ChannelBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the off-chain balance in bits available across all channels """
    ecl_req = ['channels']
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    _handle_error(context, ecl_res, always_abort=False)
    funds = 0.0
    for channel in ecl_res:
        # check id
        ecl_req = ['channel', channel['channelId']]
        ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
        if _defined(ecl_res, 'data') \
                and _defined(ecl_res['data'], 'commitments'):
            commitments = ecl_res['data']['commitments']
            if _defined(commitments, 'localCommit'):
                local_commit = commitments['localCommit']
                if _defined(local_commit, 'spec'):
                    spec = commitments['localCommit']['spec']
                    if _defined(spec, 'toLocalMsat'):
                        funds += spec['toLocalMsat']
    return pb.ChannelBalanceResponse(
        balance=convert(context, Enf.MSATS, funds))


def ListPeers(request, context):  # pylint: disable=unused-argument
    """ Returns a list of peers connected to the running LN node """
    ecl_req = ['peers']
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    response = pb.ListPeersResponse()
    for peer in ecl_res:
        # Filtering disconnected peers
        if _defined(peer, 'state') and peer['state'] == 'DISCONNECTED':
            continue
        grpc_peer = response.peers.add()  # pylint: disable=no-member
        if _defined(peer, 'nodeId'):
            grpc_peer.pubkey = peer['nodeId']
        if _defined(peer, 'address'):
            grpc_peer.address = peer['address']
    _handle_error(context, ecl_res, always_abort=False)
    return response


def ListChannels(request, context):
    """ Returns a list of channels of the running LN node """
    ecl_req = ['channels']
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    response = pb.ListChannelsResponse()
    for channel in ecl_res:
        if _defined(channel, 'channelId'):
            ecl_req = ['channel', channel['channelId']]
            ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
            if request.active_only and _defined(ecl_res, 'state') \
                    and ecl_res['state'] == 'NORMAL':
                _add_channel(context, response, ecl_res)
            elif not request.active_only:
                _add_channel(context, response, ecl_res)
    _handle_error(context, ecl_res, always_abort=False)
    return response


def CreateInvoice(request, context):
    """ Creates a LN invoice (bolt 11 standard) """
    ecl_req = ['receive']
    # [description] or [amount, description] or
    # [amount, description, expiryDuration]
    if request.min_final_cltv_expiry:
        Err().unimplemented_parameter(context, 'min_final_cltv_expiry')
    description = settings.DEFAULT_DESCRIPTION
    if request.description:
        description = request.description
    if request.amount_bits:
        ecl_req.append('{}'.format(
            convert(
                context, Enf.MSATS, request.amount_bits,
                enforce=Enf.LN_PAYREQ)))
    # Description has to exist at this moment,
    # needs to be after amount if that exists
    ecl_req.append(description)
    if request.expiry_time and request.amount_bits:
        ecl_req.append('{}'.format(request.expiry_time))
    elif request.expiry_time and not request.amount_bits:
        Err().unsettable(context, 'expiry_time (amount necessary)')
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    _handle_error(context, ecl_res, always_abort=False)
    response = pb.CreateInvoiceResponse()
    response.payment_request = ecl_res.strip()
    ecl_req = ['checkinvoice', ecl_res.strip()]
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    _handle_error(context, ecl_res, always_abort=False)
    if _defined(ecl_res, 'tags'):
        for tag in ecl_res['tags']:
            if _defined(tag, 'hash'):
                response.payment_hash = str(tag['hash'])
            if _defined(ecl_res, 'timestamp') and _defined(tag, 'seconds'):
                expires_at = int(ecl_res['timestamp']) + int(tag['seconds'])
                response.expires_at = expires_at
    return response


def CheckInvoice(request, context):
    """ Checks if a LN invoice has been paid """
    # eclair-cli checkinvoice [payment_request] | checkinvoice [payment_hash]
    ecl_req = ['checkpayment']
    check_req_params(context, request, 'payment_hash')
    ecl_req.append(request.payment_hash)
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    if not isinstance(ecl_res, bool):
        Err().invalid(context, 'payment_hash')
    return pb.CheckInvoiceResponse(settled=ecl_res)


def PayInvoice(request, context):
    """
    Tries to pay a LN invoice from its payment request (bolt 11 standard).
    An amount can be specified if the invoice doesn't already have it included.
    If a description hash is included in the invoice, its preimage must be
    included in the request
    """
    ecl_req = ['send']
    check_req_params(context, request, 'payment_request')
    if request.cltv_expiry_delta:
        Err().unimplemented_parameter(context, 'cltv_expiry_delta')
    ecl_req.append('{}'.format(request.payment_request))
    dec_req = pb.DecodeInvoiceRequest(payment_request=request.payment_request)
    invoice = DecodeInvoice(dec_req, context)
    # pylint: disable=no-member
    if request.amount_bits and invoice.amount_bits:
        Err().unsettable(context, 'amount_bits')
    elif request.amount_bits and not invoice.amount_bits:
        ecl_req.append('{}'.format(
            convert(
                context, Enf.MSATS, request.amount_bits, enforce=Enf.LN_TX)))
    # pylint: enable=no-member
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    response = pb.PayInvoiceResponse()
    if _defined(ecl_res, 'paymentPreimage'):
        response.payment_preimage = ecl_res['paymentPreimage']
    elif 'payment request is not valid' in ecl_res:
        # checking manually as error is not in json
        Err().invalid(context, 'payment_request')
    _handle_error(context, ecl_res, always_abort=False)
    return response


def DecodeInvoice(request, context):  # pylint: disable=too-many-branches
    """ Tries to return information of a LN invoice from its payment request
        (bolt 11 standard) """
    ecl_req = ['checkinvoice']
    check_req_params(context, request, 'payment_request')
    ecl_req.append('{}'.format(request.payment_request))
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    if 'invalid payment request' in ecl_res:
        # checking manually as error is not in json
        Err().invalid(context, 'payment_request')
    response = pb.DecodeInvoiceResponse()
    if _defined(ecl_res, 'amount'):
        response.amount_bits = convert(context, Enf.MSATS, ecl_res['amount'])
    if _defined(ecl_res, 'timestamp'):
        response.timestamp = ecl_res['timestamp']
    if _defined(ecl_res, 'nodeId'):
        response.destination_pubkey = ecl_res['nodeId']
    if 'tags' in ecl_res:
        found_payh = found_desh = False
        for tag in ecl_res['tags']:
            if _defined(tag, 'hash') and not found_payh:
                response.payment_hash = tag['hash']
                found_payh = True
                continue
            if _defined(tag, 'description'):
                response.description = tag['description']
            if _defined(tag, 'hash') and found_payh and not found_desh:
                response.description_hash = tag['hash']
                found_desh = True
                continue
            if _defined(tag, 'seconds'):
                response.expiry_time = tag['seconds']
            if _defined(tag, 'blocks'):
                response.min_final_cltv_expiry = tag['blocks']
            if _defined(tag, 'path'):
                _add_route_hint(response, tag['path'])
    _handle_error(context, ecl_res, always_abort=False)
    return response


def _defined(dictionary, key):
    """ Checks if key is in dictionary and that it's not None """
    if key in dictionary and dictionary[key] is not None:
        return True
    return False


def _add_channel(context, response, ecl_chan):
    """ Adds a channel to a ListChannelsResponse """
    grpc_chan = response.channels.add()
    if _defined(ecl_chan, 'nodeId'):
        grpc_chan.remote_pubkey = ecl_chan['nodeId']
    if _defined(ecl_chan, 'channelId'):
        grpc_chan.channel_id = ecl_chan['channelId']
    if _defined(ecl_chan, 'data'):
        data = ecl_chan['data']
        if _defined(data, 'shortChannelId'):
            grpc_chan.short_channel_id = data['shortChannelId']
        if _defined(data, 'commitments'):
            commitments = data['commitments']
            if _defined(commitments, 'localCommit'):
                local_commit = commitments['localCommit']
                if _defined(local_commit, 'spec'):
                    spec = local_commit['spec']
                    local_balance = remote_balance = False
                    if _defined(spec, 'toLocalMsat'):
                        grpc_chan.local_balance = convert(
                            context, Enf.MSATS, spec['toLocalMsat'])
                        local_balance = True
                    if _defined(spec, 'toRemoteMsat'):
                        grpc_chan.remote_balance = convert(
                            context, Enf.MSATS, spec['toRemoteMsat'])
                        remote_balance = True
                    if local_balance and remote_balance:
                        grpc_chan.capacity = \
                            grpc_chan.local_balance + grpc_chan.remote_balance


def _add_route_hint(response, ecl_route):
    """ Adds a route hint and its hop hints to a DecodeInvoiceResponse """
    grpc_route = response.route_hints.add()
    for ecl_hop in ecl_route:
        grpc_hop = grpc_route.hop_hints.add()
        if _defined(ecl_hop, 'nodeId'):
            grpc_hop.pubkey = ecl_hop['nodeId']
        if _defined(ecl_hop, 'shortChannelId'):
            grpc_hop.short_channel_id = ecl_hop['shortChannelId']
        if _defined(ecl_hop, 'feeBaseMsat'):
            grpc_hop.fee_base_msat = ecl_hop['feeBaseMsat']
        if _defined(ecl_hop, 'feeProportionalMillionths'):
            grpc_hop.fee_proportional_millionths = ecl_hop[
                'feeProportionalMillionths']
        if _defined(ecl_hop, 'cltvExpiryDelta'):
            grpc_hop.cltv_expiry_delta = ecl_hop['cltvExpiryDelta']


def _handle_error(context, ecl_res, always_abort=True):
    """ Checks for errors in a eclair cli response """
    if _defined(ecl_res, 'failures'):
        errors = []
        for failure in ecl_res['failures']:
            for value in failure.values():
                errors.append(value)
        error = ' + '.join(errors)
        Err().report_error(context, error)
    else:
        Err().report_error(context, ecl_res, always_abort=False)
    if always_abort:
        Err().unexpected_error(context, ecl_res)
