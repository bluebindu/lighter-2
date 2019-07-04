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
from string import ascii_lowercase, digits  # pylint: disable=deprecated-module

from . import lighter_pb2 as pb
from . import settings
from .errors import Err
from .utils import check_req_params, command, convert, Enforcer as Enf, \
    has_amount_encoded

ERRORS = {
    'cannot open connection with oneself': {
        'fun': 'connect_failed'
    },
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
    'Recv failure: Connection reset by peer': {
        'fun': 'node_error'
    },
    'route not found': {
        'fun': 'route_not_found'
    },
    'The supplied authentication is invalid': {
        'fun': 'node_error'
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
            line = sub('^# api_password=.*', "api_password=$PASSWORD",
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
        if _defined(ecl_res, 'publicAddresses'):
            response.node_uri = '{}@{}'.format(
                ecl_res['nodeId'], ecl_res['publicAddresses'][0])
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
        if _defined(channel, 'data') \
                and _defined(channel['data'], 'commitments'):
            commitments = channel['data']['commitments']
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
    _handle_error(context, ecl_res, always_abort=False)
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
    ecl_req = ['allnodes']
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    for node in ecl_res:
        for peer in response.peers:  # pylint: disable=no-member
            if 'nodeId' in node and node['nodeId'] == peer.pubkey:
                if 'alias' in node:
                    peer.alias = node['alias']
                if 'rgbColor' in node:
                    peer.color = node['rgbColor']
    return response


def ListChannels(request, context):
    """ Returns a list of channels of the running LN node """
    ecl_req = ['channels']
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    response = pb.ListChannelsResponse()
    for channel in ecl_res:
        _add_channel(context, response, channel, request.active_only)
    _handle_error(context, ecl_res, always_abort=False)
    return response


def CreateInvoice(request, context):
    """ Creates a LN invoice (bolt 11 standard) """
    ecl_req = ['createinvoice']
    if request.min_final_cltv_expiry:
        Err().unimplemented_parameter(context, 'min_final_cltv_expiry')
    description = settings.DEFAULT_DESCRIPTION
    if request.description:
        description = request.description
    ecl_req.append('--description="{}"'.format(description))
    if request.amount_bits:
        ecl_req.append('--amountMsat="{}"'.format(
            convert(context, Enf.MSATS, request.amount_bits,
                    enforce=Enf.LN_PAYREQ)))
    if request.expiry_time:
        ecl_req.append('--expireIn="{}"'.format(request.expiry_time))
    if request.fallback_addr:
        ecl_req.append('--fallbackAddress="{}"'.format(request.fallback_addr))
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    _handle_error(context, ecl_res, always_abort=False)
    response = pb.CreateInvoiceResponse()
    if _defined(ecl_res, 'serialized'):
        response.payment_request = ecl_res['serialized']
    if _defined(ecl_res, 'paymentHash'):
        response.payment_hash = ecl_res['paymentHash']
    if _defined(ecl_res, 'timestamp') and _defined(ecl_res, 'expiry'):
        expires_at = int(ecl_res['timestamp']) + int(ecl_res['expiry'])
        response.expires_at = expires_at
    return response


def CheckInvoice(request, context):
    """ Checks if a LN invoice has been paid """
    ecl_req = ['getreceivedinfo']
    check_req_params(context, request, 'payment_hash')
    ecl_req.append('--paymentHash="{}"'.format(request.payment_hash))
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    settled = False
    if _defined(ecl_res, 'receivedAt'):
        settled = True
    elif 'Not found' not in ecl_res:
        Err().invalid(context, 'payment_hash')
    return pb.CheckInvoiceResponse(settled=settled)


def PayInvoice(request, context):
    """
    Tries to pay a LN invoice from its payment request (bolt 11 standard).
    An amount can be specified if the invoice doesn't already have it included.
    If a description hash is included in the invoice, its preimage must be
    included in the request
    """
    ecl_req = ['payinvoice']
    check_req_params(context, request, 'payment_request')
    if request.cltv_expiry_delta:
        Err().unimplemented_parameter(context, 'cltv_expiry_delta')
    ecl_req.append('--invoice="{}"'.format(request.payment_request))
    amount_encoded = has_amount_encoded(request.payment_request)
    # pylint: disable=no-member
    if request.amount_bits and amount_encoded:
        Err().unsettable(context, 'amount_bits')
    elif request.amount_bits and not amount_encoded:
        ecl_req.append('--amountMsat="{}"'.format(
            convert(
                context, Enf.MSATS, request.amount_bits, enforce=Enf.LN_TX)))
    elif not amount_encoded:
        check_req_params(context, request, 'amount_bits')
    # pylint: enable=no-member
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    if 'malformed' in ecl_res:
        Err().invalid(context, 'payment_request')
    ecl_req = ['getsentinfo']
    ecl_req.append('--id="{}"'.format(ecl_res.strip()))
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    response = pb.PayInvoiceResponse()
    payment = ecl_res[0]
    if _defined(payment, 'preimage'):
        response.payment_preimage = payment['preimage']
    elif _defined(payment, 'status') and payment['status'] == 'FAILED':
        Err().payinvoice_failed(context)
    elif _defined(payment, 'status') and payment['status'] == 'PENDING':
        Err().payinvoice_pending(context)
    else:
        _handle_error(context, ecl_res, always_abort=True)
    return response


def DecodeInvoice(request, context):  # pylint: disable=too-many-branches
    """ Tries to return information of a LN invoice from its payment request
        (bolt 11 standard) """
    ecl_req = ['parseinvoice']
    check_req_params(context, request, 'payment_request')
    ecl_req.append('--invoice="{}"'.format(request.payment_request))
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
    if _defined(ecl_res, 'paymentHash'):
        response.payment_hash = ecl_res['paymentHash']
    if _defined(ecl_res, 'description'):
        if _is_description_hash(ecl_res['description']):
            response.description_hash = ecl_res['description']
        else:
            response.description = ecl_res['description']
    if _defined(ecl_res, 'expiry'):
        response.expiry_time = ecl_res['expiry']
    if _defined(ecl_res, 'minFinalCltvExpiry'):
        response.min_final_cltv_expiry = ecl_res['minFinalCltvExpiry']
    _handle_error(context, ecl_res, always_abort=False)
    return response


def _defined(dictionary, key):
    """ Checks if key is in dictionary and that it's not None """
    return key in dictionary and dictionary[key] is not None


def _is_description_hash(description):
    """ Checks if description is a hash """
    allowed_set = set(ascii_lowercase + digits)
    return len(description) == 64 and ' ' not in description and \
        set(description).issubset(allowed_set)


def _add_channel(context, response, ecl_chan, active_only):
    """ Adds a channel to a ListChannelsResponse """
    # pylint: disable=too-many-branches,too-many-locals
    state = None
    if _defined(ecl_chan, 'state'):
        state = _get_state(ecl_chan)
        if state < 0:
            return
    connected = True
    if _defined(ecl_chan, 'state'):
        connected = False
        if ecl_chan['state'] == 'NORMAL':
            connected = True
    if active_only and not connected:
        return
    grpc_chan = response.channels.add()
    grpc_chan.active = connected
    if state:
        grpc_chan.state = state
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
            if _defined(commitments, 'commitInput'):
                commit_input = commitments['commitInput']
                if _defined(commit_input, 'outPoint'):
                    funding_txid = commit_input['outPoint'].split(':')[0]
                    grpc_chan.funding_txid = funding_txid
            if _defined(commitments, 'localParams'):
                local_params = commitments['localParams']
                if _defined(local_params, 'toSelfDelay'):
                    grpc_chan.to_self_delay = local_params['toSelfDelay']
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


def _get_state(ecl_chan):
    """
    Maps implementation's channel state to lighter's channel state definition
    """
    ecl_state = ecl_chan['state']
    if ecl_state in ('CLOSED',):
        return -1
    if ecl_state in ('WAIT_FOR_FUNDING_CONFIRMED',):
        return pb.PENDING_OPEN
    if ecl_state in ('NORMAL', 'OFFLINE'):
        return pb.OPEN
    if _defined(ecl_chan, 'data'):
        data = ecl_chan['data']
        if _defined(data, 'mutualClosePublished') and \
                data['mutualClosePublished']:
            return pb.PENDING_MUTUAL_CLOSE
        if (_defined(data, 'localCommitPublished') and
                data['localCommitPublished']) or \
                (_defined(data, 'remoteCommitPublished') and
                 data['remoteCommitPublished']):
            return pb.PENDING_FORCE_CLOSE
    return pb.UNKNOWN


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
        Err().unexpected_error(context, str(ecl_res))
