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

""" Implementation of lighter.proto defined methods for eclair """

from ast import literal_eval
from concurrent.futures import TimeoutError as TimeoutFutError, \
    ThreadPoolExecutor
from fileinput import FileInput
from logging import getLogger
from os import environ, path
from re import sub
from string import ascii_lowercase, digits  # pylint: disable=deprecated-module
from time import time, sleep

from . import lighter_pb2 as pb
from . import settings
from .errors import Err
from .utils import check_req_params, command, convert, Enforcer as Enf, \
    FakeContext, get_channel_balances, get_thread_timeout, get_node_timeout, \
    handle_thread, has_amount_encoded

LOGGER = getLogger(__name__)

ERRORS = {
    'bech32 address does not match our blockchain': {
        'fun': 'invalid',
        'params': 'address'
    },
    'cannot open connection with oneself': {
        'fun': 'connect_failed'
    },
    'cannot route to self': {
        'fun': 'route_not_found'
    },
    'closing already in progress': {
        'fun': 'closechannel_failed'
    },
    'Connection refused': {
        'fun': 'node_error'
    },
    'Could not resolve host': {
        'fun': 'node_error'
    },
    'is neither a valid Base58 address': {
        'fun': 'invalid',
        'params': 'address'
    },
    'insufficient funds': {
        'fun': 'insufficient_funds'
    },
    'manually specify an amount': {
        'fun': 'amount_required'
    },
    'peer sent error: ascii=': {
        'fun': 'openchannel_failed'
    },
    'Recv failure: Connection reset by peer': {
        'fun': 'node_error'
    },
    'route not found': {
        'fun': 'route_not_found'
    },
    'The form field \'invoice\' was malformed:': {
        'fun': 'invalid',
        'params': 'payment_request'
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
    if _def(ecl_res, 'nodeId'):
        response.identity_pubkey = ecl_res['nodeId']
        if _def(ecl_res, 'publicAddresses'):
            response.node_uri = '{}@{}'.format(
                ecl_res['nodeId'], ecl_res['publicAddresses'][0])
    if _def(ecl_res, 'alias'):
        response.alias = ecl_res['alias']
    if _def(ecl_res, 'blockHeight'):
        response.blockheight = ecl_res['blockHeight']
    if _def(ecl_res, 'chainHash'):
        if ecl_res['chainHash'] == settings.TEST_HASH:
            network = 'testnet'
        elif ecl_res['chainHash'] == settings.MAIN_HASH:
            network = 'mainnet'
        else:
            network = 'regtest'
        response.network = network
    _handle_error(context, ecl_res, always_abort=False)
    return response


def ChannelBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the off-chain balance in bits available across all channels """
    # pylint: disable=no-member
    channels = ListChannels(pb.ListChannelsRequest(), context).channels
    return get_channel_balances(context, channels)


def ListPeers(request, context):  # pylint: disable=unused-argument
    """ Returns a list of peers connected to the running LN node """
    ecl_req = ['peers']
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    _handle_error(context, ecl_res, always_abort=False)
    response = pb.ListPeersResponse()
    for peer in ecl_res:
        # Filtering disconnected peers
        if _def(peer, 'state') and peer['state'] == 'DISCONNECTED':
            continue
        grpc_peer = response.peers.add()  # pylint: disable=no-member
        if _def(peer, 'nodeId'):
            grpc_peer.pubkey = peer['nodeId']
        if _def(peer, 'address'):
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
    description = ''
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
    response = pb.CreateInvoiceResponse()
    if _def(ecl_res, 'serialized'):
        response.payment_request = ecl_res['serialized']
    else:
        _handle_error(context, ecl_res, always_abort=True)
    if _def(ecl_res, 'paymentHash'):
        response.payment_hash = ecl_res['paymentHash']
    if _def(ecl_res, 'timestamp') and _def(ecl_res, 'expiry'):
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
    if _def(ecl_res, 'receivedAt'):
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
    if _def(payment, 'preimage'):
        response.payment_preimage = payment['preimage']
    elif _def(payment, 'status') and payment['status'] == 'FAILED':
        Err().payinvoice_failed(context)
    elif _def(payment, 'status') and payment['status'] == 'PENDING':
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
    if _def(ecl_res, 'amount'):
        response.amount_bits = convert(context, Enf.MSATS, ecl_res['amount'])
    if _def(ecl_res, 'timestamp'):
        response.timestamp = ecl_res['timestamp']
    if _def(ecl_res, 'nodeId'):
        response.destination_pubkey = ecl_res['nodeId']
    if _def(ecl_res, 'paymentHash'):
        response.payment_hash = ecl_res['paymentHash']
    else:
        _handle_error(context, ecl_res, always_abort=True)
    if _def(ecl_res, 'description'):
        if _is_description_hash(ecl_res['description']):
            response.description_hash = ecl_res['description']
        else:
            response.description = ecl_res['description']
    if _def(ecl_res, 'expiry'):
        response.expiry_time = ecl_res['expiry']
    if _def(ecl_res, 'minFinalCltvExpiry'):
        response.min_final_cltv_expiry = ecl_res['minFinalCltvExpiry']
    return response


def OpenChannel(request, context):
    """ Tries to connect and open a channel with a peer """
    check_req_params(context, request, 'node_uri', 'funding_bits')
    ecl_req = ['connect']
    response = pb.OpenChannelResponse()
    try:
        pubkey, _host = request.node_uri.split("@")
    except ValueError:
        Err().invalid(context, 'node_uri')
    ecl_req.append('--uri={}'.format(request.node_uri))
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    if 'connected' not in ecl_res:
        Err().connect_failed(context)
    ecl_req = ['open']
    ecl_req.append('--nodeId={}'.format(pubkey))
    ecl_req.append('--fundingSatoshis={}'.format(
        convert(context, Enf.SATS, request.funding_bits,
                enforce=Enf.FUNDING_SATOSHIS, max_precision=Enf.SATS)))
    if request.push_bits:
        ecl_req.append('--pushMsat={}'.format(
            convert(context, Enf.MSATS, request.push_bits,
                    enforce=Enf.PUSH_MSAT, max_precision=Enf.MSATS)))
    if request.private:
        ecl_req.append('--channelFlags=0')
    ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
    if 'created channel' not in ecl_res:
        _handle_error(context, ecl_res, always_abort=True)
    ecl_req = ['channel']
    try:
        channel_id = ecl_res.split(' ')[2]
        ecl_req.append('--channelId={}'.format(channel_id))
        ecl_res = command(context, *ecl_req, env=settings.ECL_ENV)
        if _def(ecl_res, 'data'):
            data = ecl_res['data']
            if _def(data, 'commitments'):
                commitments = data['commitments']
                if _def(commitments, 'commitInput'):
                    commit_input = commitments['commitInput']
                    if _def(commit_input, 'outPoint'):
                        funding_txid = commit_input['outPoint'].split(':')[0]
                        response.funding_txid = funding_txid
    except IndexError:
        pass
    return response


def CloseChannel(request, context):
    """ Tries to close a LN chanel """
    check_req_params(context, request, 'channel_id')
    ecl_req = ['close']
    if request.force:
        ecl_req = ['forceclose']
    ecl_req.append('--channelId="{}"'.format(request.channel_id))
    executor = ThreadPoolExecutor(max_workers=1)
    client_expiry_time = context.time_remaining() + time()
    close_timeout = get_node_timeout(
        context, min_time=settings.CLOSE_TIMEOUT_NODE)
    future = executor.submit(
        _close_channel, ecl_req, close_timeout, client_expiry_time)
    try:
        ecl_res = future.result(timeout=get_thread_timeout(context))
        if ecl_res:
            return pb.CloseChannelResponse(closing_txid=ecl_res)
    except TimeoutFutError:
        executor.shutdown(wait=False)
    except RuntimeError as ecl_err:
        try:
            error = literal_eval(str(ecl_err))
            _handle_error(context, error)
        except (SyntaxError, ValueError):
            Err().report_error(context, str(ecl_err))
    return pb.CloseChannelResponse()


def _def(dictionary, key):
    """ Checks if key is in dictionary and that it's not None """
    return key in dictionary and dictionary[key] is not None


def _is_description_hash(description):
    """ Checks if description is a hash """
    allowed_set = set(ascii_lowercase + digits)
    return len(description) == 64 and ' ' not in description and \
        set(description).issubset(allowed_set)


def _add_channel(context, response, ecl_chan, active_only):
    """ Adds a channel to a ListChannelsResponse """
    # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    state = None
    if _def(ecl_chan, 'state'):
        state = _get_state(ecl_chan)
        if state < 0:
            return
    connected = True
    if _def(ecl_chan, 'state'):
        connected = False
        if ecl_chan['state'] == 'NORMAL':
            connected = True
    if active_only and not connected:
        return
    grpc_chan = response.channels.add()
    grpc_chan.active = connected
    if state:
        grpc_chan.state = state
    if _def(ecl_chan, 'nodeId'):
        grpc_chan.remote_pubkey = ecl_chan['nodeId']
    if _def(ecl_chan, 'channelId'):
        grpc_chan.channel_id = ecl_chan['channelId']
    if _def(ecl_chan, 'data'):
        data = ecl_chan['data']
        if _def(data, 'shortChannelId'):
            grpc_chan.short_channel_id = data['shortChannelId']
        if _def(data, 'commitments'):
            commitments = data['commitments']
            if _def(commitments, 'commitInput'):
                commit_input = commitments['commitInput']
                if _def(commit_input, 'outPoint'):
                    funding_txid = commit_input['outPoint'].split(':')[0]
                    grpc_chan.funding_txid = funding_txid
            if _def(commitments, 'localParams'):
                local_params = commitments['localParams']
                if _def(local_params, 'toSelfDelay'):
                    grpc_chan.to_self_delay = local_params['toSelfDelay']
                if _def(local_params, 'channelReserveSatoshis'):
                    grpc_chan.local_reserve_sat = \
                        local_params['channelReserveSatoshis']
            if _def(commitments, 'remoteParams'):
                remote_params = commitments['remoteParams']
                if _def(remote_params, 'channelReserveSatoshis'):
                    grpc_chan.remote_reserve_sat = \
                        remote_params['channelReserveSatoshis']
            if _def(commitments, 'localCommit'):
                local_commit = commitments['localCommit']
                if _def(local_commit, 'spec'):
                    spec = local_commit['spec']
                    local_balance = remote_balance = False
                    if _def(spec, 'toLocalMsat'):
                        grpc_chan.local_balance = convert(
                            context, Enf.MSATS, spec['toLocalMsat'])
                        local_balance = True
                    if _def(spec, 'toRemoteMsat'):
                        grpc_chan.remote_balance = convert(
                            context, Enf.MSATS, spec['toRemoteMsat'])
                        remote_balance = True
                    if local_balance and remote_balance:
                        grpc_chan.capacity = \
                            grpc_chan.local_balance + grpc_chan.remote_balance
            if _def(commitments, 'channelFlags') and \
                    commitments['channelFlags'] == 0:
                grpc_chan.private = True


@handle_thread
def _close_channel(ecl_req, close_timeout, client_expiry_time):
    """ Returns close channel response or raises exception to caller """
    ecl_res = error = None
    try:
        # subtracting timeout to close channel call to retrieve closing txid
        close_timeout = close_timeout - settings.IMPL_MIN_TIMEOUT
        if close_timeout < settings.IMPL_MIN_TIMEOUT:
            close_timeout = settings.IMPL_MIN_TIMEOUT
        ecl_res = command(FakeContext(), *ecl_req, env=settings.ECL_ENV,
                          timeout=close_timeout)
        if isinstance(ecl_res, str) and ecl_res.strip() == 'ok':
            LOGGER.debug('[ASYNC] CloseChannel terminated with response: %s',
                         ecl_res.strip())
            ecl_req = ['channel', ecl_req[1]]
            ecl_res = None
            # while client has still time we check if txid is available
            while client_expiry_time > time() and not ecl_res:
                sleep(1)
                ecl_chan = command(
                    FakeContext(), *ecl_req, env=settings.ECL_ENV,
                    timeout=settings.IMPL_MIN_TIMEOUT)
                if not _def(ecl_chan, 'data'):
                    continue
                data = ecl_chan['data']
                if _def(data, 'mutualClosePublished') and \
                        data['mutualClosePublished'] and \
                        _def(data['mutualClosePublished'][0], 'txid'):
                    ecl_res = data['mutualClosePublished'][0]['txid']
                if _def(data, 'localCommitPublished') and \
                        _def(data['localCommitPublished'], 'commitTx') and \
                        _def(data['localCommitPublished']['commitTx'], 'txid'):
                    ecl_res = data['localCommitPublished']['commitTx']['txid']
        else:
            error = ecl_res
    except RuntimeError as err:
        error = str(err)
    if error:
        if isinstance(error, str):
            error = error.strip()
        LOGGER.debug('[ASYNC] CloseChannel terminated with error: %s', error)
        raise RuntimeError(error)
    return ecl_res


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
    if _def(ecl_chan, 'data'):
        data = ecl_chan['data']
        if _def(data, 'mutualClosePublished') and \
                data['mutualClosePublished']:
            return pb.PENDING_MUTUAL_CLOSE
        if (_def(data, 'localCommitPublished') and
                data['localCommitPublished']) or \
                (_def(data, 'remoteCommitPublished') and
                 data['remoteCommitPublished']):
            return pb.PENDING_FORCE_CLOSE
    return pb.UNKNOWN


def _handle_error(context, ecl_res, always_abort=True):
    """ Checks for errors in a eclair cli response """
    if _def(ecl_res, 'failures'):
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
