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
from logging import getLogger
from string import ascii_lowercase, digits  # pylint: disable=deprecated-module
from time import time, sleep

from requests.auth import HTTPBasicAuth

from . import lighter_pb2 as pb, settings
from .errors import Err
from .utils.bitcoin import convert, Enforcer as Enf, get_channel_balances, \
    has_amount_encoded
from .utils.misc import handle_thread, set_defaults
from .utils.network import check_req_params, FakeContext, get_thread_timeout, \
    get_node_timeout, RPCSession


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


def get_settings(config, sec):
    """ Gets eclair settings """
    settings.IMPL_SEC_TYPE = 'password'
    ecl_values = ['ECL_HOST', 'ECL_PORT']
    set_defaults(config, ecl_values)
    ecl_host = config.get(sec, 'ECL_HOST')
    ecl_port = config.get(sec, 'ECL_PORT')
    ecl_url = '{}:{}'.format(ecl_host, ecl_port)
    settings.RPC_URL = 'http://{}:{}'.format(ecl_host, ecl_port)


def update_settings(password):
    """ Updates eclair specific settings """
    ecl_pass = password.decode()
    settings.ECL_PASS = ecl_pass


def GetInfo(request, context):  # pylint: disable=unused-argument
    """ Returns info about the running LN node """
    rpc_ecl = EclairRPC()
    ecl_res, is_err = rpc_ecl.getinfo(context)
    if is_err:
        _handle_error(context, ecl_res)
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
    return response


def ChannelBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the off-chain balance in bits available across all channels """
    # pylint: disable=no-member
    channels = ListChannels(pb.ListChannelsRequest(), context).channels
    return get_channel_balances(context, channels)


def ListPeers(request, context):  # pylint: disable=unused-argument
    """ Returns a list of peers connected to the running LN node """
    rpc_ecl = EclairRPC()
    ecl_res, is_err = rpc_ecl.peers(context)
    if is_err:
        _handle_error(context, ecl_res)
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
    ecl_res, _ = rpc_ecl.allnodes(context)
    if isinstance(ecl_res, list):
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
    rpc_ecl = EclairRPC()
    ecl_res, is_err = rpc_ecl.channels(context)
    if is_err:
        _handle_error(context, ecl_res)
    response = pb.ListChannelsResponse()
    for channel in ecl_res:
        _add_channel(context, response, channel, request.active_only)
    return response


def CreateInvoice(request, context):
    """ Creates a LN invoice (bolt 11 standard) """
    if request.min_final_cltv_expiry:
        Err().unimplemented_parameter(context, 'min_final_cltv_expiry')
    ecl_req = {'description': ''}
    if request.description:
        ecl_req = {'description': request.description}
    if request.amount_bits:
        ecl_req['amountMsat'] = convert(
            context, Enf.MSATS, request.amount_bits, enforce=Enf.LN_PAYREQ)
    ecl_req['expireIn'] = settings.EXPIRY_TIME
    if request.expiry_time:
        ecl_req['expireIn'] = request.expiry_time
    if request.fallback_addr:
        ecl_req['fallbackAddress'] = request.fallback_addr
    rpc_ecl = EclairRPC()
    ecl_res, is_err = rpc_ecl.createinvoice(context, ecl_req)
    if is_err:
        _handle_error(context, ecl_res)
    response = pb.CreateInvoiceResponse()
    if _def(ecl_res, 'serialized'):
        response.payment_request = ecl_res['serialized']
    if _def(ecl_res, 'paymentHash'):
        response.payment_hash = ecl_res['paymentHash']
    if _def(ecl_res, 'timestamp') and _def(ecl_res, 'expiry'):
        expires_at = int(ecl_res['timestamp']) + int(ecl_res['expiry'])
        response.expires_at = expires_at
    return response


def CheckInvoice(request, context):
    """ Checks if a LN invoice has been paid """
    check_req_params(context, request, 'payment_hash')
    ecl_req = {'paymentHash': request.payment_hash}
    rpc_ecl = EclairRPC()
    ecl_res, _ = rpc_ecl.getreceivedinfo(context, ecl_req)
    response = pb.CheckInvoiceResponse()
    if _def(ecl_res, 'status'):
        response.state = _get_invoice_state(ecl_res)
    else:
        Err().invalid(context, 'payment_hash')
    # pylint: disable=no-member
    if response.state == pb.PAID:
        response.settled = True
    return response


def PayInvoice(request, context):
    """
    Tries to pay a LN invoice from its payment request (bolt 11 standard).
    An amount can be specified if the invoice doesn't already have it included.
    If a description hash is included in the invoice, its preimage must be
    included in the request
    """
    check_req_params(context, request, 'payment_request')
    if request.cltv_expiry_delta:
        Err().unimplemented_parameter(context, 'cltv_expiry_delta')
    ecl_req = {'invoice': request.payment_request}
    amount_encoded = has_amount_encoded(request.payment_request)
    # pylint: disable=no-member
    if request.amount_bits and amount_encoded:
        Err().unsettable(context, 'amount_bits')
    elif request.amount_bits and not amount_encoded:
        ecl_req['amountMsat'] = convert(
            context, Enf.MSATS, request.amount_bits, enforce=Enf.LN_TX)
    elif not amount_encoded:
        check_req_params(context, request, 'amount_bits')
    # pylint: enable=no-member
    rpc_ecl = EclairRPC()
    ecl_res, is_err = rpc_ecl.payinvoice(context, ecl_req)
    if 'malformed' in ecl_res:
        Err().invalid(context, 'payment_request')
    elif is_err:
        _handle_error(context, ecl_res)
    ecl_req = {'id': ecl_res.strip()}
    ecl_res, is_err = rpc_ecl.getsentinfo(context, ecl_req)
    response = pb.PayInvoiceResponse()
    payment = ecl_res[0]
    if _def(payment, 'preimage'):
        response.payment_preimage = payment['preimage']
    elif _def(payment, 'status') and payment['status'] == 'FAILED':
        Err().payinvoice_failed(context)
    elif _def(payment, 'status') and payment['status'] == 'PENDING':
        Err().payinvoice_pending(context)
    else:
        _handle_error(context, ecl_res)
    return response


def DecodeInvoice(request, context):  # pylint: disable=too-many-branches
    """ Tries to return information of a LN invoice from its payment request
        (bolt 11 standard) """
    check_req_params(context, request, 'payment_request')
    ecl_req = {'invoice': request.payment_request}
    rpc_ecl = EclairRPC()
    ecl_res, is_err = rpc_ecl.parseinvoice(context, ecl_req)
    if 'invalid payment request' in ecl_res:
        # checking manually as error is not in json
        Err().invalid(context, 'payment_request')
    elif is_err:
        _handle_error(context, ecl_res)
    response = pb.DecodeInvoiceResponse()
    if _def(ecl_res, 'amount'):
        response.amount_bits = convert(context, Enf.MSATS, ecl_res['amount'])
    if _def(ecl_res, 'timestamp'):
        response.timestamp = ecl_res['timestamp']
    if _def(ecl_res, 'nodeId'):
        response.destination_pubkey = ecl_res['nodeId']
    if _def(ecl_res, 'paymentHash'):
        response.payment_hash = ecl_res['paymentHash']
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
    response = pb.OpenChannelResponse()
    try:
        pubkey, _host = request.node_uri.split("@")
    except ValueError:
        Err().invalid(context, 'node_uri')
    ecl_req = {'uri': request.node_uri}
    rpc_ecl = EclairRPC()
    ecl_res, is_err = rpc_ecl.connect(context, ecl_req)
    if 'connected' not in ecl_res:
        Err().connect_failed(context)
    ecl_req = {'nodeId': pubkey}
    ecl_req['fundingSatoshis'] = convert(
        context, Enf.SATS, request.funding_bits, enforce=Enf.FUNDING_SATOSHIS,
        max_precision=Enf.SATS)
    if request.push_bits:
        ecl_req['pushMsat'] = convert(
            context, Enf.MSATS, request.push_bits, enforce=Enf.PUSH_MSAT,
            max_precision=Enf.MSATS)
    if request.private:
        ecl_req['channelFlags'] = 0
    ecl_res, is_err = rpc_ecl.open(context, ecl_req)
    if 'created channel' not in ecl_res or is_err:
        _handle_error(context, ecl_res)
    try:
        channel_id = ecl_res.split(' ')[2]
        ecl_req = {'channelId': channel_id}
        ecl_res, _ = rpc_ecl.channel(context, ecl_req)
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
    ecl_req = {'channelId': request.channel_id}
    executor = ThreadPoolExecutor(max_workers=1)
    client_exp_time = context.time_remaining() + time()
    close_time = get_node_timeout(
        context, min_time=settings.CLOSE_TIMEOUT_NODE)
    future = executor.submit(
        _close_channel, ecl_req, request.force, close_time, client_exp_time)
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
        state = _get_channel_state(ecl_chan)
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
                if _def(local_params, 'channelReserve'):
                    grpc_chan.local_reserve_sat = \
                        local_params['channelReserve']
            if _def(commitments, 'remoteParams'):
                remote_params = commitments['remoteParams']
                if _def(remote_params, 'channelReserve'):
                    grpc_chan.remote_reserve_sat = \
                        remote_params['channelReserve']
            if _def(commitments, 'localCommit'):
                local_commit = commitments['localCommit']
                if _def(local_commit, 'spec'):
                    spec = local_commit['spec']
                    local_balance = remote_balance = False
                    if _def(spec, 'toLocal'):
                        grpc_chan.local_balance = convert(
                            context, Enf.MSATS, spec['toLocal'])
                        local_balance = True
                    if _def(spec, 'toRemote'):
                        grpc_chan.remote_balance = convert(
                            context, Enf.MSATS, spec['toRemote'])
                        remote_balance = True
                    if local_balance and remote_balance:
                        grpc_chan.capacity = \
                            grpc_chan.local_balance + grpc_chan.remote_balance
            if _def(commitments, 'channelFlags') and \
                    commitments['channelFlags'] == 0:
                grpc_chan.private = True


@handle_thread
def _close_channel(ecl_req, force, close_timeout, client_expiry_time):
    """ Returns close channel response or raises exception to caller """
    ecl_res = error = None
    try:
        # subtracting timeout to close channel call to retrieve closing txid
        close_time = close_timeout - settings.IMPL_MIN_TIMEOUT
        if close_time < settings.IMPL_MIN_TIMEOUT:
            close_time = settings.IMPL_MIN_TIMEOUT
        rpc_ecl = EclairRPC()
        if force:
            ecl_res, _ = rpc_ecl.forceclose(FakeContext(), ecl_req, close_time)
        else:
            ecl_res, _ = rpc_ecl.close(FakeContext(), ecl_req, close_time)
        if isinstance(ecl_res, str) and ecl_res.strip() == 'ok':
            LOGGER.debug('[ASYNC] CloseChannel terminated with response: %s',
                         ecl_res.strip())
            ecl_res = None
            # while client has still time we check if txid is available
            while client_expiry_time > time() and not ecl_res:
                sleep(1)
                ecl_chan, _ = rpc_ecl.channel(
                    FakeContext(), ecl_req, settings.IMPL_MIN_TIMEOUT)
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


def _get_channel_state(ecl_chan):
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


def _get_invoice_state(ecl_invoice):
    """
    Maps implementation's invoice state to lighter's invoice state definition
    """
    if _def(ecl_invoice, 'status'):
        ecl_status = ecl_invoice['status']
        if _def(ecl_status, 'type'):
            if ecl_status['type'] == 'received':
                return pb.PAID
            if ecl_status['type'] == 'pending':
                return pb.PENDING
            if ecl_status['type'] == 'expired':
                return pb.EXPIRED
    return pb.PENDING


def _handle_error(context, ecl_res):
    """ Checks for errors in a eclair cli response """
    if _def(ecl_res, 'failures'):
        errors = []
        for failure in ecl_res['failures']:
            for value in failure.values():
                errors.append(value)
        error = ' + '.join(errors)
        Err().report_error(context, error)
    else:
        Err().report_error(context, ecl_res)


class EclairRPC(RPCSession):
    """ Creates and mantains an RPC session with eclair """

    def __init__(self):
        super().__init__(auth=HTTPBasicAuth('', settings.ECL_PASS))

    def __getattr__(self, name):

        def call_adapter(context, data=None, timeout=None):
            url = '{}/{}'.format(settings.RPC_URL, name)
            if data is None:
                data = {}
            LOGGER.debug("RPC req: %s", data)
            return super(EclairRPC, self).call(context, data, url, timeout)

        return call_adapter
