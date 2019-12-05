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

from os import environ
from logging import getLogger

from decimal import Decimal
from . import lighter_pb2 as pb
from . import settings
from .errors import Err
from .utils import check_req_params, convert, ElectrumRPC, Enforcer as Enf, \
    get_address_type, get_channel_balances, has_amount_encoded

LOGGER = getLogger(__name__)

ERRORS = {
    'Bad bech32 checksum': {
        'fun': 'invalid',
        'params': 'payment_request'
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


def update_settings(password):
    """ Updates electrum specific settings """
    ele_host = environ.get('ELE_HOST', settings.ELE_HOST)
    ele_port = environ.get('ELE_PORT', settings.ELE_PORT)
    ele_user = environ.get('ELE_USER', settings.ELE_USER)
    ele_pass = password.decode()
    settings.RPC_URL = 'http://{}:{}@{}:{}'.format(
        ele_user, ele_pass, ele_host, ele_port)


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
        response.balance = response.balance_confirmed
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
    if request.active_only:
        Err().unimplemented_param_value(context, 'active_only', 'True')
    rpc_ele = ElectrumRPC()
    ele_res, is_err = rpc_ele.list_channels(context)
    if is_err:
        _handle_error(context, ele_res)
    response = pb.ListChannelsResponse()
    for ele_chan in ele_res:
        _add_channel(context, response, ele_chan, request.active_only)
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
    response = pb.PayInvoiceResponse()
    # TODO: retrieve payment preimage
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


def _add_channel(context, response, ele_chan, active_only):
    """ Adds a channel to a ListChannelsResponse """
    state = _get_channel_state(ele_chan)
    if active_only and state != pb.OPEN:
        return
    grpc_chan = response.channels.add()
    grpc_chan.state = state
    if 'remote_pubkey' in ele_chan:
        grpc_chan.remote_pubkey = ele_chan['remote_pubkey']
    if _def(ele_chan, 'channel_id'):
        grpc_chan.short_channel_id = ele_chan['channel_id']
    if _def(ele_chan, 'full_channel_id'):
        grpc_chan.channel_id = ele_chan['full_channel_id']
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


def _def(dictionary, key):
    """ Checks if key is in dictionary and that it's not None """
    return key in dictionary and dictionary[key] is not None


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


def _handle_error(context, ele_res):
    """ Reports errors of an electrum rpc response """
    Err().report_error(context, ele_res)
