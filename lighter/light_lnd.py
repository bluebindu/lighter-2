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

""" Implementation of lighter.proto defined methods for lnd """

from binascii import hexlify
from codecs import encode
from contextlib import contextmanager
from os import environ, path

import grpc

from . import rpc_pb2 as ln
from . import rpc_pb2_grpc as lnrpc
from . import lighter_pb2 as pb
from . import settings
from .utils import convert, Enforcer as Enf
from .errors import Err

ERRORS = {
    'amount must be specified when paying a zero amount invoice': {
        'fun': 'amount_required',
        'params': None
    },
    'checksum failed': {
        'fun': 'incorrect_invoice',
        'params': None
    },
    'encoding/hex': {
        'fun': 'incorrect_payment_hash',
        'params': None
    },
    'expected 1 macaroon, got': {
        'fun': 'node_error',
        'params': 'expected 1 macaroon'
    },
    'invoice expired': {
        'fun': 'invoice_expired',
        'params': None
    },
    'Name resolution failure': {
        'fun': 'node_error',
        'params': 'name resolution failure (hint: check node host name)'
    },
    'payment hash must': {
        'fun': 'incorrect_payment_hash',
        'params': None
    },
    'unable to find a path to destination': {
        'fun': 'route_not_found',
        'params': None
    },
    'unable to locate invoice': {
        'fun': 'invoice_not_found',
        'params': None
    },
    'unable to route payment to destination: FeeInsufficient': {
        'fun': 'insufficient_fee',
        'params': None
    },
    'unknown service lnrpc.Lightning': {
        'fun': 'node_error',
        'params': 'unknown service lnrpc.Lightning (hint: locked wallet?)'
    }
}

LND_PAYREQ = {'min_value': 0, 'max_value': 2**32 / 1000, 'unit': Enf.SATS}
LND_LN_TX = {'min_value': 1, 'max_value': 2**32 / 1000, 'unit': Enf.SATS}


def update_settings():
    """
    Updates lnd specific settings

    KeyError exception raised by missing dictionary keys in environ
    are left unhandled on purpose and later catched by lighter.start()
    """
    lnd_host = environ['LND_HOST']
    lnd_port = environ['LND_PORT']
    settings.LND_ADDR = '{}:{}'.format(lnd_host, lnd_port)
    lnd_tls_cert_dir = environ['LND_CERT_DIR']
    lnd_tls_cert = environ['LND_CERT']
    lnd_tls_cert_path = path.join(lnd_tls_cert_dir, lnd_tls_cert)
    with open(lnd_tls_cert_path, 'rb') as file:
        cert = file.read()
    # Build ssl credentials using the cert
    settings.LND_CREDS = cert_creds = grpc.ssl_channel_credentials(cert)
    if environ.get('LND_MACAROON_DIR'):
        # Build meta data credentials
        auth_creds = grpc.metadata_call_credentials(_metadata_callback)
        # Combine the cert credentials and the macaroon auth credentials
        # Such that every call is properly encrypted and authenticated
        settings.LND_CREDS = grpc.composite_channel_credentials(
            cert_creds, auth_creds)


def _metadata_callback(context, callback):  # pylint: disable=unused-argument
    """ Gets lnd macaroon """
    lnd_macaroon_dir = environ['LND_MACAROON_DIR']
    lnd_macaroon = environ['LND_MACAROON']
    lnd_macaroon_path = path.join(lnd_macaroon_dir, lnd_macaroon)
    with open(lnd_macaroon_path, 'rb') as file:
        macaroon_bytes = file.read()
        macaroon = encode(macaroon_bytes, 'hex')
    callback([('macaroon', macaroon)], None)


@contextmanager
def _connect():
    """ Securely connects to the lnd node using gRPC """
    channel = grpc.secure_channel(settings.LND_ADDR, settings.LND_CREDS)
    stub = lnrpc.LightningStub(channel)
    yield stub
    channel.close()


def GetInfo(request, context):  # pylint: disable=unused-argument
    """ Returns info about the running LN node """
    response = pb.GetInfoResponse()
    lnd_req = ln.GetInfoRequest()
    with _connect() as stub:
        try:
            lnd_res = stub.GetInfo(lnd_req)
            network = 'mainnet'
            if lnd_res.testnet:
                network = 'testnet'
            response = pb.GetInfoResponse(
                identity_pubkey=lnd_res.identity_pubkey,
                alias=lnd_res.alias,
                version=lnd_res.version,
                blockheight=lnd_res.block_height,
                network=network)
            if lnd_res.identity_pubkey:
                lnd_req = ln.NodeInfoRequest(pub_key=lnd_res.identity_pubkey)
                lnd_res = stub.GetNodeInfo(lnd_req)
                response.color = lnd_res.node.color
        except grpc.RpcError as error:
            _handle_error(context, error)
    return response


def NewAddress(request, context):
    """ Creates a new bitcoin address under control of the running LN node """
    response = pb.NewAddressResponse()
    if request.type == 0:
        # in lnd NESTED_PUBKEY_HASH = 1;
        lnd_req = ln.NewAddressRequest(type=1)
    else:
        # in lnd WITNESS_PUBKEY_HASH = 0;
        lnd_req = ln.NewAddressRequest(type=0)
    with _connect() as stub:
        try:
            lnd_res = stub.NewAddress(lnd_req)
            response = pb.NewAddressResponse(address=lnd_res.address)
        except grpc.RpcError as error:
            _handle_error(context, error)
    return response


def WalletBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the on-chain balance in bits of the running LN node """
    response = pb.WalletBalanceResponse()
    lnd_req = ln.WalletBalanceRequest()
    with _connect() as stub:
        try:
            lnd_res = stub.WalletBalance(lnd_req)
            response = pb.WalletBalanceResponse(
                balance=convert(context, Enf.SATS, lnd_res.total_balance))
        except grpc.RpcError as error:
            _handle_error(context, error)
    return response


def ChannelBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the off-chain balance in bits available across all channels """
    response = pb.ChannelBalanceResponse()
    lnd_req = ln.ChannelBalanceRequest()
    with _connect() as stub:
        try:
            lnd_res = stub.ChannelBalance(lnd_req)
            response = pb.ChannelBalanceResponse(
                balance=convert(context, Enf.SATS, lnd_res.balance))
        except grpc.RpcError as error:
            _handle_error(context, error)
    return response


def ListPeers(request, context):  # pylint: disable=unused-argument
    """ Returns a list of peers connected to the running LN node """
    response = pb.ListPeersResponse()
    lnd_req = ln.ListPeersRequest()
    with _connect() as stub:
        try:
            lnd_res = stub.ListPeers(lnd_req)
            for lnd_peer in lnd_res.peers:
                response.peers.add(  # pylint: disable=no-member
                    pubkey=lnd_peer.pub_key,
                    address=lnd_peer.address)
        except grpc.RpcError as error:
            _handle_error(context, error)
    return response


def ListChannels(request, context):
    """ Returns a list of channels of the running LN node """
    response = pb.ListChannelsResponse()
    lnd_req = ln.ListChannelsRequest()
    with _connect() as stub:
        try:
            lnd_res = stub.ListChannels(lnd_req)
            for lnd_chan in lnd_res.channels:
                _add_channel(context, response, lnd_chan, active=True)
            if not request.active_only:
                lnd_req = ln.PendingChannelsRequest()
                lnd_res = stub.PendingChannels(lnd_req)
                for lnd_chan in lnd_res.pending_open_channels:
                    _add_channel(context, response, lnd_chan.channel)
                for lnd_chan in lnd_res.pending_closing_channels:
                    _add_channel(context, response, lnd_chan.channel)
                for lnd_chan in lnd_res.pending_force_closing_channels:
                    _add_channel(context, response, lnd_chan.channel)
                for lnd_chan in lnd_res.waiting_close_channels:
                    _add_channel(context, response, lnd_chan.channel)
        except grpc.RpcError as error:
            _handle_error(context, error)
    return response


def CreateInvoice(request, context):
    """ Creates a LN invoice (bolt 11 standard) """
    response = pb.CreateInvoiceResponse()
    lnd_req = ln.Invoice(
        memo=request.description,
        expiry=request.expiry_time,
        fallback_addr=request.fallback_addr,
        cltv_expiry=Enf.check_value(
            context, request.min_final_cltv_expiry,
            enforce=Enf.MIN_FINAL_CLTV_EXPIRY))
    if request.amount_bits:
        lnd_req.value = convert(
            context, Enf.SATS, request.amount_bits,
            enforce=LND_PAYREQ, max_precision=Enf.SATS)
    with _connect() as stub:
        try:
            lnd_res = stub.AddInvoice(lnd_req)
            payment_hash_str = ''
            if lnd_res.r_hash:
                payment_hash_str = hexlify(lnd_res.r_hash)
            response = pb.CreateInvoiceResponse(
                payment_hash=payment_hash_str,
                payment_request=lnd_res.payment_request)
            if payment_hash_str:
                lnd_req = ln.PaymentHash(r_hash_str=payment_hash_str)
                lnd_res = stub.LookupInvoice(lnd_req)
                response.expires_at = lnd_res.creation_date + lnd_res.expiry
        except grpc.RpcError as error:
            _handle_error(context, error)
    return response


def CheckInvoice(request, context):
    """ Checks if a LN invoice has been paid """
    if not request.payment_hash:
        Err().missing_parameter(context, 'payment_hash')
    response = pb.CheckInvoiceResponse()
    lnd_req = ln.PaymentHash(r_hash_str=request.payment_hash)
    with _connect() as stub:
        try:
            lnd_res = stub.LookupInvoice(lnd_req)
            response.settled = lnd_res.settled
        except grpc.RpcError as error:
            _handle_error(context, error)
    return response


def PayInvoice(request, context):
    """
    Tries to pay a LN invoice from its payment request (bolt 11 standard).
    An amount can be specified if the invoice doesn't already have it included.
    If a description hash is included in the invoice, its preimage must be
    included in the request
    """
    response = pb.PayInvoiceResponse()
    dec_req = pb.DecodeInvoiceRequest(payment_request=request.payment_request)
    invoice = DecodeInvoice(dec_req, context)
    lnd_req = ln.SendRequest(
        payment_request=request.payment_request,
        final_cltv_delta=Enf.check_value(
            context, request.cltv_expiry_delta, enforce=Enf.CLTV_EXPIRY_DELTA))
    # pylint: disable=no-member
    if request.amount_bits and invoice.amount_bits:
        Err().unsettable(context, 'amount_bits')
    elif request.amount_bits and not invoice.amount_bits:
        lnd_req.amt = convert(
            context, Enf.SATS, request.amount_bits,
            enforce=LND_LN_TX, max_precision=Enf.SATS)
    # pylint: enable=no-member
    with _connect() as stub:
        try:
            lnd_res = stub.SendPaymentSync(lnd_req)
            if lnd_res.payment_preimage:
                response.payment_preimage = hexlify(lnd_res.payment_preimage)
            elif lnd_res.payment_error:
                _handle_error(context, lnd_res.payment_error)
        except grpc.RpcError as error:
            _handle_error(context, error)
    return response


def DecodeInvoice(request, context):
    """
    Tries to return information of a LN invoice from its payment request
    (bolt 11 standard)
    """
    response = pb.DecodeInvoiceResponse()
    if not request.payment_request:
        Err().missing_parameter(context, 'payment_request')
    lnd_req = ln.PayReqString(pay_req=request.payment_request)
    with _connect() as stub:
        try:
            lnd_res = stub.DecodePayReq(lnd_req)
            response = pb.DecodeInvoiceResponse(
                amount_bits=convert(context, Enf.SATS, lnd_res.num_satoshis),
                timestamp=lnd_res.timestamp,
                payment_hash=lnd_res.payment_hash,
                description=lnd_res.description,
                destination_pubkey=lnd_res.destination,
                description_hash=lnd_res.description_hash,
                expiry_time=lnd_res.expiry,
                min_final_cltv_expiry=lnd_res.cltv_expiry,
                fallback_addr=lnd_res.fallback_addr)
            for lnd_route in lnd_res.route_hints:
                _add_route_hint(context, response, lnd_route)
        except grpc.RpcError as error:
            _handle_error(context, error)
    return response


def _add_channel(context, response, lnd_chan, active=False):
    """ Adds an active or pending channel to a ListChannelsResponse """
    if lnd_chan.ListFields():
        channel = response.channels.add(
            funding_txid=lnd_chan.channel_point,
            capacity=convert(context, Enf.SATS, lnd_chan.capacity),
            local_balance=convert(context, Enf.SATS, lnd_chan.local_balance),
            remote_balance=convert(context, Enf.SATS, lnd_chan.remote_balance))
        if active:
            channel.remote_pubkey = lnd_chan.remote_pubkey
            channel.channel_id = str(lnd_chan.chan_id)
            channel.to_self_delay = lnd_chan.csv_delay
        else:
            channel.remote_pubkey = lnd_chan.remote_node_pub


def _add_route_hint(context, response, lnd_route):
    """ Adds a route hint and its hop hints to a DecodeInvoiceResponse """
    if lnd_route.ListFields():
        grpc_route = response.route_hints.add()
    for lnd_hop in lnd_route.hop_hints:
        grpc_route.hop_hints.add(
            pubkey=lnd_hop.node_id,
            short_channel_id=str(lnd_hop.chan_id),
            fee_base_bits=convert(context, Enf.MSATS, lnd_hop.fee_base_msat),
            fee_proportional_millionths=lnd_hop.fee_proportional_millionths,
            cltv_expiry_delta=lnd_hop.cltv_expiry_delta)


def _handle_error(context, error):
    """
    Reports a lnd RpcError
    This is always terminating: raises a grpc.RpcError
    """
    error = error.details() if hasattr(error, 'details') else error
    if not isinstance(error, str):
        error = 'Could not decode error message'
    Err().report_error(context, error)
