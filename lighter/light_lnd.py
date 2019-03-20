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
from datetime import datetime
from functools import wraps
from logging import getLogger
from os import environ, path

from grpc import channel_ready_future, composite_channel_credentials, \
    FutureTimeoutError, metadata_call_credentials, RpcError, secure_channel, \
    ssl_channel_credentials

from . import rpc_pb2 as ln
from . import rpc_pb2_grpc as lnrpc
from . import lighter_pb2 as pb
from . import settings
from .errors import Err
from .utils import check_req_params, convert, Enforcer as Enf

LOGGER = getLogger(__name__)

ERRORS = {
    'already connected to peer': {
        'fun': 'connect_failed'
    },
    'amount must be specified when paying a zero amount invoice': {
        'fun': 'amount_required'
    },
    'chain backend is still syncing': {
        'fun': 'node_error'
    },
    'channels cannot be created before the wallet is fully synced': {
        'fun': 'openchannel_failed'
    },
    'checksum failed': {
        'fun': 'invalid',
        'params': 'payment_request'
    },
    'checksum mismatch': {
        'fun': 'invalid',
        'params': 'address'
    },
    'Deadline Exceeded': {
        'fun': 'node_error'
    },
    'encoding/hex': {
        'fun': 'invalid',
        'params': 'payment_hash'
    },
    'expected 1 macaroon, got': {
        'fun': 'node_error'
    },
    'greater than max expiry of': {
        'fun': 'invalid',
        'params': 'expiry_time'
    },
    'i/o timeout': {
        'fun': 'node_error'
    },
    'invalid bech32 string length': {
        'fun': 'invalid',
        'params': 'payment_request'
    },
    'invalid index of': {
        'fun': 'invalid',
        'params': 'payment_request'
    },
    'invoice expired': {
        'fun': 'invoice_expired'
    },
    'invoice is already paid': {
        'fun': 'invalid',
        'params': 'payment_request'
    },
    'is not online': {
        'fun': 'openchannel_failed'
    },
    'Name resolution failure': {
        'fun': 'node_error'
    },
    'payment hash must': {
        'fun': 'invalid',
        'params': 'payment_hash'
    },
    'Socket closed': {
        'fun': 'node_error'
    },
    'string not all lowercase or all uppercase': {
        'fun': 'invalid',
        'params': 'payment_request'
    },
    'unable to find a path to destination': {
        'fun': 'route_not_found'
    },
    'unable to get best block info': {
        'fun': 'node_error'
    },
    'unable to locate invoice': {
        'fun': 'invoice_not_found'
    },
    'unable to route payment to destination: FeeInsufficient': {
        'fun': 'insufficient_fee'
    },
    'unknown service lnrpc.Lightning': {
        'fun': 'node_error'
    }
}

LND_PAYREQ = {'min_value': 0, 'max_value': 2**32 / 1000, 'unit': Enf.SATS}
LND_LN_TX = {'min_value': 1, 'max_value': 2**32 / 1000, 'unit': Enf.SATS}
LND_FUNDING = {'min_value': 20000, 'max_value': 2**24, 'unit': Enf.SATS}


def update_settings(macaroon):
    """
    Updates lnd specific settings

    KeyError exception raised by missing dictionary keys in environ
    are left unhandled on purpose and later catched by lighter.start()
    """
    lnd_host = environ.get('LND_HOST', settings.LND_HOST)
    lnd_port = environ.get('LND_PORT', settings.LND_PORT)
    settings.LND_ADDR = '{}:{}'.format(lnd_host, lnd_port)
    lnd_tls_cert_dir = environ['LND_CERT_DIR']
    lnd_tls_cert = environ.get('LND_CERT', settings.LND_CERT)
    lnd_tls_cert_path = path.join(lnd_tls_cert_dir, lnd_tls_cert)
    with open(lnd_tls_cert_path, 'rb') as file:
        cert = file.read()
    # Build ssl credentials using the cert
    settings.LND_CREDS = cert_creds = ssl_channel_credentials(cert)
    if macaroon:
        LOGGER.info("Connecting to lnd in secure mode (tls + macaroon)")
        settings.LND_MAC = macaroon
        # Build meta data credentials
        auth_creds = metadata_call_credentials(_metadata_callback)
        # Combine the cert credentials and the macaroon auth credentials
        # Such that every call is properly encrypted and authenticated
        settings.LND_CREDS = composite_channel_credentials(
            cert_creds, auth_creds)
    else:
        LOGGER.info("Connecting to lnd in insecure mode")


def _metadata_callback(context, callback):  # pylint: disable=unused-argument
    """ Gets lnd macaroon """
    macaroon = encode(settings.LND_MAC, 'hex')
    callback([('macaroon', macaroon)], None)


def _handle_rpc_errors(func):
    """ Decorator to add more context to RPC errors """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RpcError as error:
            _handle_error(args[1], error)

    return wrapper


@contextmanager
def _connect(context):
    """ Securely connects to the lnd node using gRPC """
    channel = secure_channel(settings.LND_ADDR, settings.LND_CREDS)
    future_channel = channel_ready_future(channel)
    try:
        future_channel.result(timeout=settings.IMPL_TIMEOUT)
    except FutureTimeoutError:
        # Handle gRPC channel that did not connect
        Err().node_error(context, 'Failed to dial server')
    else:
        stub = lnrpc.LightningStub(channel)
        yield stub
        channel.close()


@_handle_rpc_errors
def GetInfo(request, context):  # pylint: disable=unused-argument
    """ Returns info about the running LN node """
    response = pb.GetInfoResponse()
    lnd_req = ln.GetInfoRequest()
    with _connect(context) as stub:
        lnd_res = stub.GetInfo(lnd_req, timeout=settings.IMPL_TIMEOUT)
        network = lnd_res.chains[0].network
        response = pb.GetInfoResponse(
            identity_pubkey=lnd_res.identity_pubkey,
            alias=lnd_res.alias,
            version=lnd_res.version,
            blockheight=lnd_res.block_height,
            network=network)
        if lnd_res.identity_pubkey:
            lnd_req = ln.NodeInfoRequest(pub_key=lnd_res.identity_pubkey)
            lnd_res = stub.GetNodeInfo(lnd_req, timeout=settings.IMPL_TIMEOUT)
            response.color = lnd_res.node.color
    return response


@_handle_rpc_errors
def NewAddress(request, context):  # pylint: disable=unused-argument
    """ Creates a new bitcoin address under control of the running LN node """
    response = pb.NewAddressResponse()
    if request.type == 0:
        # in lnd NESTED_PUBKEY_HASH = 1;
        lnd_req = ln.NewAddressRequest(type=1)
    else:
        # in lnd WITNESS_PUBKEY_HASH = 0;
        lnd_req = ln.NewAddressRequest(type=0)
    with _connect(context) as stub:
        lnd_res = stub.NewAddress(lnd_req, timeout=settings.IMPL_TIMEOUT)
        response = pb.NewAddressResponse(address=lnd_res.address)
    return response


@_handle_rpc_errors
def WalletBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the on-chain balance in bits of the running LN node """
    response = pb.WalletBalanceResponse()
    lnd_req = ln.WalletBalanceRequest()
    with _connect(context) as stub:
        lnd_res = stub.WalletBalance(lnd_req, timeout=settings.IMPL_TIMEOUT)
        response = pb.WalletBalanceResponse(
            balance=convert(context, Enf.SATS, lnd_res.total_balance))
    return response


@_handle_rpc_errors
def ChannelBalance(request, context):  # pylint: disable=unused-argument
    """ Returns the off-chain balance in bits available across all channels """
    response = pb.ChannelBalanceResponse()
    lnd_req = ln.ChannelBalanceRequest()
    with _connect(context) as stub:
        lnd_res = stub.ChannelBalance(lnd_req, timeout=settings.IMPL_TIMEOUT)
        response = pb.ChannelBalanceResponse(
            balance=convert(context, Enf.SATS, lnd_res.balance))
    return response


@_handle_rpc_errors
def ListChannels(request, context):
    """ Returns a list of channels of the running LN node """
    response = pb.ListChannelsResponse()
    lnd_req = ln.ListChannelsRequest()
    with _connect(context) as stub:
        lnd_res = stub.ListChannels(lnd_req, timeout=settings.IMPL_TIMEOUT)
        for lnd_chan in lnd_res.channels:
            _add_channel(context, response, lnd_chan, active=True)
        if not request.active_only:
            lnd_req = ln.PendingChannelsRequest()
            lnd_res = stub.PendingChannels(
                lnd_req, timeout=settings.IMPL_TIMEOUT)
            for lnd_chan in lnd_res.pending_open_channels:
                _add_channel(context, response, lnd_chan.channel)
            for lnd_chan in lnd_res.pending_closing_channels:
                _add_channel(context, response, lnd_chan.channel)
            for lnd_chan in lnd_res.pending_force_closing_channels:
                _add_channel(context, response, lnd_chan.channel)
            for lnd_chan in lnd_res.waiting_close_channels:
                _add_channel(context, response, lnd_chan.channel)
    return response


@_handle_rpc_errors
def ListInvoices(request, context):
    """ Returns a list of lightning invoices created by the running LN node """
    if not request.max_items:
        request.max_items = settings.MAX_INVOICES
    response = pb.ListInvoicesResponse()
    lnd_req = ln.ListInvoiceRequest(
        reversed=request.search_order,
        num_max_invoices=request.max_items * settings.INVOICES_TIMES)
    stop = False
    with _connect(context) as stub:
        while True:
            lnd_res = stub.ListInvoices(lnd_req, timeout=settings.IMPL_TIMEOUT)
            if not lnd_res.invoices:
                break
            if request.search_order:
                lnd_res.CopyFrom(ln.ListInvoiceResponse(
                    invoices=reversed(lnd_res.invoices),
                    first_index_offset=lnd_res.first_index_offset,
                    last_index_offset=lnd_res.last_index_offset))
            stop = _parse_invoices(
                context, response, lnd_res.invoices, request)
            if stop:
                break
            if request.search_order:
                lnd_req.index_offset = lnd_res.first_index_offset
            else:
                lnd_req.index_offset = lnd_res.last_index_offset
        if request.list_order != request.search_order:
            # pylint: disable=no-member
            response.CopyFrom(pb.ListInvoicesResponse(
                invoices=reversed(response.invoices)))
            # pylint: enable=no-member
    return response


@_handle_rpc_errors
def ListPayments(request, context):  # pylint: disable=unused-argument
    """ Returns a list of lightning invoices paid by the running LN node """
    response = pb.ListPaymentsResponse()
    lnd_req = ln.ListPaymentsRequest()
    with _connect(context) as stub:
        lnd_res = stub.ListPayments(lnd_req, timeout=settings.IMPL_TIMEOUT)
        for lnd_payment in lnd_res.payments:
            _add_payment(context, response, lnd_payment)
    return response


@_handle_rpc_errors
def ListPeers(request, context):  # pylint: disable=unused-argument
    """ Returns a list of peers connected to the running LN node """
    response = pb.ListPeersResponse()
    lnd_req = ln.ListPeersRequest()
    with _connect(context) as stub:
        lnd_res = stub.ListPeers(lnd_req, timeout=settings.IMPL_TIMEOUT)
        for lnd_peer in lnd_res.peers:
            response.peers.add(  # pylint: disable=no-member
                pubkey=lnd_peer.pub_key,
                address=lnd_peer.address)
    return response


@_handle_rpc_errors
def ListTransactions(request, context):  # pylint: disable=unused-argument
    """ Returns a list of on-chain transactions of the running LN node """
    response = pb.ListTransactionsResponse()
    lnd_req = ln.GetTransactionsRequest()
    with _connect(context) as stub:
        lnd_res = stub.GetTransactions(lnd_req, timeout=settings.IMPL_TIMEOUT)
        for lnd_transaction in lnd_res.transactions:
            _add_transaction(context, response, lnd_transaction)
    return response


@_handle_rpc_errors
def CreateInvoice(request, context):
    """ Creates a LN invoice (bolt 11 standard) """
    response = pb.CreateInvoiceResponse()
    lnd_req = ln.Invoice(
        memo=request.description,
        expiry=request.expiry_time,
        fallback_addr=request.fallback_addr)
    if request.min_final_cltv_expiry:
        if Enf.check_value(
                context, request.min_final_cltv_expiry,
                enforce=Enf.MIN_FINAL_CLTV_EXPIRY):
            lnd_req.cltv_expiry = request.min_final_cltv_expiry
        else:
            Err().out_of_range(context, 'min_final_cltv_expiry')
    if request.amount_bits:
        lnd_req.value = convert(
            context, Enf.SATS, request.amount_bits,
            enforce=LND_PAYREQ, max_precision=Enf.SATS)
    with _connect(context) as stub:
        lnd_res = stub.AddInvoice(lnd_req, timeout=settings.IMPL_TIMEOUT)
        payment_hash_str = ''
        if lnd_res.r_hash:
            payment_hash_str = hexlify(lnd_res.r_hash)
        response = pb.CreateInvoiceResponse(
            payment_hash=payment_hash_str,
            payment_request=lnd_res.payment_request)
        if payment_hash_str:
            lnd_req = ln.PaymentHash(r_hash_str=payment_hash_str)
            lnd_res = stub.LookupInvoice(
                lnd_req, timeout=settings.IMPL_TIMEOUT)
            response.expires_at = lnd_res.creation_date + lnd_res.expiry
    return response


@_handle_rpc_errors
def CheckInvoice(request, context):
    """ Checks if a LN invoice has been paid """
    check_req_params(context, request, 'payment_hash')
    response = pb.CheckInvoiceResponse()
    lnd_req = ln.PaymentHash(r_hash_str=request.payment_hash)
    with _connect(context) as stub:
        lnd_res = stub.LookupInvoice(lnd_req, timeout=settings.IMPL_TIMEOUT)
        response.settled = False
        if lnd_res.state == 1:
            response.settled = True
    return response


@_handle_rpc_errors
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
    lnd_req = ln.SendRequest(payment_request=request.payment_request)
    if request.cltv_expiry_delta:
        if Enf.check_value(
                context, request.cltv_expiry_delta,
                enforce=Enf.CLTV_EXPIRY_DELTA):
            lnd_req.final_cltv_delta = request.cltv_expiry_delta
        else:
            Err().out_of_range(context, 'cltv_expiry_delta')
    # pylint: disable=no-member
    if request.amount_bits and invoice.amount_bits:
        Err().unsettable(context, 'amount_bits')
    elif request.amount_bits and not invoice.amount_bits:
        lnd_req.amt = convert(
            context, Enf.SATS, request.amount_bits,
            enforce=LND_LN_TX, max_precision=Enf.SATS)
    # pylint: enable=no-member
    with _connect(context) as stub:
        lnd_res = stub.SendPaymentSync(lnd_req, timeout=settings.IMPL_TIMEOUT)
        if lnd_res.payment_preimage:
            response.payment_preimage = hexlify(lnd_res.payment_preimage)
        elif lnd_res.payment_error:
            _handle_error(context, lnd_res.payment_error)
    return response


@_handle_rpc_errors
def PayOnChain(request, context):
    """ Tries to pay a bitcoin address """
    response = pb.PayOnChainResponse()
    check_req_params(context, request, 'address', 'amount_bits')
    lnd_req = ln.SendCoinsRequest(
        addr=request.address,
        amount=convert(
            context, Enf.SATS, request.amount_bits, enforce=Enf.OC_TX,
            max_precision=Enf.SATS))
    if request.fee_sat_byte:
        if Enf.check_value(
                context, request.fee_sat_byte, enforce=Enf.OC_FEE):
            lnd_req.sat_per_byte = request.fee_sat_byte
        else:
            Err().out_of_range(context, 'fee_sat_byte')
    with _connect(context) as stub:
        lnd_res = stub.SendCoins(lnd_req, timeout=settings.IMPL_TIMEOUT)
        response.txid = lnd_res.txid
    return response


@_handle_rpc_errors
def DecodeInvoice(request, context):
    """
    Tries to return information of a LN invoice from its payment request
    (bolt 11 standard)
    """
    response = pb.DecodeInvoiceResponse()
    check_req_params(context, request, 'payment_request')
    lnd_req = ln.PayReqString(pay_req=request.payment_request)
    with _connect(context) as stub:
        lnd_res = stub.DecodePayReq(lnd_req, timeout=settings.IMPL_TIMEOUT)
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
            _add_route_hint(response, lnd_route)
    return response


@_handle_rpc_errors
def OpenChannel(request, context):
    """ Tries to connect and open a channel with a peer """
    response = pb.OpenChannelResponse()
    check_req_params(context, request, 'node_uri', 'funding_bits')
    try:
        pubkey, host = request.node_uri.split("@")
    except ValueError:
        Err().invalid(context, 'node_uri')
    peer_address = ln.LightningAddress(pubkey=pubkey, host=host)
    lnd_req = ln.ConnectPeerRequest(addr=peer_address, perm=True)
    with _connect(context) as stub:
        lnd_res = stub.ConnectPeer(lnd_req, timeout=settings.IMPL_TIMEOUT)
        lnd_req = ln.OpenChannelRequest(
            node_pubkey_string=pubkey, private=request.private,
            local_funding_amount=convert(
                context, Enf.SATS, request.funding_bits,
                enforce=Enf.FUNDING_SATOSHIS,
                max_precision=Enf.SATS))
        if request.push_bits:
            lnd_req.push_sat = convert(context, Enf.SATS,
                                       request.push_bits,
                                       enforce=Enf.PUSH_MSAT,
                                       max_precision=Enf.SATS)
        lnd_res = stub.OpenChannelSync(lnd_req, timeout=settings.IMPL_TIMEOUT)
        response.funding_txid = lnd_res.funding_txid_str
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


def _check_timestamp(request, lnd_invoice):
    """
    Checks creation_date against search_timestamp to decide if invoice has to
    be skipped (not added to response)
    """
    if not request.search_timestamp:
        return False
    if request.list_order:
        # descending list_order
        if request.search_order:
            # descending search_order: use descending list, skip newer invoices
            # will stop when list reaches max_items size
            if lnd_invoice.creation_date >= request.search_timestamp:
                return True
        else:
            # ascending search_order: use ascending list, skip older invoices
            # must flip the list at the end
            if lnd_invoice.creation_date <= request.search_timestamp:
                return True
    else:
        # ascending list_order
        if request.search_order:
            # descending search_order: use descending list, skip newer invoices
            # must flip the list at the end
            if lnd_invoice.creation_date >= request.search_timestamp:
                return True
        else:
            # ascending search_order: use ascending list, skip older invoices
            # will stop when list reaches max_items size
            if lnd_invoice.creation_date <= request.search_timestamp:
                return True
    return False


def _parse_invoices(context, response, invoices, request):
    """
    Decides, according to the request, if invoice has to be added and which
    with state (paid, pending, expired)
    """
    now = datetime.now().timestamp()
    for lnd_invoice in invoices:
        if _check_timestamp(request, lnd_invoice):
            continue
        if request.paid and lnd_invoice.state == 1:
            _add_invoice(context, response, lnd_invoice, 0)
        if request.pending and not lnd_invoice.state == 1 and \
                (lnd_invoice.creation_date + lnd_invoice.expiry) > now:
            _add_invoice(context, response, lnd_invoice, 1)
        if request.expired and not lnd_invoice.state == 1 and \
                (lnd_invoice.creation_date + lnd_invoice.expiry) < now:
            _add_invoice(context, response, lnd_invoice, 2)
        if len(response.invoices) == request.max_items:
            return True
    return False


def _add_invoice(context, response, lnd_invoice, invoice_state):
    """ Adds an invoice to a ListInvoicesResponse """
    if lnd_invoice.ListFields():
        invoice = response.invoices.add(
            amount_bits=convert(context, Enf.SATS, lnd_invoice.value),
            timestamp=lnd_invoice.creation_date,
            payment_hash=hexlify(lnd_invoice.r_hash),
            description=lnd_invoice.memo,
            description_hash=hexlify(lnd_invoice.description_hash),
            expiry_time=lnd_invoice.expiry,
            fallback_addr=lnd_invoice.fallback_addr,
            state=invoice_state)
        for lnd_route in lnd_invoice.route_hints:
            _add_route_hint(invoice, lnd_route)


def _add_payment(context, response, lnd_payment):
    """ Adds a payment to a ListPaymentsResponse """
    if lnd_payment.ListFields():
        response.payments.add(
            payment_hash=lnd_payment.payment_hash,
            amount_bits=convert(context, Enf.MSATS, lnd_payment.value_msat),
            timestamp=lnd_payment.creation_date,
            fee_base_msat=lnd_payment.fee,
            payment_preimage=lnd_payment.payment_preimage)


def _add_transaction(context, response, lnd_transaction):
    """ Adds a transaction to a ListTransactionsResponse """
    if lnd_transaction.ListFields():
        transaction = response.transactions.add(
            txid=lnd_transaction.tx_hash,
            amount_bits=convert(context, Enf.SATS, lnd_transaction.amount),
            num_confirmations=lnd_transaction.num_confirmations,
            block_hash=lnd_transaction.block_hash,
            blockheight=lnd_transaction.block_height,
            timestamp=lnd_transaction.time_stamp,
            fee_sat=lnd_transaction.total_fees)
        if lnd_transaction.dest_addresses:
            transaction.dest_addresses.extend(lnd_transaction.dest_addresses)


def _add_route_hint(response, lnd_route):
    """ Adds a route hint and its hop hints to a DecodeInvoiceResponse """
    if lnd_route.ListFields():
        grpc_route = response.route_hints.add()
    for lnd_hop in lnd_route.hop_hints:
        grpc_route.hop_hints.add(
            pubkey=lnd_hop.node_id,
            short_channel_id=str(lnd_hop.chan_id),
            fee_base_msat=lnd_hop.fee_base_msat,
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
