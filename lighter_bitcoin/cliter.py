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

"""
Implementation of a CLI (Command Line Interface) to command Lighter

- Exits with code 0 if everything is OK
- Exits with code 1 when a general client-side error occurs
- Exits with code 64 + <gRPC status code> when a gRPC error is raised by server
(https://github.com/grpc/grpc/blob/master/doc/statuscodes.md)

WARNING: new imports might require updating the package build system
"""

import sys

from codecs import encode
from configparser import Error as ConfigError
from contextlib import contextmanager
from functools import wraps
from json import dumps
from os import getcwd, path
from shutil import copyfile

from click import argument, echo, group, option, ParamType, pass_context, \
    version_option
from google.protobuf.json_format import MessageToJson
from grpc import channel_ready_future, composite_channel_credentials, \
    FutureTimeoutError, insecure_channel, metadata_call_credentials, \
    RpcError, secure_channel, ssl_channel_credentials

from . import __version__, lighter_pb2 as pb, lighter_pb2_grpc as pb_grpc, \
    settings as sett


class AddressType(ParamType):
    """ Custom type of AddressType proto enum """
    name = 'AddressType'

    def convert(self, value, param, ctx):
        """ Converts input value to corresponding AddressType enum """
        if value in ('0', 'NP2WKH', 'P2SH_SEGWIT',):
            return 0
        elif value in ('1', 'P2WKH', 'BECH32',):
            return 1
        self.fail('%s is not a valid %s' % (value, self.name), param, ctx)


def _get_address_type(ctx, args, incomplete):
    """ Autocompletion for AddressType """
    address_types = ('NP2WKH', 'P2WKH',)
    if incomplete == '': return address_types
    for k in address_types:
        return [k for k in address_types if k.startswith(incomplete)]


class Order(ParamType):
    """ Custom type of Order proto enum """
    name = 'Order'

    def convert(self, value, param, ctx):
        """ Converts input value to corresponding Order enum """
        if value in ('0', 'ASCENDING',):
            return 0
        elif value in ('1', 'DESCENDING',):
            return 1
        self.fail('%s is not a valid %s' % (value, self.name), param, ctx)


def _get_order(ctx, args, incomplete):
    """ Autocompletion for Order """
    orders = ('ASCENDING', 'DESCENDING',)
    if incomplete == '': return orders
    for k in orders:
        return [k for k in orders if k.startswith(incomplete)]


def _die(message=None, exit_code=1):
    """ Prints message to stderr with specified error code """
    if not message:
        message = 'Aborted'
    echo(message, err=True)
    sys.exit(exit_code)


def _check_rpcserver_addr():
    """ Checks the rpcserver address, adding port if missing """
    if not sett.CLI_RPCSERVER:
        _die('Invalid rpcserver address')
    rpcserver = sett.CLI_RPCSERVER.split(':', 1)
    if len(rpcserver) > 1:
        port = rpcserver[1]
        if not port.isdigit():
            _die('Invalid port')
        if int(port) not in range(1, 65536):
            _die('Invalid port')
    else:
        sett.CLI_RPCSERVER = sett.CLI_RPCSERVER + ':' + sett.PORT


def _get_cli_options():
    """ Sets CLI options """
    from .utils.misc import get_config_parser, get_path, set_defaults, str2bool
    config = get_config_parser(interactive=True)
    c_values = ['RPCSERVER', 'TLSCERT', 'MACAROON', 'INSECURE', 'NO_MACAROON']
    set_defaults(config, c_values)
    sec = 'cliter'
    if not sett.CLI_INSECURE:
        sett.CLI_INSECURE = str2bool(config.get(sec, 'INSECURE'))
    if not sett.CLI_NO_MACAROON:
        sett.CLI_NO_MACAROON = str2bool(config.get(sec, 'NO_MACAROON'))
    if not sett.CLI_RPCSERVER:
        sett.CLI_RPCSERVER = config.get(sec, 'RPCSERVER')
        _check_rpcserver_addr()
    if not sett.CLI_INSECURE:
        if not sett.CLI_TLSCERT:
            sett.CLI_TLSCERT = get_path(config.get(sec, 'TLSCERT'))
    else:
        sett.CLI_NO_MACAROON = True
    if not sett.CLI_NO_MACAROON:
        if not sett.CLI_MACAROON:
            sett.CLI_MACAROON = get_path(config.get(sec, 'MACAROON'))


def handle_call(func):
    """ Decorator to handle a gRPC call to Lighter """

    @wraps(func)
    def wrapper(*args, **kwargs):
        """ Gets start options and runs wrapped function """
        try:
            _get_cli_options()
            api, req = func(*args, **kwargs)
            stub_name = _get_stub_name(api)
            with _connect(stub_name) as stub:
                res = getattr(stub, api)(req, timeout=sett.CLI_TIMEOUT)
            _print_res(res)
        except RpcError as err:
            # pylint: disable=no-member
            json_err = {
                'code': err.code().name, 'details': err.details()}
            error = dumps(json_err, indent=4, sort_keys=True)
            _die(error, sett.CLI_BASE_GRPC_CODE + err.code().value[0])
        except ConfigError as err:
            _die('Configuration error: {}'.format(err))
        except Exception as err:
            _die('Error, terminating cli: {}'.format(err))

    return wrapper


def _print_res(response):
    """ Prints response using JSON format """
    echo(MessageToJson(response, including_default_value_fields=True,
                       preserving_proto_field_name=True, sort_keys=True))


def _get_stub_name(api):
    """ Gets name of servicer based on api name """
    if api in ('UnlockLighter',): return 'UnlockerStub'
    if api in ('LockLighter',): return 'LockerStub'
    return 'LightningStub'


@contextmanager
def _connect(stub_class):
    """ Connects to Lighter using gRPC (securely or insecurely) """
    channel = None
    if sett.CLI_INSECURE:
        channel = insecure_channel(sett.CLI_RPCSERVER)
    else:
        if sett.CLI_NO_MACAROON:
            creds = _get_credentials(None)
        else:
            creds = _get_credentials(_metadata_callback)
        channel = secure_channel(sett.CLI_RPCSERVER, creds)
    future_channel = channel_ready_future(channel)
    try:
        future_channel.result(timeout=sett.CLI_TIMEOUT)
    except FutureTimeoutError:
        # Handle gRPC channel that did not connect
        _die('Failed to dial server')
    else:
        stub = getattr(pb_grpc, stub_class)(channel)
        yield stub
        channel.close()


def _get_credentials(callback):
    """
    Gets credentials to open a secure gRPC channel (with or without macaroons)
    """
    with open(sett.CLI_TLSCERT, 'rb') as file:
        cert = file.read()
    creds = cert_creds = ssl_channel_credentials(root_certificates=cert)
    if callback:  # macaroons are enabled
        if not path.exists(sett.CLI_MACAROON):
            _die('Macaroon file not found')
        auth_creds = metadata_call_credentials(callback)
        creds = composite_channel_credentials(cert_creds, auth_creds)
    return creds


def _metadata_callback(_context, callback):
    """ Gets Lighter's macaroon to be included in the gRPC request """
    with open(sett.CLI_MACAROON, 'rb') as file:
        macaroon_bytes = file.read()
        macaroon = encode(macaroon_bytes, 'hex')
    callback([('macaroon', macaroon)], None)


@group()
@option('--config', nargs=1, help='Path to cliter configuration file '
        '(default ~/.lighter/config)')
@option('--rpcserver', nargs=1, help='Set host[:port] of Lighter gRPC server')
@option('--tlscert', nargs=1, help='Path to Lighter\'s TLS certificate')
@option('--macaroon', nargs=1, help='Path to Lighter\'s macaroon')
@option('--insecure', is_flag=True, help='Do not use TLS and macaroon')
@option('--no-macaroon', is_flag=True, help='Do not use macaroon')
@version_option(version=__version__, message='%(version)s')
@pass_context
def entrypoint(ctx, config, rpcserver, tlscert, macaroon, insecure,
               no_macaroon):
    """
    Cliter, a CLI for Lighter.

    Paths are relative to the working directory.
    """
    incompatible_opts = {
        'insecure': ['tlscert', 'macaroon'],
        'no_macaroon': ['macaroon'],
    }
    passed_params = [param for param in ctx.params if ctx.params[param]]
    for param in passed_params:
        if param in incompatible_opts:
            if any(opt in passed_params for opt in incompatible_opts[param]):
                _die('Incompatible options')

    if config is not None:
        if not config:
            _die('Invalid configuration file')
        from .utils.misc import get_path
        sett.L_CONFIG = get_path(config, base_path=getcwd())
    if rpcserver is not None:
        sett.CLI_RPCSERVER = rpcserver
        _check_rpcserver_addr()
    if tlscert is not None:
        if not tlscert or not path.exists(tlscert):
            _die('Missing TLS certificate "{}"'.format(tlscert))
        sett.CLI_TLSCERT = tlscert
    if macaroon is not None:
        if not macaroon or not path.exists(macaroon):
            _die('Missing macaroon "{}"'.format(macaroon))
        sett.CLI_MACAROON = macaroon
    if insecure:
        sett.CLI_INSECURE = True
    if no_macaroon:
        sett.CLI_NO_MACAROON = True


@entrypoint.command()
@option('--password', prompt='Insert Lighter\'s password', hide_input=True,
        help='Lighter\'s password to unlock the runtime service')
@option('--unlock-node', is_flag=True, help='Whether to also unlock the LN '
        'node. Node unlock may not be available (implementation does not have'
        ' a locking system) or fail (missing configuration or connection '
        'issues) but the whole UnlockLighter operation will still succeed')
@handle_call
def unlocklighter(password, unlock_node):
    """
    UnlockLighter unlocks Lighter's secrets using the password chosen during
    the secure phase. The underlying node can also be unlocked, but failures
    will be ignored. This call does not require macaroon authentication.
    """
    req = pb.UnlockLighterRequest(password=password, unlock_node=unlock_node)
    return 'UnlockLighter', req


@entrypoint.command()
@option('--password', prompt='Insert Lighter\'s password',
        hide_input=True, help='Lighter\'s password to lock the runtime '
        'service')
@handle_call
def locklighter(password):
    """
    LockLighter locks Lighter using the password chosen during the secure
    phase. This stops the runtime server (LightningServicer + LockerServicer)
    and deletes secrets from runtime memory.
    """
    req = pb.LockLighterRequest(password=password)
    return 'LockLighter', req


@entrypoint.command()
@handle_call
def channelbalance():
    """
    ChannelBalance returns the off-chain balance, in bits, available across all
    channels.
    """
    req = pb.ChannelBalanceRequest()
    return 'ChannelBalance', req


@entrypoint.command()
@argument('payment_hash', nargs=1)
@handle_call
def checkinvoice(payment_hash):
    """ CheckInvoice checks if a LN invoice has been paid. """
    req = pb.CheckInvoiceRequest(payment_hash=payment_hash)
    return 'CheckInvoice', req


@entrypoint.command()
@argument('channel_id')
@option('--force', is_flag=True, help="Whether to force a unilateral close "
        "(necessary if peer's offline)")
@handle_call
def closechannel(channel_id, force):
    """
    CloseChannel closes a LN channel.
    If the operation succeds it returns the ID of the closing transaction.
    If the operation takes more than the client timeout, it returns an empty
    response. The operation could still complete.
    In the other cases the operation will fail with an appropriate message.
    """
    req = pb.CloseChannelRequest(channel_id=channel_id, force=force)
    return 'CloseChannel', req


@entrypoint.command()
@option('--amount_bits', nargs=1, type=float, help='Invoice amount, in bits')
@option('--description', nargs=1, help='Description of the invoice')
@option('--expiry_time', nargs=1, type=int, help='Invoice expiration time, '
        'in seconds (default: 420)')
@option('--min_final_cltv_expiry', nargs=1, type=int, help='CTLV delay '
        '(absolute) to use for the final hop in the route')
@option('--fallback_addr', nargs=1, help='Fallback address (on-chain) to use '
        'if the LN payment fails')
@handle_call
def createinvoice(amount_bits, description, expiry_time, min_final_cltv_expiry,
                  fallback_addr):
    """ CreateInvoice creates a LN invoice (BOLT 11). """
    req = pb.CreateInvoiceRequest(
        amount_bits=amount_bits,
        description=description,
        expiry_time=expiry_time,
        min_final_cltv_expiry=min_final_cltv_expiry,
        fallback_addr=fallback_addr)
    return 'CreateInvoice', req


@entrypoint.command()
@argument('payment_request', nargs=1)
@option('--description', nargs=1, help='Invoice description, whose hash should'
        ' match the description hash in the payment request (if present)')
@handle_call
def decodeinvoice(payment_request, description):
    """
    DecodeInvoice returns information of a LN invoice from its payment
    request (BOLT 11).
    """
    req = pb.DecodeInvoiceRequest(
        payment_request=payment_request,
        description=description)
    return 'DecodeInvoice', req


@entrypoint.command()
@handle_call
def getinfo():
    """ GetInfo returns info about the connected LN node. """
    req = pb.GetInfoRequest()
    return 'GetInfo', req


@entrypoint.command()
@option('--active_only', is_flag=True, help='Whether to return active '
        'channels only (channel is open and peer is online)')
@handle_call
def listchannels(active_only):
    """ ListChannels returns a list of channels of the connected LN node. """
    req = pb.ListChannelsRequest(active_only=active_only)
    return 'ListChannels', req


@entrypoint.command()
@option('--max_items', nargs=1, type=int, help='Maximum number of invoices '
        'to be returned (default: 200)')
@option('--search_timestamp', nargs=1, type=int, help='Timestamp to be used '
        'as starting point for the search')
@option('--search_order', nargs=1, type=Order(), autocompletion=_get_order,
        help='Search direction - requires search_timestamp (default: '
        'ascending)')
@option('--list_order', nargs=1, type=Order(), autocompletion=_get_order,
        help='Order of the returned invoices (default: ascending)')
@option('--paid', is_flag=True, help='Whether to include paid invoices')
@option('--pending', is_flag=True, help='Whether to include pending invoices')
@option('--expired', is_flag=True, help='Whether to include expired invoices')
@handle_call
def listinvoices(max_items, search_timestamp, search_order, list_order, paid,
                 pending, expired):
    """
    ListInvoices returns a list of invoices created by the connected LN node.
    """
    req = pb.ListInvoicesRequest(
        max_items=max_items,
        search_timestamp=search_timestamp,
        search_order=search_order,
        list_order=list_order,
        paid=paid,
        pending=pending,
        expired=expired)
    return 'ListInvoices', req


@entrypoint.command()
@handle_call
def listpayments():
    """
    ListPayments returns a list of invoices the connected LN node has paid.
    """
    req = pb.ListPaymentsRequest()
    return 'ListPayments', req


@entrypoint.command()
@handle_call
def listpeers():
    """
    ListPeers returns a list of peers connected to the connected LN node.
    """
    req = pb.ListPeersRequest()
    return 'ListPeers', req


@entrypoint.command()
@handle_call
def listtransactions():
    """
    ListTransactions returns a list of on-chain transactions of the connected
    LN node.
    """
    req = pb.ListTransactionsRequest()
    return 'ListTransactions', req


@entrypoint.command()
@option('--type', nargs=1, type=AddressType(),
        autocompletion=_get_address_type, help='Bitcoin address type (P2WKH '
        'or NP2WKH)')
@handle_call
def newaddress(type):
    """
    NewAddress creates a new bitcoin address under control of the connected LN
    node.
    """
    req = pb.NewAddressRequest(type=type)
    return 'NewAddress', req


@entrypoint.command()
@argument('node_uri', nargs=1)
@argument('funding_bits', nargs=1, type=float)
@option('--push_bits', nargs=1, type=float, help='Amount (taken '
        'from funding_bits) to be pushed to peer, in bits')
@option('--private', is_flag=True, help='Whether the channel will be private '
        '(not anonunced)')
@handle_call
def openchannel(node_uri, funding_bits, push_bits, private):
    """ OpenChannel tries to connect and open a channel with a peer. """
    req = pb.OpenChannelRequest(
        node_uri=node_uri,
        funding_bits=funding_bits,
        push_bits=push_bits,
        private=private)
    return 'OpenChannel', req


@entrypoint.command()
@argument('payment_request', nargs=1)
@option('--amount_bits', nargs=1, type=float, help='Value to be paid, in bits')
@option('--description', nargs=1, help='Invoice description, whose hash should'
        ' match the description hash in the payment request (if present)')
@option('--cltv_expiry_delta', nargs=1, type=int, help='Delta to use for the '
        'time-lock of the CLTV (absolute) extended to the final hop')
@handle_call
def payinvoice(payment_request, amount_bits, description, cltv_expiry_delta):
    """
    PayInvoice tries to pay a LN invoice from its payment request (BOLT 11).
    An amount can be specified if the invoice doesn't already have it
    included. If a description hash is included in the invoice, its preimage
    must be included in the request.
    """
    req = pb.PayInvoiceRequest(
        payment_request=payment_request,
        amount_bits=amount_bits,
        description=description,
        cltv_expiry_delta=cltv_expiry_delta)
    return 'PayInvoice', req


@entrypoint.command()
@argument('address', nargs=1)
@argument('amount_bits', nargs=1, type=float)
@option('--fee_sat_byte', nargs=1, type=int, help='Fee rate in satoshi per '
        'byte')
@handle_call
def payonchain(address, amount_bits, fee_sat_byte):
    """ PayOnChain tries to pay a bitcoin payment request. """
    req = pb.PayOnChainRequest(
        address=address,
        amount_bits=amount_bits,
        fee_sat_byte=fee_sat_byte)
    return 'PayOnChain', req


@entrypoint.command()
@option('--password', prompt='Insert Lighter\'s password',
        hide_input=True, help='Lighter\'s password to decrypt the underlying '
        'node\'s secret')
@handle_call
def unlocknode(password):
    """
    UnlockNode tries to unlock the underlying node. Requires an implementation
    that supports a locking mechanism and the password must have been provided
    during Lighter's secure phase.
    """
    req = pb.UnlockNodeRequest(password=password)
    return 'UnlockNode', req


@entrypoint.command()
@handle_call
def walletbalance():
    """ WalletBalance returns the on-chain balance, in bits. """
    req = pb.WalletBalanceRequest()
    return 'WalletBalance', req
