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

""" Bitcoin and Lightning Network utils module """

from decimal import Context, Decimal, Inexact, InvalidOperation
from logging import getLogger

from .. import lighter_pb2 as pb, settings as sett
from ..errors import Err

LOGGER = getLogger(__name__)


def convert(context, unit, amount, enforce=None, max_precision=None):
    """
    Handles the conversion of btc measure units to and from bits.

    If enforce is set, check the value in bits against the given boundaries
    and then convert it to the unit required by the node.
    If enforce is not set, output the value in bits (assuming correctness
    of the value coming from the node).

    If the output unit matches the max precision, the value is returned as
    an integer to comply with node requirements.
    """
    if enforce:
        # input: converting from lighter to ln node (converts and enforces)
        if not max_precision:
            max_precision = enforce['unit']
        source = Enforcer.BITS
        target = unit
    else:
        # output: converting from ln node to lighter (converts only)
        if not max_precision:
            max_precision = Enforcer.MSATS
        source = unit
        target = Enforcer.BITS
    return _convert_value(context, source, target, amount, max_precision,
                          enforce)


# pylint: disable=too-many-arguments
def _convert_value(context, source, target, amount, max_precision,
                   enforce=None):
    """
    Converts amount from source to target unit, rounding the result to the
    specified maximum precision
    """
    try:
        amount = Decimal(str(amount))
    except InvalidOperation:
        # An invalid number would be blocked by the interface,
        # so this case has to come from the node
        Err().internal_value_error(context)
    if enforce:
        ratio = enforce['unit']['decimal'] - source['decimal']
        Enforcer.check_value(context, amount.scaleb(ratio), enforce)
    ratio = target['decimal'] - source['decimal']
    decimals = target['decimal'] - max_precision['decimal']
    try:
        converted = amount.scaleb(ratio)
        # cuts the amount to the required precision,
        # raising exceptions in case of inexact conversion
        result = converted.quantize(Decimal(1).scaleb(decimals),
                                    context=Context(traps=[Inexact,
                                                           InvalidOperation]))
        if max_precision['decimal'] == target['decimal']:
            int_result = int(result)
            return int_result
        return float(result)
    except (Inexact, InvalidOperation):
        Err().value_error(context)


def get_address_type(address):
    """ Returns the type of an address """
    if address[0] in ['b', 't']:
        return pb.P2WKH
    return pb.NP2WKH


def get_channel_balances(context, channels):
    """ Calculates channel balances from a ListChannelsResponse """
    out_tot = out_tot_now = out_max_now = in_tot = in_tot_now = in_max_now = 0
    for chan in channels:
        if chan.state != pb.OPEN:
            continue
        out_tot += chan.local_balance
        in_tot += chan.remote_balance
        if not chan.active:
            continue
        local_reserve = convert(context, Enforcer.SATS, chan.local_reserve_sat)
        remote_reserve = convert(
            context, Enforcer.SATS, chan.remote_reserve_sat)
        out_tot_now += \
            Decimal(str(chan.local_balance)) - Decimal(str(local_reserve))
        in_tot_now += \
            Decimal(str(chan.remote_balance)) - Decimal(str(remote_reserve))
        if chan.local_balance - local_reserve > out_max_now:
            out_max_now = \
                Decimal(str(chan.local_balance)) - Decimal(str(local_reserve))
        if chan.remote_balance - remote_reserve > in_max_now:
            in_max_now = Decimal(str(chan.remote_balance)) - \
                Decimal(str(remote_reserve))
    return pb.ChannelBalanceResponse(
        balance=out_tot, out_tot_now=out_tot_now, out_max_now=out_max_now,
        in_tot=in_tot, in_tot_now=in_tot_now, in_max_now=in_max_now)


def has_amount_encoded(payment_request):
    """ Checks if a bech32 payment request has an amount encoded """
    separator = payment_request.rfind('1')
    hrp = payment_request[:separator]
    return _has_numbers(set(hrp))


def _has_numbers(input_string):
    """ Checks if string contains any number """
    return any(char.isdigit() for char in input_string)


class Enforcer():  # pylint: disable=too-few-public-methods
    """
    Enforces BOLTs rules and value limits.
    """

    BTC = {'name': 'btc', 'decimal': 0}
    MBTC = {'name': 'mbtc', 'decimal': 3}
    BITS = {'name': 'bits', 'decimal': 6}
    SATS = {'name': 'sats', 'decimal': 8}
    MSATS = {'name': 'msats', 'decimal': 11}

    DEFAULT = {'min_value': 0, 'unit': MSATS}

    # BOLT2 suggests (but does not enforce) a reserve of 1% of the channel
    # funding total, and the reserve cannot be lower than the dust limit.
    FUNDING_SATOSHIS = {'min_value': 100 * sett.DUST_LIMIT_SAT,
                        'max_value': 2**24, 'unit': SATS}
    PUSH_MSAT = {'max_value': 2**24 * 1000, 'unit': MSATS}
    LN_PAYREQ = {'min_value': 0, 'max_value': 2**32, 'unit': MSATS}
    LN_TX = {'min_value': 1, 'max_value': 2**32, 'unit': MSATS}

    OC_TX = {'min_value': 1, 'max_value': 2.1e15, 'unit': SATS}
    # assuming minimum 220 bytes tx and single 21M BTC input
    OC_FEE = {'min_value': 1, 'max_value': 2.1e15 / 220, 'unit': SATS}

    MIN_FINAL_CLTV_EXPIRY = {'min_value': 1, 'max_value': 5e8}
    CLTV_EXPIRY_DELTA = {'min_value': 1, 'max_value': 2**16}

    # pylint: disable=dangerous-default-value
    @staticmethod
    def check_value(context, value, enforce=DEFAULT):
        """ Checks that value is between min_value and max_value """
        if sett.ENFORCE:
            if 'min_value' in enforce and value < enforce['min_value']:
                Err().value_too_low(context)
            if 'max_value' in enforce and value > enforce['max_value']:
                Err().value_too_high(context)
        return True
    # pylint: enable=dangerous-default-value
