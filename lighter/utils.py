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

""" The utils module for Lighter """

from decimal import Decimal, InvalidOperation
from importlib import import_module
from json import dumps, loads, JSONDecodeError
from logging import getLogger
from logging.config import dictConfig
from subprocess import PIPE, Popen, TimeoutExpired
from os import environ, path
from time import strftime

from . import lighter_pb2 as pb
from . import settings
from .errors import Err

LOGGER = getLogger(__name__)


def update_logger():
    """ Activate logs on file """
    settings.LOGS_DIR = environ['LOGS_DIR']
    log_path = path.join(path.abspath(settings.LOGS_DIR), 'lighter.log')
    settings.LOGGING['handlers'].update(settings.FILE_LOGGING)
    settings.LOGGING['loggers']['']['handlers'].append('file')
    settings.LOGGING['handlers']['file']['filename'] = log_path
    dictConfig(settings.LOGGING)


def log_intro():
    """ Prints a booting boilerplate to ease run distinction """
    LOGGER.info(' '*72)
    LOGGER.info(' '*72)
    LOGGER.info(' '*72)
    LOGGER.info('*'*72)
    LOGGER.info(' '*72)
    LOGGER.info('Lighter')
    LOGGER.info('version 0.1.0')
    LOGGER.info(' '*72)
    LOGGER.info('booting up at %s', strftime(settings.LOG_TIMEFMT))
    LOGGER.info(' '*72)
    LOGGER.info('*'*72)


def log_outro():
    """ Prints a quitting boilerplate to ease run distinction """
    LOGGER.info('stopping at %s', strftime(settings.LOG_TIMEFMT))
    LOGGER.info('*'*37)


def check_connection():
    """
    Calls a GetInfo in order to check if connection to node is successful
    """
    request = pb.GetInfoRequest()
    module = import_module('lighter.light_{}'.format(settings.IMPLEMENTATION))
    # If connection is unsuccessful, a runtime error is raised
    response = getattr(module, 'GetInfo')(request, FakeContext())
    return response


def get_connection_modes():
    """ Sets the connection modes to open """
    conn = {'insecure': environ.get('ALLOW_INSECURE_CONNECTION'),
            'secure': environ.get('ALLOW_SECURE_CONNECTION')}
    for mod, active in conn.items():
        try:
            conn[mod] = int(active)
        except Exception:  # pylint: disable=broad-except
            conn[mod] = None
    if not conn['insecure'] and not conn['secure']:
        raise RuntimeError('Allow at least one connection (secure/insecure)')
    settings.INSECURE_CONN = conn['insecure']
    settings.SECURE_CONN = conn['secure']


class FakeContext():  # pylint: disable=too-few-public-methods
    """
    Simulates a grpc server context in order to (re)define abort()

    This allows checking connection to node before a context is available from
    a client request
    """
    @staticmethod
    def abort(scode, msg):
        """ Raises a runtime error """
        assert scode
        raise RuntimeError(msg)


def command(context, *args_cmd):
    """ Given a command, calls a cli interface """
    if not settings.CMD_BASE:
        raise RuntimeError
    cmd = settings.CMD_BASE + list(args_cmd)
    # universal_newlines ensures bytes are returned
    proc = Popen(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=False)
    out = err = b''
    try:
        out, err = proc.communicate(timeout=settings.CMD_TIMEOUT)
    except TimeoutExpired:
        proc.kill()
    out = out.decode('utf-8')
    err = err.decode('utf-8')
    res = None
    try:
        res = loads(out)
    except JSONDecodeError:
        res = loads(dumps(out))
    if res is None or res == "":
        if err:
            Err().report_error(context, err)
        Err().unexpected_error(context, 'Empty result from command')
    return res


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

    FUNDING_SATOSHIS = {'max_value': 2**24, 'unit': SATS}
    LN_PAYREQ = {'min_value': 0, 'max_value': 2**32, 'unit': MSATS}
    LN_TX = {'min_value': 1, 'max_value': 2**32, 'unit': MSATS}

    OC_TX = {'min_value': 1, 'max_value': 2.1e15, 'unit': SATS}

    MIN_FINAL_CLTV_EXPIRY = {'min_value': 0, 'max_value': 500000000}
    CLTV_EXPIRY_DELTA = {'min_value': 0, 'max_value': 65536}

    # pylint: disable=dangerous-default-value
    @staticmethod
    def check_value(context, value, enforce=DEFAULT):
        """ Checks that value is between min_value and max_value """
        if settings.ENFORCE:
            if 'min_value' in enforce and value < enforce['min_value']:
                Err().value_too_low(context)
            if 'max_value' in enforce and value > enforce['max_value']:
                Err().value_too_high(context)
    # pylint: enable=dangerous-default-value


# pylint: disable=dangerous-default-value
def convert(context, unit, amount, enforce=None,
            max_precision=Enforcer.MSATS):
    """
    Converts amount from or to unit, according to enforce presence
    """
    if enforce:
        # input: converting from lighter to ln node (converts and enforces)
        source = Enforcer.BITS
        target = enforce['unit']
    else:
        # output: converting from ln node to lighter (converts only)
        source = unit
        target = Enforcer.BITS
    result = _convert_value(context, source, target, amount, max_precision)
    if enforce:
        Enforcer.check_value(context, result, enforce)
    return result


# pylint: enable=dangerous-default-value

def _convert_value(context, source, target, amount, max_precision):
    """
    Converts amount from source to target unit, rounding the result to the
    specified maximum precision
    """
    try:
        ratio = 1 / 10 ** (source['decimal'] - target['decimal'])
        decimals = 1 / 10 ** (max_precision['decimal'] - target['decimal'])
        converted = Decimal(amount) * Decimal(ratio)
        result = converted.quantize(Decimal(str(decimals)))
        if max_precision['decimal'] - target['decimal'] == 0:
            return int(result)
        return float(result)
    except InvalidOperation:
        Err().value_error(context)
