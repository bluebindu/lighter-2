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

from contextlib import suppress
from decimal import Decimal, InvalidOperation
from functools import wraps
from importlib import import_module
from json import dumps, loads, JSONDecodeError
from logging import getLogger
from logging.config import dictConfig
from marshal import dumps as mdumps, loads as mloads
from os import environ as env, path
from subprocess import PIPE, Popen, TimeoutExpired
from threading import active_count, current_thread
from time import sleep, strftime, time

from . import lighter_pb2 as pb

from . import __version__, settings as sett
from .db import get_secret_from_db, get_token_from_db
from .errors import Err

LOGGER = getLogger(__name__)


def update_logger():
    """ Activate logs on file """
    sett.LOGS_LEVEL = env.get('LOGS_LEVEL', sett.LOG_LEVEL_CONSOLE).upper()
    sett.LOGGING['handlers']['console']['level'] = sett.LOGS_LEVEL
    sett.LOGS_DIR = env.get('LOGS_DIR', sett.LOGS_DIR)
    log_path = path.join(path.abspath(sett.LOGS_DIR), sett.LOGS_LIGHTER)
    sett.LOGGING['handlers']['file']['filename'] = log_path
    dictConfig(sett.LOGGING)


def log_intro():
    """ Prints a booting boilerplate to ease run distinction """
    LOGGER.info(' '*72)
    LOGGER.info(' '*72)
    LOGGER.info(' '*72)
    LOGGER.info('*'*72)
    LOGGER.info(' '*72)
    LOGGER.info('Lighter')
    LOGGER.info('version %s', __version__)
    LOGGER.info(' '*72)
    LOGGER.info('booting up at %s', strftime(sett.LOG_TIMEFMT))
    LOGGER.info(' '*72)
    LOGGER.info('*'*72)


def log_outro():
    """ Prints a quitting boilerplate to ease run distinction """
    LOGGER.info('stopping at %s', strftime(sett.LOG_TIMEFMT))
    LOGGER.info('*'*37)


def check_connection():
    """
    Calls a GetInfo in order to check if connection to node is successful
    """
    request = pb.GetInfoRequest()
    module = import_module('lighter.light_{}'.format(sett.IMPLEMENTATION))
    info = None
    LOGGER.info('Checking connection to %s node...', sett.IMPLEMENTATION)
    while not info:
        try:
            info = getattr(module, 'GetInfo')(request, FakeContext())
        except RuntimeError as err:
            LOGGER.error('Connection to LN node failed: %s', str(err).strip())
        if not info:
            sleep(3)
            continue
        if info.identity_pubkey:
            LOGGER.info(
                'Connection to node "%s" successful', info.identity_pubkey)
        if info.version:
            LOGGER.info(
                'Using %s version %s', sett.IMPLEMENTATION, info.version)
        else:
            LOGGER.info('Using %s', sett.IMPLEMENTATION)


def get_start_options(warning=False):
    """ Sets Lighter start options """
    sett.IMPLEMENTATION = env['IMPLEMENTATION'].lower()
    bool_opt = {
        'INSECURE_CONNECTION': sett.INSECURE_CONNECTION,
        'DISABLE_MACAROONS': sett.DISABLE_MACAROONS}
    for opt, def_val in bool_opt.items():
        setattr(sett, opt, str2bool(env.get(opt, def_val)))
    sett.PORT = env.get('PORT', sett.PORT)
    sett.LIGHTER_ADDR = '{}:{}'.format(sett.HOST, sett.PORT)
    if sett.INSECURE_CONNECTION:
        sett.DISABLE_MACAROONS = True
    else:
        sett.SERVER_KEY = env.get('SERVER_KEY', sett.SERVER_KEY)
        sett.SERVER_CRT = env.get('SERVER_CRT', sett.SERVER_CRT)
    if sett.DISABLE_MACAROONS:
        if warning:
            LOGGER.warning('Disabling macaroons is not safe, '
                           'do not disable them in production')
    else:
        sett.MACAROONS_DIR = env.get('MACAROONS_DIR', sett.MACAROONS_DIR)
    sett.DB_DIR = env.get('DB_DIR', sett.DB_DIR)
    if sett.IMPLEMENTATION == 'eclair':
        sett.IMPL_SEC_TYPE = 'password'
    if sett.IMPLEMENTATION == 'lnd':
        sett.IMPL_SEC_TYPE = 'macaroon'


def detect_impl_secret(session):
    """ Detects if implementation has a secret stored """
    if sett.IMPLEMENTATION == 'clightning':
        return False
    detected = False
    error = False
    impl_secret = get_secret_from_db(
        session, sett.IMPLEMENTATION, sett.IMPL_SEC_TYPE)
    if sett.IMPLEMENTATION == 'eclair':
        detected = True  # secret always necessary when using eclair
        if not impl_secret or not impl_secret.secret:
            error = True
    if sett.IMPLEMENTATION == 'lnd':
        if impl_secret and impl_secret.active:
            detected = True
            if not impl_secret.secret:
                error = True
    if error:
        raise RuntimeError(
            'Cannot obtain implementation secret, add it by running make '
            'secure')
    return detected


def str2bool(string, force_true=False):
    """ Casts a string to boolean, forcing to a default value """
    if isinstance(string, int):
        string = str(string)
    if not string and not force_true:
        return False
    if not string and force_true:
        return True
    if force_true:
        return string.lower() not in ('no', 'false', 'n', '0')
    return string.lower() in ('yes', 'true', 'y', '1')


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

    @staticmethod
    def time_remaining():
        """ Acts as no timeout has been set by client """
        return None


def command(context, *args_cmd, **kwargs):
    """ Given a command, calls a cli interface """
    if not sett.CMD_BASE:
        raise RuntimeError
    cmd = sett.CMD_BASE + list(args_cmd)
    envi = kwargs.get('env', None)
    wait_time = kwargs.get('timeout', get_node_timeout(context))
    # universal_newlines ensures bytes are returned
    proc = Popen(
        cmd, env=envi, stdout=PIPE, stderr=PIPE, universal_newlines=False)
    out = err = b''
    try:
        out, err = proc.communicate(timeout=wait_time)
    except TimeoutExpired:
        proc.kill()
        Err().node_error(context, 'Timeout')
    out = out.decode('utf-8')
    err = err.decode('utf-8')
    res = None
    try:
        res = loads(out)
    except JSONDecodeError:
        res = loads(dumps(out))
    if res is None or res == "":
        if err:
            Err().report_error(context, err.strip())
        LOGGER.debug('Empty result from command')
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


def check_req_params(context, request, *parameters):
    """
    Raises a missing_parameter error if one of parameters is not given in the
    request
    """
    for param in parameters:
        if not getattr(request, param):
            Err().missing_parameter(context, param)


def get_node_timeout(context, min_time=sett.IMPL_MIN_TIMEOUT):
    """
    Calculates timeout to use when calling LN node considering client's
    timeout
    """
    node_timeout = min_time
    client_time = context.time_remaining()
    if client_time and client_time > node_timeout:
        node_timeout = client_time - sett.RESPONSE_RESERVED_TIME
    node_timeout = min(sett.IMPL_MAX_TIMEOUT, node_timeout)
    return node_timeout


def get_thread_timeout(context):
    """ Calculates timeout for future.result() """
    wait_time = sett.THREAD_TIMEOUT
    if context.time_remaining():
        # subtracting time to do the request and answer to the client
        wait_time = context.time_remaining() - sett.RESPONSE_RESERVED_TIME
    if wait_time < 0:
        wait_time = 0
    return wait_time


def handle_keyboardinterrupt(func):
    """ Handles KeyboardInterrupt stopping the gRPC server and exiting """

    @wraps(func)
    def wrapper(*args, **kwargs):
        close_event = None
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            with suppress(IndexError):
                close_event = args[0].stop(sett.GRPC_GRACE_TIME)
                print()

            LOGGER.error('Keyboard interrupt detected.')
            if close_event:
                while not close_event.is_set() or sett.THREADS:
                    LOGGER.error('Waiting for %s threads to complete...',
                                 active_count())
                    sleep(3)
            LOGGER.info('All threads shutdown correctly')
            raise RuntimeError

    return wrapper


def handle_logs(func):
    """ Logs gRPC call request and response """

    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time()
        peer = user_agent = 'unknown'
        request = args[0]
        context = args[1]
        if len(args) == 3:
            request = args[1]
            context = args[2]
        with suppress(ValueError):
            peer = context.peer().split(':', 1)[1]
        for data in context.invocation_metadata():
            if data.key == 'user-agent':
                user_agent = data.value
        LOGGER.info('< %-24s %s %s',
                    request.DESCRIPTOR.name, peer, user_agent)
        response = func(*args, **kwargs)
        response_name = response.DESCRIPTOR.name
        stop_time = time()
        call_time = round(stop_time - start_time, 3)
        LOGGER.info('> %-24s %s %2.3fs',
                    response_name, peer, call_time)
        LOGGER.debug('Full response: %s', str(response).replace('\n', ' '))
        return response

    return wrapper


def handle_thread(func):
    """ Adds and removes async threads from global list """

    @wraps(func)
    def wrapper(*args, **kwargs):
        sett.THREADS.append(current_thread())
        try:
            res = func(*args, **kwargs)
            sett.THREADS.remove(current_thread())
            return res
        except Exception as exc:
            sett.THREADS.remove(current_thread())
            raise exc

    return wrapper


def has_amount_encoded(payment_request):
    """ Checks if a bech32 payment request has an amount encoded """
    separator = payment_request.rfind('1')
    hrp = payment_request[:separator]
    return _has_numbers(set(hrp))


def _has_numbers(input_string):
    """ Checks if string contains any number """
    return any(char.isdigit() for char in input_string)


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
        out_tot_now += chan.local_balance
        in_tot_now += chan.remote_balance
        local_reserve = convert(context, Enforcer.SATS, chan.local_reserve_sat)
        if chan.local_balance - local_reserve > out_max_now:
            out_max_now = chan.local_balance - local_reserve
        remote_reserve = convert(
            context, Enforcer.SATS, chan.remote_reserve_sat)
        if chan.remote_balance - remote_reserve > in_max_now:
            in_max_now = chan.remote_balance - remote_reserve
    return pb.ChannelBalanceResponse(
        balance=out_tot, out_tot_now=out_tot_now, out_max_now=out_max_now,
        in_tot=in_tot, in_tot_now=in_tot_now, in_max_now=in_max_now)


def check_password(context, session, password):
    """
    Checks the inserted password by generating an access key and trying
    to decrypt the token in the db
    """
    encrypted_token, params = get_token_from_db(session)
    token_params = ScryptParams('')
    token_params.deserialize(params)
    derived_key = Crypter.gen_derived_key(password, token_params)
    clear_token = Crypter.decrypt(context, encrypted_token, derived_key)
    if clear_token != sett.ACCESS_TOKEN:
        Err().wrong_password(context)


# pylint: disable=too-many-arguments
def get_secret(context, session, password, impl, sec_type, active_only=False):
    """ Retrieves and decrypts implementation secret from DB """
    impl_secret = get_secret_from_db(session, impl, sec_type)
    if not impl_secret or not impl_secret.secret:
        return None
    if active_only and not impl_secret.active:
        return None
    params = ScryptParams('')
    params.deserialize(impl_secret.scrypt_params)
    derived_key = Crypter.gen_derived_key(password, params)
    return Crypter.decrypt(context, impl_secret.secret, derived_key)
    # pylint: enable=too-many-arguments


class ScryptParams():
    """ Convenient class to store scrypt parameters """

    # pylint: disable=too-many-arguments
    def __init__(self, salt,
                 cost_factor=sett.SCRYPT_PARAMS['cost_factor'],
                 block_size_factor=sett.SCRYPT_PARAMS['block_size_factor'],
                 parallelization_factor=sett.SCRYPT_PARAMS
                 ['parallelization_factor'],
                 key_len=sett.SCRYPT_PARAMS['key_len']):
        self.salt = salt
        self.cost_factor = cost_factor
        self.block_size_factor = block_size_factor
        self.parallelization_factor = parallelization_factor
        self.key_len = key_len
        # pylint: enable=too-many-arguments

    def serialize(self):
        """ Serializes ScryptParams """
        return mdumps(
            [self.salt, self.cost_factor, self.block_size_factor,
             self.parallelization_factor, self.key_len])

    def deserialize(self, serialized):
        """ Deserializes ScryptParams """
        deserialized = mloads(serialized)
        self.salt = deserialized[0]
        self.cost_factor = deserialized[1]
        self.block_size_factor = deserialized[2]
        self.parallelization_factor = deserialized[3]
        self.key_len = deserialized[4]


class Crypter():  # pylint: disable=too-many-instance-attributes
    """
    Crypter provides methods to encrypt and decrypt data and to generate
    a derived key from a password.
    """

    @staticmethod
    def gen_derived_key(password, scrypt_params):
        """ Derives a key from a password using Scrypt """
        # pylint: disable=import-outside-toplevel
        from pylibscrypt import scrypt
        return scrypt(
            bytes(password, 'utf-8'),
            scrypt_params.salt,
            N=scrypt_params.cost_factor,
            r=scrypt_params.block_size_factor,
            p=scrypt_params.parallelization_factor,
            olen=scrypt_params.key_len)

    @staticmethod
    def crypt(clear_data, derived_key):
        """
        Crypts data using Secretbox and the access key.
        It returns the encrypted data in a serialized form
        """
        # pylint: disable=import-outside-toplevel
        from nacl.secret import SecretBox
        return SecretBox(derived_key).encrypt(clear_data)

    @staticmethod
    def decrypt(context, encrypted_data, derived_key):
        """
        Decrypts serialized data using Secretbox and the access key.
        Throws an error when password is wrong
        """
        # pylint: disable=import-outside-toplevel
        from nacl.exceptions import CryptoError
        from nacl.secret import SecretBox
        try:
            return SecretBox(derived_key).decrypt(encrypted_data)
        except CryptoError:
            Err().wrong_password(context)
