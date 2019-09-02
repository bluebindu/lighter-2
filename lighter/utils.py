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

import sys

from contextlib import suppress
from decimal import Decimal, InvalidOperation
from functools import wraps
from importlib import import_module
from json import dumps, loads, JSONDecodeError
from logging import getLogger
from logging.config import dictConfig
from marshal import dumps as mdumps, loads as mloads
from os import environ as env, path
from sqlite3 import connect, Error
from subprocess import PIPE, Popen, TimeoutExpired
from threading import active_count, current_thread
from time import sleep, strftime, time

from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from pylibscrypt import scrypt

from . import lighter_pb2 as pb
from . import settings as sett
from .errors import Err

LOGGER = getLogger(__name__)


def update_logger():
    """ Activate logs on file """
    sett.LOGS_LEVEL = env.get('LOGS_LEVEL', sett.LOG_LEVEL_CONSOLE).upper()
    sett.LOGGING['handlers']['console']['level'] = sett.LOGS_LEVEL
    sett.LOGS_DIR = env.get('LOGS_DIR', sett.LOGS_DIR)
    log_path = path.join(path.abspath(sett.LOGS_DIR), 'lighter.log')
    sett.LOGGING['handlers'].update(sett.FILE_LOGGING)
    sett.LOGGING['loggers']['']['handlers'].append('file')
    sett.LOGGING['handlers']['file']['filename'] = log_path
    dictConfig(sett.LOGGING)


def log_intro(version):
    """ Prints a booting boilerplate to ease run distinction """
    LOGGER.info(' '*72)
    LOGGER.info(' '*72)
    LOGGER.info(' '*72)
    LOGGER.info('*'*72)
    LOGGER.info(' '*72)
    LOGGER.info('Lighter')
    LOGGER.info('version %s', version)
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


def get_start_options(warning=False, detect=False):
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
    if detect:
        sett.IMPLEMENTATION_SECRETS = _detect_impl_secret()
    if sett.DISABLE_MACAROONS:
        if warning:
            LOGGER.warning('Disabling macaroons is not safe, '
                           'do not disable them in production')
    else:
        sett.DB_DIR = env.get('DB_DIR', sett.DB_DIR)
        sett.MACAROONS_DIR = env.get('MACAROONS_DIR', sett.MACAROONS_DIR)
    sett.CLI_HOST = env.get('CLI_HOST', sett.CLI_HOST)
    if not sett.CLI_ADDR:
        sett.CLI_ADDR = '{}:{}'.format(sett.CLI_HOST, sett.PORT)


def _detect_impl_secret():
    """ Detects if implementation has a secret stored """
    if sett.IMPLEMENTATION == 'clightning':
        return False
    detected = False
    error = False
    secret, active, _ = DbHandler.get_secret_from_db(
        FakeContext(), sett.IMPLEMENTATION)
    if sett.IMPLEMENTATION == 'eclair':
        detected = True  # secret always necessary when using eclair
        if not secret:
            error = True
    if sett.IMPLEMENTATION == 'lnd' and active:
        detected = True
        if not secret:
            error = True
    if error:
        slow_exit('Cannot obtain implementation secret (hint: make secure)')
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


def slow_exit(message, wait=True):
    """
    Exits with optional sleep, useful when autorestarting (docker).
    If wait is False, a voluntary exit is assumed.
    """
    exit_code = 0
    if wait:
        LOGGER.error(message)
        LOGGER.info(
            'Sleeping for %s secs before exiting...',
            sett.RESTART_THROTTLE)
        sleep(sett.RESTART_THROTTLE)
        exit_code = 1
    else:
        LOGGER.error(message)
    log_outro()
    sys.exit(exit_code)


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
            slow_exit('All threads shutdown correctly', wait=False)

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


def check_password(context, password):
    """
    Checks the inserted password by generating an access key and trying
    to decrypt the token in the db
    """
    encrypted_token, params = DbHandler.get_token_from_db(context)
    token_params = ScryptParams('')
    token_params.deserialize(params)
    derived_key = Crypter.gen_derived_key(password, token_params)
    clear_token = Crypter.decrypt(context, encrypted_token, derived_key)
    if clear_token != sett.ACCESS_TOKEN:
        Err().wrong_password(context)


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
        return SecretBox(derived_key).encrypt(clear_data)

    @staticmethod
    def decrypt(context, encrypted_data, derived_key):
        """
        Decrypts serialized data using Secretbox and the access key.
        Throws an error when password is wrong
        """
        try:
            return SecretBox(derived_key).decrypt(encrypted_data)
        except CryptoError:
            Err().wrong_password(context)


def _handle_db_errors(func):
    """ Decorator to handle sqlite3 errors """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Error:
            Err().db_error(args[0])

    return wrapper


class DbHandler():
    """
    DbHandler saves and retrieves data from a sqlite3 database.
    """

    DATABASE = path.join(sett.DB_DIR, sett.DB_NAME)
    TABLE_TOKEN = 'access_token_table'
    TABLE_MAC = 'mac_root_key_table'
    TABLE_SECRETS = 'implementation_secrets'
    DEPRECATED_TABLE_SALT = 'salt_table'

    @staticmethod
    @_handle_db_errors
    # pylint: disable=unused-argument
    def is_db_ok(context):
        """
        It returns wheter the db is ok (not containing old data or missing
        essential data)
        """
        # pylint: enable=unused-argument
        # checking if encrypted token exists
        encrypted_token_exists = False
        table = DbHandler.TABLE_TOKEN
        if not path.isfile(DbHandler.DATABASE):
            return False
        with connect(DbHandler.DATABASE) as connection:
            cursor = connection.cursor()
            cursor.execute('''SELECT count(*) FROM sqlite_master
                           WHERE type="table"
                           AND name="{}"'''.format(table))
            encrypted_token_exists = cursor.fetchone()[0]
        # checking if old salt table exists
        salt_table_exists = True
        table = DbHandler.DEPRECATED_TABLE_SALT
        with connect(DbHandler.DATABASE) as connection:
            cursor = connection.cursor()
            cursor.execute('''SELECT count(*) FROM sqlite_master
                           WHERE type="table"
                           AND name="{}"'''.format(table))
            salt_table_exists = cursor.fetchone()[0]
        return encrypted_token_exists and not salt_table_exists

    @staticmethod
    @_handle_db_errors
    # pylint: disable=unused-argument
    def _get_from_db(context, table):
        """ Returns the content of a database table """
        # pylint: enable=unused-argument
        with connect(DbHandler.DATABASE) as connection:
            cursor = connection.cursor()
            cursor.execute('''SELECT count(*) FROM sqlite_master
                           WHERE type="table"
                           AND name="{}"'''.format(table))
            entry = cursor.fetchone()[0]
            if not entry:
                return None, None
            cursor.execute('SELECT * FROM {}'.format(table))
            return cursor.fetchone()

    @staticmethod
    @_handle_db_errors
    # pylint: disable=unused-argument
    def _save_in_db(context, table, data, scrypt_params):
        """ Stores data into database table """
        # pylint: enable=unused-argument
        with connect(DbHandler.DATABASE) as connection:
            connection.execute(
                '''CREATE TABLE IF NOT EXISTS {}
                (data BLOB, scrypt_params BLOB, PRIMARY KEY(data))'''
                .format(table))
            connection.execute(
                'INSERT OR REPLACE INTO {} VALUES (?,?)'
                .format(table), (data, scrypt_params,))

    @staticmethod
    def save_token_in_db(context, token, scrypt_params):
        """ Saves the encrypted token in database """
        DbHandler._save_in_db(
            context, DbHandler.TABLE_TOKEN, token, scrypt_params)

    @staticmethod
    def get_token_from_db(context):
        """ Gets the encrypted token from database """
        return DbHandler._get_from_db(context, DbHandler.TABLE_TOKEN)

    @staticmethod
    def save_mac_params_in_db(context, scrypt_params):
        """ Saves macaroon root key parameters in database """
        DbHandler._save_in_db(
            context, DbHandler.TABLE_MAC, 'mac_params', scrypt_params)

    @staticmethod
    def get_mac_params_from_db(context):
        """ Gets macaroon root key parameters from database """
        return DbHandler._get_from_db(context, DbHandler.TABLE_MAC)[1]

    @staticmethod
    @_handle_db_errors
    # pylint: disable=unused-argument
    def save_secret_in_db(context, implementation, active, data,
                          scrypt_params):
        """ Saves implementation's secret in database """
        # pylint: enable=unused-argument
        table = DbHandler.TABLE_SECRETS
        with connect(DbHandler.DATABASE) as connection:
            connection.execute(
                '''CREATE TABLE IF NOT EXISTS {}
                (implementation TEXT, active INTEGER, secret BLOB,
                scrypt_params BLOB, PRIMARY KEY(implementation))'''
                .format(table))
            connection.execute(
                'INSERT OR REPLACE INTO {} VALUES (?, ?, ?, ?)'
                .format(table), (implementation, active, data, scrypt_params,))

    @staticmethod
    @_handle_db_errors
    # pylint: disable=unused-argument
    def get_secret_from_db(context, implementation):
        """ Gets implementation's secret from database """
        # pylint: enable=unused-argument
        if not path.isfile(DbHandler.DATABASE):
            return None, None, None
        table = DbHandler.TABLE_SECRETS
        with connect(DbHandler.DATABASE) as connection:
            cursor = connection.cursor()
            cursor.execute('''SELECT count(*) FROM sqlite_master
                  WHERE type="table" AND name="{}"'''.format(table))
            if not cursor.fetchone()[0]:
                return None, None, None
            cursor.execute('SELECT * FROM {} WHERE implementation="{}"'
                           .format(table, implementation))
            entry = cursor.fetchone()
            if not entry:
                return None, None, None
            secret = entry[2]
            active = entry[1]
            scrypt_params = entry[3]
            return secret, active, scrypt_params
