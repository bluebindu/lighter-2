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
from os import environ as env, path, urandom
from sqlite3 import connect, Error
from subprocess import PIPE, Popen, TimeoutExpired
from time import sleep, strftime

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
        sett.ENABLE_UNLOCKER = _detect_impl_secret()
        if warning:
            LOGGER.warning('Disabling macaroons is not safe, '
                           'do not disable them in production')
    else:
        sett.DB_DIR = env.get('DB_DIR', sett.DB_DIR)
        sett.MACAROONS_DIR = env.get('MACAROONS_DIR', sett.MACAROONS_DIR)
    if not sett.ENABLE_UNLOCKER and warning:
        LOGGER.warning('Running Lighter without secrets. '
                       'Run make secure to configure them')
    sett.CLI_HOST = env.get('CLI_HOST', sett.CLI_HOST)
    sett.CLI_ADDR = '{}:{}'.format(sett.CLI_HOST, sett.PORT)


def _detect_impl_secret():
    """ Detects if implementation has a secret stored """
    if sett.IMPLEMENTATION == 'clightning':
        return False
    if not path.isfile(path.join(sett.DB_DIR, sett.DB_NAME)):
        return False
    _, secret, active = DbHandler.get_secret_from_db(
        FakeContext(), sett.IMPLEMENTATION)
    if not active:
        return False
    if active and not secret:
        slow_exit('Cannot obtain implementation secret (hint: make secure)')
    return True


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


def command(context, *args_cmd, **kwargs):
    """ Given a command, calls a cli interface """
    if not sett.CMD_BASE:
        raise RuntimeError
    cmd = sett.CMD_BASE + list(args_cmd)
    envi = kwargs.get('env', None)
    # universal_newlines ensures bytes are returned
    proc = Popen(
        cmd, env=envi, stdout=PIPE, stderr=PIPE, universal_newlines=False)
    out = err = b''
    try:
        out, err = proc.communicate(timeout=sett.IMPL_TIMEOUT)
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
        LOGGER.info(message)
    log_outro()
    sys.exit(exit_code)


def handle_keyboardinterrupt(func):
    """ Handles KeyboardInterrupt stopping the gRPC server and exiting """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            with suppress(IndexError):
                args[0].stop(sett.GRPC_GRACE_TIME)
                print()
            slow_exit('Keyboard interrupt detected. Waiting for threads to '
                      'complete...', wait=False)

    return wrapper


def gen_random_data(key_len):
    """ Generates random data of key_len length """
    return urandom(key_len)


def check_password(context):
    """
    Checks the inserted password by generating an access key and trying 
    to decrypt the token in the db
    """
    version, encrypted_token = DbHandler.get_token_from_db(context)
    clear_token = Crypter.decrypt(context, version, encrypted_token)
    if clear_token != sett.ACCESS_TOKEN:
        Err().wrong_password(context)


class Crypter():  # pylint: disable=too-many-instance-attributes
    """
    Crypter provides methods to crypt and decrypt data.

    When crypting, it returns the serialized data
    cotaining a the crypted data and other data used to generate derived key
    from password. A version string is attached to the serialized data in order
    to allow migration.

    When decrypting, it returns only the plain data that was crypted.
    """

    LATEST_VERSION = sett.LATEST_VERSION

    V1_PARAMS = {
        'cost_factor': 2**14,
        'block_size_factor': 8,
        'parallelization_factor': 1,
        'key_len': 32
    }

    @staticmethod
    def gen_access_key(version, password, salt):
        """ Derives a key from a password using Scrypt """
        params = getattr(Crypter, 'V{}_PARAMS'.format(version))
        access_key = scrypt(
            bytes(password, 'utf-8'),
            salt,
            N=params['cost_factor'],
            r=params['block_size_factor'],
            p=params['parallelization_factor'],
            olen=params['key_len'])
        setattr(sett, 'ACCESS_KEY_V{}'.format(version), access_key)

    @staticmethod
    def crypt(version, clear_data):
        """
        Crypts data using Secretbox and the access key.
        It returns the encrypted data in a serialized form
        """
        access_key = getattr(sett, 'ACCESS_KEY_V{}'.format(version))
        return SecretBox(access_key).encrypt(clear_data)

    @staticmethod
    def decrypt(context, version, encrypted_data):
        """
        Decrypts serialized data using Secretbox and the access key.
        Throws an error when password is wrong
        """
        access_key = getattr(sett, 'ACCESS_KEY_V{}'.format(version))
        try:
            return SecretBox(access_key).decrypt(encrypted_data)
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
    TABLE_SALT = 'salt_table'
    TABLE_SECRETS = 'implementation_secrets'

    @staticmethod
    @_handle_db_errors
    # pylint: disable=unused-argument
    def is_old_version(context):
        """
        It returns wheter the db is in an old version
        """
        table = DbHandler.TABLE_TOKEN
        # pylint: enable=unused-argument
        with connect(DbHandler.DATABASE) as connection:
            cursor = connection.cursor()
            cursor.execute('''SELECT count(*) FROM sqlite_master
                           WHERE type="table"
                           AND name="{}"'''.format(table))
            entry = cursor.fetchone()[0]
            return not entry

    @staticmethod
    @_handle_db_errors
    # pylint: disable=unused-argument
    def _get_from_db(context, table, get_all=False):
        """
        returns the content of table ordered by version
        """
        # pylint: enable=unused-argument
        with connect(DbHandler.DATABASE) as connection:
            cursor = connection.cursor()
            cursor.execute('''SELECT count(*) FROM sqlite_master
                           WHERE type="table"
                           AND name="{}"'''.format(table))
            entry = cursor.fetchone()[0]
            if not entry and not get_all:
                return None, None
            if not entry and get_all:
                return [(None, None,)]
            cursor.execute('SELECT * FROM {} ORDER BY version DESC'
                           .format(table))
            if get_all:
                return cursor.fetchall()
            return cursor.fetchone()

    @staticmethod
    @_handle_db_errors
    # pylint: disable=unused-argument
    def _save_in_db(context, table, version, data):
        """
        stores data into table setting the version to the db
        """
        # pylint: enable=unused-argument
        with connect(DbHandler.DATABASE) as connection:
           connection.execute('''CREATE TABLE IF NOT EXISTS {}
               (version INTEGER, data BLOB, PRIMARY KEY(version))'''
               .format(table))
           connection.execute('INSERT OR REPLACE INTO {} VALUES (?,?)'
               .format(table), (version, data,))

    @staticmethod
    def save_token_in_db(context, version, token):
        """ Saves the encrypted token in database """
        DbHandler._save_in_db(
            context, DbHandler.TABLE_TOKEN, version, token)

    @staticmethod
    def get_token_from_db(context):
        """ Gets the encrypted token from database """
        return DbHandler._get_from_db(context, DbHandler.TABLE_TOKEN)

    @staticmethod
    def save_salt_in_db(context, version, salt):
        """ Saves Scrypt salt in database """
        DbHandler._save_in_db(
            context, DbHandler.TABLE_SALT, version, salt)

    @staticmethod
    def get_salt_from_db(context):
        """ Gets Scrypt salt from database """
        return DbHandler._get_from_db(
            context, DbHandler.TABLE_SALT, get_all=True)

    @staticmethod
    @_handle_db_errors
    # pylint: disable=unused-argument
    def save_secret_in_db(context, version, implementation, active, data):
        """ Saves implementation's secret in database """
        # pylint: enable=unused-argument
        table = DbHandler.TABLE_SECRETS
        with connect(DbHandler.DATABASE) as connection:
           connection.execute('''CREATE TABLE IF NOT EXISTS {}
               (version INTEGER, implementation TEXT, active INTEGER,
               secret BLOB, PRIMARY KEY(version, implementation))'''
               .format(table))
           connection.execute('INSERT OR REPLACE INTO {} VALUES (?, ?, ?, ?)'
               .format(table), (version, implementation, active, data,))

    @staticmethod
    @_handle_db_errors
    # pylint: disable=unused-argument
    def get_secret_from_db(context, implementation):
        """ Gets implementation's secret from database """
        # pylint: enable=unused-argument
        table = DbHandler.TABLE_SECRETS
        with connect(DbHandler.DATABASE) as connection:
            cursor = connection.cursor()
            cursor.execute('''SELECT count(*) FROM sqlite_master
                  WHERE type="table" AND name="{}"'''.format(table))
            entry = cursor.fetchone()[0]
            if not entry:
                return None, None, None
            cursor.execute('''SELECT * FROM {} WHERE implementation="{}"
                ORDER BY version DESC LIMIT 1'''.format(table, implementation))
            entry = cursor.fetchone()[0]
            if not entry:
                return None, None, None
            cursor.execute('SELECT version FROM {}'.format(table))
            version = cursor.fetchone()[0]
            cursor.execute('SELECT secret FROM {}'.format(table))
            secret = cursor.fetchone()[0]
            cursor.execute('SELECT active FROM {}'.format(table))
            active = cursor.fetchone()[0]
            return version, secret, active
