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

from argparse import ArgumentParser
from configparser import ConfigParser
from contextlib import suppress
from decimal import Decimal, InvalidOperation
from functools import wraps
from glob import glob
from importlib import import_module
from logging import getLogger
from logging.config import dictConfig
from marshal import dumps as mdumps, loads as mloads
from os import access, mkdir, path, R_OK, W_OK
from pathlib import Path
from shutil import copyfile
from site import USER_BASE
from threading import current_thread
from time import sleep, strftime, time

from requests import Session as ReqSession
from requests.exceptions import ConnectionError as ReqConnectionErr, Timeout

from . import lighter_pb2 as pb

from . import __version__, settings as sett
from .db import get_secret_from_db, get_token_from_db
from .errors import Err
from .migrate import migrate

LOGGER = getLogger(__name__)


def init_common(help_msg, core=True, write_perms=False):
    """ Initializes common entrypoints calls """
    update_logger()
    parse_args(help_msg, write_perms)
    if core:
        init_tree()
    config = get_config_parser()
    update_logger(config)
    get_start_options(config)
    if core:
        migrate()
        # reupdating logger as migrate overrides configuration
        update_logger(config)


def update_logger(config=None):
    """
    Activates console logs by default and, when configuration is available,
    activates file logs and sets configured log level
    """
    if config:
        sec = 'lighter'
        logs_level = config.get(sec, 'LOGS_LEVEL').upper()
        sett.LOGGING['handlers']['console']['level'] = logs_level
        sett.LOGGING['loggers']['']['handlers'].append('file')
        sett.LOGGING['handlers'].update(sett.LOGGING_FILE)
        sett.LOGS_DIR = get_path(config.get(sec, 'LOGS_DIR'))
        log_path = path.join(sett.LOGS_DIR, sett.LOGS_LIGHTER)
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


def parse_args(help_msg, write_perms):
    """ Parses command line arguments """
    parser = ArgumentParser(description=help_msg)
    acc_mode = R_OK
    if write_perms:
        acc_mode = W_OK
    parser.add_argument(
        '--lighterdir', metavar='PATH',
        help="Path containing config file and other data")
    args = vars(parser.parse_args())
    if 'lighterdir' in args and args['lighterdir'] is not None:
        lighterdir = args['lighterdir']
        if not lighterdir:
            raise RuntimeError('Invalid lighterdir: empty path')
        if not path.isdir(lighterdir):
            raise RuntimeError('Invalid lighterdir: path is not a directory')
        if not access(lighterdir, acc_mode):
            raise RuntimeError('Invalid lighterdir: permission denied')
        sett.L_DATA = lighterdir
        sett.L_CONFIG = path.join(sett.L_DATA, 'config')


def check_connection():
    """
    Calls a GetInfo in order to check if connection to node is successful
    """
    request = pb.GetInfoRequest()
    module = import_module('..light_{}'.format(sett.IMPLEMENTATION), __name__)
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


def get_config_parser():
    """
    Reads config file, settings default values, and returns its parser.
    When config is missing, it copies config.sample in its expected location.
    """
    if not path.exists(sett.L_CONFIG):
        LOGGER.error('Missing config file, copying sample to "%s", '
                     'read doc/configuring.md for details', sett.L_CONFIG)
        sample = get_data_files_path(
            'share/doc/' + sett.PKG_NAME, 'examples/config.sample')
        copyfile(sample, sett.L_CONFIG)
    config = ConfigParser()
    config.read(sett.L_CONFIG)
    l_values = ['INSECURE_CONNECTION', 'PORT', 'SERVER_KEY', 'SERVER_CRT',
                'LOGS_DIR', 'LOGS_LEVEL', 'DB_DIR', 'MACAROONS_DIR',
                'DISABLE_MACAROONS']
    set_defaults(config, l_values)
    return config


def get_data_files_path(install_dir, relative_path):
    """
    Given a relative path to a data file, returns its absolute path.
    If it detects editable pip install / python setup.py develop, it uses a
    path relative to the source directory (following the .egg-link).
    """
    for base_path in (sys.prefix, USER_BASE, path.join(sys.prefix, 'local')):
        install_path = path.join(base_path, install_dir)
        if path.exists(path.join(install_path, relative_path)):
            return path.join(install_path, relative_path)
        egg_glob = path.join(base_path, 'lib*', 'python*', '*-packages',
                             '{}.egg-link'.format(sett.PIP_NAME))
        egg_link = glob(egg_glob)
        if egg_link:
            with open(egg_link[0], 'r') as f:
                realpath = f.readline().strip()
            if path.exists(path.join(realpath, relative_path)):
                return path.join(realpath, relative_path)
    raise RuntimeError('File "{}" not found'.format(relative_path))


def set_defaults(config, values):
    """ Sets configuration defaults """
    defaults = {}
    for var in values:
        defaults[var] = getattr(sett, var)
    config.read_dict({'DEFAULT': defaults})


def get_start_options(config):
    """ Sets Lighter and implementation start options """
    sec = 'lighter'
    sett.IMPLEMENTATION = config.get(sec, 'IMPLEMENTATION').lower()
    sett.INSECURE_CONNECTION = str2bool(config.get(sec, 'INSECURE_CONNECTION'))
    sett.DISABLE_MACAROONS = str2bool(config.get(sec, 'DISABLE_MACAROONS'))
    sett.PORT = config.get(sec, 'PORT')
    sett.LIGHTER_ADDR = '{}:{}'.format(sett.HOST, sett.PORT)
    if sett.INSECURE_CONNECTION:
        sett.DISABLE_MACAROONS = True
    else:
        sett.SERVER_KEY = get_path(config.get(sec, 'SERVER_KEY'))
        sett.SERVER_CRT = get_path(config.get(sec, 'SERVER_CRT'))
    if sett.DISABLE_MACAROONS:
        LOGGER.warning('Disabling macaroons is not safe, '
                       'do not disable them in production')
    else:
        sett.MACAROONS_DIR = get_path(config.get(sec, 'MACAROONS_DIR'))
    sett.DB_DIR = get_path(config.get(sec, 'DB_DIR'))
    sett.DB_PATH = path.join(sett.DB_DIR, sett.DB_NAME)
    module = import_module('..light_{}'.format(sett.IMPLEMENTATION), __name__)
    getattr(module, 'get_settings')(config, sett.IMPLEMENTATION)


def detect_impl_secret(session):
    """ Detects if implementation has a secret stored """
    if sett.IMPLEMENTATION == 'clightning':
        return False
    detected = False
    error = False
    impl_secret = get_secret_from_db(
        session, sett.IMPLEMENTATION, sett.IMPL_SEC_TYPE)
    if sett.IMPLEMENTATION == 'eclair' or sett.IMPLEMENTATION == 'electrum':
        detected = True  # secret always necessary when using eclair/electrum
        if not impl_secret or not impl_secret.secret:
            error = True
    if sett.IMPLEMENTATION == 'lnd':
        if impl_secret and impl_secret.active:
            detected = True
            if not impl_secret.secret:
                error = True
    if error:
        raise RuntimeError(
            'Cannot obtain implementation secret, add it by running '
            'lighter-secure')
    return detected


def init_tree():
    """ Creates data directory tree if missing """
    _try_mkdir(sett.L_DATA)
    _try_mkdir(path.join(sett.L_DATA, 'certs'))
    _try_mkdir(path.join(sett.L_DATA, 'db'))
    _try_mkdir(path.join(sett.L_DATA, 'logs'))
    _try_mkdir(path.join(sett.L_DATA, 'macaroons'))


def _try_mkdir(dir_path):
    """ Creates a directory if it doesn't exist """
    if not path.exists(dir_path):
        LOGGER.info('Creating dir %s', dir_path)
        mkdir(dir_path)


def get_path(ipath, base_path=None):
    """
    Gets absolute posix path. By default relative paths are calculated from
    lighterdir
    """
    ipath = Path(ipath).expanduser()
    if ipath.is_absolute():
        return ipath.as_posix()
    if not base_path:
        base_path = sett.L_DATA
    return Path(base_path, ipath).as_posix()


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


class RPCSession():  # pylint: disable=too-few-public-methods
    """ Creates and mantains an RPC session open """

    def __init__(self, auth=None, headers=None, jsonrpc_ver='2.0'):
        self._session = ReqSession()
        self._auth = auth
        self._headers = headers
        self._jsonrpc_ver = jsonrpc_ver
        self._id_count = 0

    def call(self, context, data=None, url=None, timeout=None):
        """ Makes an RPC call using the opened session """
        self._id_count += 1
        if url is None:
            url = sett.RPC_URL
        if timeout is None:
            timeout = get_node_timeout(context)
        tries = sett.RPC_TRIES
        while True:
            try:
                response = self._session.post(
                    url, data=data, auth=self._auth,
                    timeout=(sett.RPC_CONN_TIMEOUT, timeout))
            except ReqConnectionErr:
                tries -= 1
                if tries == 0:
                    Err().node_error(
                        context, 'RPC call failed: max retries reached')
                LOGGER.info(
                    'Connection failed, sleeping for %d secs (%d tries left)',
                    sett.RPC_SLEEP, tries)
                sleep(sett.RPC_SLEEP)
            except Timeout:
                Err().node_error(context, 'RPC call timed out')
            else:
                break
        if response.status_code not in (200, 500):
            err_msg = 'RPC call failed: {} {}'.format(
                response.status_code, response.reason)
            Err().node_error(context, err_msg)
        is_error = response.status_code == 500
        json_response = response.json()
        LOGGER.debug('response: %s', json_response)
        if 'error' in json_response and json_response['error'] is not None:
            err = json_response['error']
            if 'message' in err:
                err = json_response['error']['message']
            return err, is_error
        if 'result' in json_response:
            return json_response['result'], is_error
        return json_response, is_error


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


def convert(context, unit, amount, enforce=None, max_precision=None):
    """
    Converts amount from or to unit, according to enforce presence
    """
    if enforce:
        # input: converting from lighter to ln node (converts and enforces)
        if not max_precision:
            max_precision = enforce['unit']
        source = Enforcer.BITS
        target = enforce['unit']
    else:
        # output: converting from ln node to lighter (converts only)
        if not max_precision:
            max_precision = Enforcer.MSATS
        source = unit
        target = Enforcer.BITS
    result = _convert_value(context, source, target, amount, max_precision)
    if enforce:
        Enforcer.check_value(context, result, enforce)
        result = _convert_value(context, source, unit, amount, max_precision)
    return result


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
            int_result = int(result)
            if int_result != result:
                raise InvalidOperation
            return int_result
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


def handle_sigterm(_signo, _stack_frame):
    """ Handles a SIGTERM, raising an InterruptException """
    raise InterruptException


def handle_keyboardinterrupt(func):
    """ Handles KeyboardInterrupt, raising an InterruptException """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            print('\nKeyboard interrupt detected.')
            raise InterruptException

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


class InterruptException(Exception):
    """ Raised to interrupt Lighter """
