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

""" Securing: implementation secrets, macaroons creation and storage """

import sys

from concurrent.futures import TimeoutError as TimeoutErrFut, \
    ThreadPoolExecutor
from configparser import Error as ConfigError
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from getpass import getpass
from logging import CRITICAL, getLogger
from select import select
from time import time, sleep
from os import devnull, environ, path, remove, urandom
from signal import signal, SIGTERM

from sqlalchemy.exc import SQLAlchemyError

from . import settings as sett
from .macaroons import get_baker, MACAROONS, MAC_VERSION
from .utils.db import init_db, is_db_ok, save_mac_params_to_db, save_secret_to_db, \
    save_token_to_db, session_scope
from .utils.exceptions import InterruptException
from .utils.misc import check_password, Crypter, die, FakeContext, get_secret, \
    handle_keyboardinterrupt, handle_sigterm, init_common, str2bool
from .utils.security import ScryptParams

signal(SIGTERM, handle_sigterm)

LOGGER = getLogger(__name__)

DONE = False
NEW_DB = False

SEARCHING_ENTROPY = True
COLLECTING_INPUT = True

READ_LIST = [sys.stdin]

IDLE_MESSAGES = {
    1: {
        'msg': 'please keep generating entropy',
        'delay': 5
    },
    2: {
        'msg': 'more entropy, please',
        'delay': 15
    },
    3: {
        'msg': '...good things come to those who wait...',
        'delay': 30
    }
}

FIRST_WORK_TIME = None
IDLE_COUNTER = 1
IDLE_LAST_DELAY = 15


def _consume_bytes(consumable, num):
    """ Consume num elements from a byte string and returns them """
    consumable = list(consumable)
    i = 0
    data = []
    while i < num:
        data.append(consumable.pop(0))
        i = i + 1
    return bytes(data)


def _remove_files():
    """ Removes database and macaroons """
    LOGGER.info('Removing database and macaroons')
    with suppress(FileNotFoundError):
        remove(sett.DB_PATH)
        for file_name in MACAROONS:
            macaroon_file = path.join(sett.MACAROONS_DIR, file_name)
            remove(macaroon_file)


def _get_eclair_password():
    """ Gets eclair's password from stdin """
    while True:
        data = getpass('Insert eclair password (cannot be empty): ')
        if data:
            more_data = getpass('Insert eclair password again: ')
            if data != more_data:
                die('Passwords do not match')
            return data.encode()


def _get_electrum_password():
    """ Gets electrum's password from stdin """
    while True:
        data = getpass('Insert electrum password (cannot be empty): ')
        if data:
            more_data = getpass('Insert electrum password again: ')
            if data != more_data:
                die('Passwords do not match')
            return data.encode()


def _get_lnd_macaroon(mac_path=None):
    """ Gets lnd's macaroon from file """
    def _read_macaroon(mac_path):
        print('Reading lnd macaroon from the provided path...')
        try:
            with open(mac_path, 'rb') as file:
                return file.read()
        except OSError as err:
            die('Cannot read macaroon file: ' + str(err))
    if mac_path:
        return _read_macaroon(mac_path)
    mac_path = input('If your lnd instance requires a macaroon for '
                     'authorization, provide its path\nhere (filename included'
                     ', overrides current one if any) or just press enter to\n'
                     'provide none (skip) ')
    if mac_path:
        return _read_macaroon(mac_path)
    print('You have not provided a path, usage of lnd without macaroon '
          '(insecure)')
    return None


def _get_lnd_password():
    """ Gets lnd's password from stdin """
    data = getpass('Insert lnd password or press enter to skip '
                   '(node unlocking will not be available): ')
    if data:
        more_data = getpass('Insert lnd password again: ')
        if data != more_data:
            die('Passwords do not match')
        return data.encode()
    return None


def _set_eclair_password(secret):
    """ Handles storage of eclair's password """
    data = None
    activate_secret = 1
    if not secret:
        data = _get_eclair_password()
    else:
        data = secret
        rm_sec = input("A password for eclair is already stored, "
                       "do you want to update it? [y/N] ")
        if str2bool(rm_sec):
            data = _get_eclair_password()
    return data, activate_secret, 'password'


def _set_electrum_password(secret):
    """ Handles storage of electrum's password """
    data = None
    activate_secret = 1
    if not secret:
        data = _get_electrum_password()
    else:
        data = secret
        rm_sec = input("A password for electrum is already stored, "
                       "do you want to update it? [y/N] ")
        if str2bool(rm_sec):
            data = _get_electrum_password()
    return data, activate_secret, 'password'


def _set_lnd_macaroon(secret):
    """ Handles storage of lnd's macaroon """
    data = None
    activate_secret = 1
    if not secret:
        data = _get_lnd_macaroon()
    else:
        data = secret
        rm_sec = input("A macaroon for lnd is already stored, "
                       "do you want to update it? [y/N] ")
        if str2bool(rm_sec):
            data = _get_lnd_macaroon()
    if data:
        res = input("Connect to lnd using its macaroon "
                    "(warning: insecure without)? [Y/n] ")
        if not str2bool(res, force_true=True):
            activate_secret = 0
    return data, activate_secret, 'macaroon'


def _set_lnd_password(secret):
    """ Handles storage of lnd's password """
    data = None
    activate_secret = 0
    if not secret:
        data = _get_lnd_password()
    else:
        data = secret
        rm_sec = input("A password for lnd is already stored, "
                       "do you want to update it? [y/N] ")
        if str2bool(rm_sec):
            data = _get_lnd_password()
    if data:
        activate_secret = 1
    return data, activate_secret, 'password'


def _save_token(session, password, scrypt_params):
    """ Encrypts token and saves it into db to verify password correctness """
    derived_key = Crypter.gen_derived_key(password, scrypt_params)
    encrypted_token = Crypter.crypt(sett.ACCESS_TOKEN, derived_key)
    save_token_to_db(session, encrypted_token, scrypt_params.serialize())
    LOGGER.info('Encrypted token stored in the DB')


def _save_secret(session, password, scrypt_params, sec_type, secret,
                 activate_secret, implementation=None):
    """ Encrypts implementation secret and saves it into DB """
    encrypted_secret = None
    if not implementation:
        implementation = sett.IMPLEMENTATION
    if secret:
        derived_key = Crypter.gen_derived_key(password, scrypt_params)
        encrypted_secret = Crypter.crypt(secret, derived_key)
    save_secret_to_db(
        session, implementation, sec_type, activate_secret,
        encrypted_secret, scrypt_params.serialize())


def _recover_secrets(session, password):
    """ Recovers secrets from db, making sure password is correct """
    ecl_pass = lnd_mac = lnd_pass = None
    try:
        ecl_pass = get_secret(
            FakeContext(), session, password, 'eclair', 'password')
        ele_pass = get_secret(
            FakeContext(), session, password, 'electrum', 'password')
        lnd_mac = get_secret(
            FakeContext(), session, password, 'lnd', 'macaroon')
        lnd_pass = get_secret(
            FakeContext(), session, password, 'lnd', 'password')
    except RuntimeError as err:
        die(err)
    return ecl_pass, ele_pass, lnd_mac, lnd_pass


def _create_lightning_macaroons(session, password, scrypt_params):
    """ Creates macaroon files to use the LightningServicer """
    print('Creating macaroons...')
    sett.MAC_ROOT_KEY = Crypter.gen_derived_key(password, scrypt_params)
    save_mac_params_to_db(session, scrypt_params.serialize())
    baker = get_baker(sett.MAC_ROOT_KEY)
    for file_name, permitted_ops in MACAROONS.items():
        macaroon_file = path.join(sett.MACAROONS_DIR, file_name)
        expiration_time = datetime.now(tz=timezone.utc) + timedelta(days=365)
        caveats = None
        mac = baker.oven.macaroon(
            MAC_VERSION, expiration_time, caveats, permitted_ops)
        serialized_macaroon = mac.macaroon.serialize()
        with open(macaroon_file, 'wb') as file:
            file.write(serialized_macaroon.encode())
        LOGGER.info('%s written to %s', file_name, sett.MACAROONS_DIR)


def _get_entropy():
    """ Gets available entropy """
    with open('/proc/sys/kernel/random/entropy_avail', 'r') as entropy:
        entropy_available = int(entropy.read())
        return entropy_available


def _input():
    """ Gets input asynchronously """
    global COLLECTING_INPUT
    global READ_LIST
    global FIRST_WORK_TIME
    FIRST_WORK_TIME = time()
    while READ_LIST and COLLECTING_INPUT:
        ready = select(READ_LIST, [], [], 0.2)[0]
        if not ready and COLLECTING_INPUT:
            _idle()
        else:
            for file in ready:
                line = file.readline()
                if not line: # EOF, remove file from input list
                    READ_LIST.remove(file)
                elif line.rstrip():
                    return line.rstrip()


def _idle():
    """ During input idling prints periodic messages """
    global FIRST_WORK_TIME
    global IDLE_COUNTER
    global IDLE_MESSAGES
    if time() - FIRST_WORK_TIME > IDLE_MESSAGES[IDLE_COUNTER]['delay']:
        print(IDLE_MESSAGES[IDLE_COUNTER]['msg'])
        if IDLE_COUNTER == 3:
            IDLE_MESSAGES[IDLE_COUNTER]['delay'] = \
                IDLE_MESSAGES[IDLE_COUNTER]['delay'] + 15
        else:
            IDLE_COUNTER = IDLE_COUNTER + 1


def _read(source, num_bytes):
    """ Gets entropy from /dev/random asynchronously """
    global SEARCHING_ENTROPY
    try:
        while _get_entropy() < num_bytes * 8 * 1.2:
            if not SEARCHING_ENTROPY:
                return
            sleep(1)
        random_bytes = source.read(num_bytes)
        return random_bytes
    except IOError:
        if not SEARCHING_ENTROPY:
            return
        use_urand = input("Cannot retrieve available entropy, do you want to "
                          "use whatever your os provides\nto python's "
                          "os.urandom? [Y/n] ")
        if str2bool(use_urand, force_true=True):
            return
        die("No way to retrieve the amount of available entropy")


def _gen_random_data(num_bytes):
    """ Generates random data of key_len length """
    global COLLECTING_INPUT
    global SEARCHING_ENTROPY
    if sett.ENTROPY_BLOCKING:
        print('Trying to collect entropy...')
        try:
            source = open("/dev/random", "rb")
            executor = ThreadPoolExecutor(max_workers=2)
            future_input = None
            future_read = executor.submit(_read, source, num_bytes)
            data = future_read.result(timeout=1)
            if data:
                return data
        except FileNotFoundError:
            use_urand = input("The blocking '/dev/random' entropy source is "
                              "not available, do you want to use\nwhatever "
                              "your os provides to python's os.urandom? "
                              "[Y/n] ")
            if str2bool(use_urand, force_true=True):
                return urandom(num_bytes)
            die("No Random Numbers Generator available")
        except TimeoutErrFut:
            print("This call might take long depending on the "
                  "available entropy.\nIf this happens you can:\n"
                  " - type randomly on the keyboard or move the mouse\n"
                  " - install entropy collecting tools like haveged\n"
                  " - install a hardware TRNG\n"
                  " - type 'unsafe' and press enter to use a non-blocking "
                  "entropy source; this choice will NOT be remembered for "
                  "later\n")
            while future_read.running():
                if not future_input:
                    future_input = executor.submit(_input)
                if future_input.done():
                    if future_input.result() == 'unsafe':
                        SEARCHING_ENTROPY = False
                        COLLECTING_INPUT = False
                        return urandom(num_bytes)
                    future_input = None
                sleep(1)
            COLLECTING_INPUT = False
            print("\nEnough entropy was collected, thanks for waiting")
            result = future_read.result()
            if result:
                return result
        finally:
            if source:
                source.close()
            if executor:
                executor.shutdown(wait=False)
    return urandom(num_bytes)


def _gen_password(seed):
    """ Generates a safe random password from a 64-char alphabet """
    # base58 charset plus some symbols up to 64
    alpha = r'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz+/\&-_'
    assert 256 % len(alpha) is 0
    return ''.join(alpha[i % len(alpha)] for i in seed)


def _get_req_salt_len(new, interactive=True):
    """ Determines maximum bytes of salt that will be needed """
    secrets = 1  # for lighter's macaroons
    if sett.IMPLEMENTATION == 'eclair':
        secrets += 1  # for eclair password
    elif sett.IMPLEMENTATION == 'lnd':
        secrets += 2  # for lnd password and macaroon
    for_password = 0
    if new:
        secrets += 1  # for access token
        if interactive:
            for_password = sett.PASSWORD_LEN  # for auto-generated password
    return sett.SALT_LEN * secrets + for_password


def _rm_db():
    """
    Checks if DB exists and eventually deletes it. Returns False if DB
    was missing or has been requested deletion.
    """
    if path.exists(sett.DB_PATH):
        delete = input('Db already exists, do you want to override it? (note '
                       'this will also delete\nmacaroon files) [y/N] ')
        if str2bool(delete):
            _remove_files()
            return False
        return True
    else:
        return False


def db_config_interactive(session, new):
    """ Configures a new or existing database interactively """
    ecl_pass = ele_pass = lnd_mac = lnd_pass = None
    if new:
        print('Lighter is about to ask for a new password! As humans are '
              'really bad at\ngenerating entropy, we suggest using a password '
              'manager to generate and store\nthe password on your behalf. '
              'Refer to doc/security.md for more details.')
        gen_psw = input('Do you want Lighter to generate a safe random '
                        'password for you? (new password\nwill be printed to '
                        'stdout) [Y/n] ')
        salts_len = _get_req_salt_len(new)
        if str2bool(gen_psw, force_true=True):
            seed = _gen_random_data(sett.PASSWORD_LEN + salts_len)
            password = _gen_password(_consume_bytes(seed, sett.PASSWORD_LEN))
            print("Here is your new password:")
            print(password)
        else:
            seed = _gen_random_data(salts_len)
            password = getpass('Insert a safe password for Lighter: ')
        password_check = getpass('Save the password and then enter it '
                                 'for verification: ')
        if password != password_check:
            _remove_files()
            die("Passwords do not match")
        scrypt_params = ScryptParams(_consume_bytes(seed, sett.SALT_LEN))
        _save_token(session, password, scrypt_params)
    else:
        if not is_db_ok(session, configuring=True):
            die('Detected an incomplete configuration. Delete database.')
        password = getpass("Insert Lighter's password: ")
        try:
            check_password(FakeContext(), session, password)
        except RuntimeError:
            die('Wrong password')
        ecl_pass, ele_pass, lnd_mac, lnd_pass = _recover_secrets(
            session, password)
        seed = _gen_random_data(_get_req_salt_len(new))
    create_mac = input('Do you want to create macaroons (warning: generated '
                       'files should not be kept in\nthis host)? [y/N] ')
    if str2bool(create_mac):
        scrypt_params = ScryptParams(_consume_bytes(seed, sett.SALT_LEN))
        _create_lightning_macaroons(session, password, scrypt_params)
    secrets = []
    if sett.IMPLEMENTATION == 'eclair':
        secrets = [_set_eclair_password(ecl_pass)]
    if sett.IMPLEMENTATION == 'electrum':
        secrets = [_set_electrum_password(ele_pass)]
    if sett.IMPLEMENTATION == 'lnd':
        secrets = [_set_lnd_macaroon(lnd_mac), _set_lnd_password(lnd_pass)]
    if secrets:  # user gave us secrets to encrypt and save
        for secret in secrets:
            scrypt_params = ScryptParams(_consume_bytes(seed, sett.SALT_LEN))
            _save_secret(
                session, password, scrypt_params, secret[2], secret[0],
                secret[1])


def db_config_non_interactive(session, new, password):
    """ Configures a new or existing database in batch-mode """
    ecl_pass = ele_pass = lnd_mac = lnd_pass = None
    if new:
        salts_len = _get_req_salt_len(new, interactive=False)
        seed = _gen_random_data(salts_len)
        scrypt_params = ScryptParams(_consume_bytes(seed, sett.SALT_LEN))
        _save_token(session, password, scrypt_params)
    else:
        if not is_db_ok(session):
            die('Detected an incomplete configuration. Delete database.')
        try:
            check_password(FakeContext(), session, password)
        except RuntimeError:
            die('Wrong password')
        ecl_pass, ele_pass, lnd_mac, lnd_pass = \
            _recover_secrets(session, password)
        seed = _gen_random_data(_get_req_salt_len(new, interactive=False))
    create_mac = environ.get('create_macaroons', 0)
    if create_mac:
        scrypt_params = ScryptParams(_consume_bytes(seed, sett.SALT_LEN))
        _create_lightning_macaroons(session, password, scrypt_params)
    secrets = []
    ecl_pass = environ.get('eclair_password')
    ele_pass = environ.get('electrum_password')
    lnd_mac = environ.get('lnd_macaroon')
    lnd_pass = environ.get('lnd_password')
    if ecl_pass:
        secrets.append([ecl_pass.encode(), 1, 'password', 'eclair'])
    if ele_pass:
        secrets.append([ele_pass.encode(), 1, 'password', 'electrum'])
    if lnd_mac:
        secrets.append([_get_lnd_macaroon(lnd_mac), 1, 'macaroon', 'lnd'])
    if lnd_pass:
        secrets.append([lnd_pass.encode(), 1, 'password', 'lnd'])
    if secrets:  # user gave us secrets to encrypt and save
        for secret in secrets:
            scrypt_params = ScryptParams(_consume_bytes(seed, sett.SALT_LEN))
            _save_secret(
                session, password, scrypt_params, secret[2], secret[0],
                secret[1], implementation=secret[3])


def secure():
    """ Secure entrypoint """
    try:
        _secure()
    except ImportError as err:
        LOGGER.debug('Import error: %s', str(err))
        LOGGER.error(
            "Implementation '%s' is not supported", sett.IMPLEMENTATION)
        die()
    except RuntimeError as err:
        die(str(err))
    except ConfigError as err:
        err_msg = ''
        if str(err):
            err_msg = str(err)
        die('Configuration error: ' + err_msg)
    except SQLAlchemyError as err:
        err_msg = ''
        if str(err):
            err_msg = str(err)
        die('DB error: ' + err_msg)
    except InterruptException:
        COLLECTING_INPUT = False
        SEARCHING_ENTROPY = False
        if not DONE and NEW_DB:
            _remove_files()
        die()


@handle_keyboardinterrupt
def _secure():
    """ Handles Lighter and implementation secrets """
    global COLLECTING_INPUT
    global DONE
    global NEW_DB
    global SEARCHING_ENTROPY
    getLogger('lighter.errors').setLevel(CRITICAL)
    init_common("Start Lighter's secure procedure", write_perms=True)
    if not _rm_db():
        NEW_DB = True
    init_db(new_db=NEW_DB)
    lighter_password = environ.get('lighter_password')
    try:
        if lighter_password:
            sys.stdout = open(devnull, 'w')
        with session_scope(FakeContext()) as session:
            if lighter_password:
                db_config_non_interactive(session, NEW_DB, lighter_password)
            else:
                db_config_interactive(session, NEW_DB)
        DONE = True
        print('All done!')
    finally:
        if lighter_password:
            sys.stdout.close()
