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
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from functools import wraps
from getpass import getpass
from logging import getLogger
from select import select
from time import time, sleep
from os import environ, path, remove, urandom

from lighter import settings
from lighter.macaroons import get_baker, MACAROONS, MAC_VERSION
from lighter.utils import check_password, Crypter, DbHandler, FakeContext, \
    get_start_options, str2bool, update_logger

LOGGER = getLogger(__name__)

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


def _exit(message):
    """ Exits printing a message """
    if message:
        print(message)
    sys.exit(0)


def _handle_keyboardinterrupt(func):
    """ Handles KeyboardInterrupt """

    @wraps(func)
    def wrapper(*args, **kwargs):
        global COLLECTING_INPUT
        global SEARCHING_ENTROPY
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            COLLECTING_INPUT = False
            SEARCHING_ENTROPY = False
            _exit('\nKeyboard interrupt detected. Exiting...')

    return wrapper


def _remove_files():
    """ Removes database and macaroons """
    LOGGER.info('Removing database and macaroons')
    database = path.join(settings.DB_DIR, settings.DB_NAME)
    with suppress(FileNotFoundError):
        remove(database)
        for file_name in MACAROONS:
            macaroon_file = path.join(settings.MACAROONS_DIR, file_name)
            remove(macaroon_file)


def _get_eclair_secret():
    """ Gets eclair's password from stdin """
    data = getpass('Insert eclair password: ')
    return data.encode()


def _get_lnd_secret(macaroon_path):
    """ Gets lnd's macaroon from file """
    print('Reading lnd macaroon from the provided path...')
    with open(macaroon_path, 'rb') as file:
        return file.read()


def _set_eclair(secret):
    """ Handles storage of eclair's password """
    if not secret:
        return _get_eclair_secret()
    rm_sec = input("A password for eclair is already stored, "
                   "do you want to update it? [y/N] ")
    if str2bool(rm_sec):
        return _get_eclair_secret()


def _set_lnd(secret):
    """ Handles storage of lnd's macaroon """
    data = None
    activate_secret = 1
    macaroon_path = environ.get('LND_MAC')
    if not secret and not macaroon_path:
        print("You have not provided a path and there's no macaroon "
              "stored for lnd, assuming usage of lnd without macaroon")
        return None, 0
    if macaroon_path:
        data = _get_lnd_secret(macaroon_path)
        secret = None
    if secret:
        print('A macaroon for lnd is already stored')
        data = secret
    if secret or macaroon_path:
        res = input("Connect to lnd using its macaroon "
                    "(warning: insecure without)? [Y/n] ")
        if not str2bool(res, force_true=True):
            activate_secret = 0
    return data, activate_secret


def _encrypt_token():
    """ Encrypts token and saves it into db to verify password correctness """
    encrypted_token = Crypter.crypt(
        Crypter.LATEST_VERSION, settings.ACCESS_TOKEN)
    DbHandler.save_token_in_db(
        FakeContext(), Crypter.LATEST_VERSION, encrypted_token)
    LOGGER.info('Encrypted token stored in the DB')


def _recover_secrets():
    """ Recovers secrets from db, making sure password is correct """
    ecl_sec = lnd_sec = None
    try:
        version, ecl_sec, _ = DbHandler.get_secret_from_db(
            FakeContext(), settings.IMPLEMENTATION)
        if ecl_sec:
            ecl_sec = Crypter.decrypt(FakeContext(), version, ecl_sec)
        version, lnd_sec, _ = DbHandler.get_secret_from_db(
            FakeContext(), settings.IMPLEMENTATION)
        if lnd_sec:
            lnd_sec = Crypter.decrypt(FakeContext(), version, lnd_sec)
    except RuntimeError as err:
        _exit(err)
    return ecl_sec, lnd_sec


def _create_lightning_macaroons():
    """ Creates macaroon files to use the LightningServicer """
    print('Creating macaroons...')
    baker = get_baker(settings.ACCESS_KEY_V1)
    for file_name, permitted_ops in MACAROONS.items():
        macaroon_file = path.join(settings.MACAROONS_DIR, file_name)
        expiration_time = datetime.now(tz=timezone.utc) + timedelta(days=365)
        caveats = None
        mac = baker.oven.macaroon(
            MAC_VERSION, expiration_time, caveats, permitted_ops)
        serialized_macaroon = mac.macaroon.serialize()
        with open(macaroon_file, 'wb') as file:
            file.write(serialized_macaroon.encode())
        LOGGER.info('%s written to %s', file_name, settings.MACAROONS_DIR)


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
        while _get_entropy() < num_bytes * 8:
            if not SEARCHING_ENTROPY:
                return
            sleep(1)
        random_bytes = source.read(num_bytes)
        return random_bytes
    except Exception:
        use_urand = input("Cannot retrieve available entropy, do you want to "
                          "use whatever your os provides to python's "
                          "os.urandom? [Y/n] ")
        if str2bool(use_urand, force_true=True):
            return
        _exit("No way to retrieve the amount of available entropy")


def _gen_random_data(num_bytes):
    """ Generates random data of key_len length """
    global COLLECTING_INPUT
    global SEARCHING_ENTROPY
    if settings.ENTROPY_BLOCKING:
        try:
            source = open("/dev/random", "rb")
            executor = ThreadPoolExecutor(max_workers=2)
            future_input = None
            future = executor.submit(_read, source, num_bytes)
            data = future.result(timeout=1)
            if data:
                return data
        except FileNotFoundError:
            use_urand = input("The blocking '/dev/random' entropy source is "
                              "not available, do you want to use whatever "
                              "your os provides to python's os.urandom? "
                              "[Y/n] ")
            if str2bool(use_urand, force_true=True):
                return urandom(num_bytes)
            _exit("No Random Numbers Generator available")
        except TimeoutErrFut:
            print("This call might take long depending on the "
                  "available entropy. If this happens you can:\n"
                  " - type randomly on the keyboard or move the mouse\n"
                  " - install entropy collecting tools like haveged\n"
                  " - install a hardware TRNG\n"
                  " - type 'unsafe' and press enter to use a non-blocking "
                  "entropy source; this choice will NOT be remembered for "
                  "later\n")
            while future.running():
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
            print()
            LOGGER.info("Enough entropy was collected, thanks for waiting")
            result = future.result()
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


@_handle_keyboardinterrupt
def secure():
    """ Handles Lighter and implementation secrets """
    update_logger()
    no_db = environ.get('NO_DB')
    rm_db = environ.get('RM_DB')
    if rm_db: _remove_files()
    get_start_options()
    new = False
    if no_db or rm_db:
        new = True
    else:
        if not DbHandler.has_token(FakeContext()):
            _exit('Detected an incomplete configuration. Delete database.')
    if new:
        print('Lighter is about to ask for a new password! As humans are '
              'really bad at generating entropy, we suggest using a password '
              'manager to generate and store the password on your behalf. '
              'Refer to doc/security.md for more details.')
        gen_psw = input('Do you want Lighter to generate a safe random '
                        'password for you? (new password will be printed to '
                        'stdout) [Y/n] ')
        if str2bool(gen_psw, force_true=True):
            seed = _gen_random_data(settings.PASSWORD_LEN + settings.SALT_LEN)
            password = _gen_password(seed[:settings.PASSWORD_LEN])
            print("Here is your new password:")
            print(password)
        else:
            seed = _gen_random_data(settings.SALT_LEN)
            password = getpass('Insert a safe password for Lighter: ')
        password_check = getpass('Save the password and then enter it '
                                 'for verification: ')
        if password != password_check:
            _exit("Passwords do not match")
        salt = seed[-settings.SALT_LEN:]
        DbHandler.save_salt_in_db(FakeContext(), Crypter.LATEST_VERSION, salt)
        Crypter.gen_access_key(Crypter.LATEST_VERSION, password, salt)
        _encrypt_token()
        ecl_sec = lnd_sec = None
    else:
        password = getpass("Insert Lighter's password: ")
        for version, salt in DbHandler.get_salt_from_db(FakeContext()):
            Crypter.gen_access_key(version, password, salt)
        try:
            check_password(FakeContext())
        except RuntimeError:
            _exit('')
        ecl_sec, lnd_sec = _recover_secrets()
    create_mac = input('Do you want to create macaroon files (warning: '
                       'macaroons should not be kept in this host)? [Y/n] ')
    if str2bool(create_mac, force_true=True):
        _create_lightning_macaroons()
    data = crypt_data = None
    activate_secret = 1
    if settings.IMPLEMENTATION == 'eclair':
        data = _set_eclair(ecl_sec)
    if settings.IMPLEMENTATION == 'lnd':
        data, activate_secret = _set_lnd(lnd_sec)
    if data:
        crypt_data = Crypter.crypt(Crypter.LATEST_VERSION, data)
        DbHandler.save_secret_in_db(
            FakeContext(), Crypter.LATEST_VERSION, settings.IMPLEMENTATION,
            activate_secret, crypt_data)
    _exit('All done!')
