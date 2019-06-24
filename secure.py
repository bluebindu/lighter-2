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

from contextlib import suppress
from getpass import getpass
from logging import getLogger
from os import environ, path, remove

from lighter import settings
from lighter.macaroons import create_lightning_macaroons, MACAROONS
from lighter.utils import check_password, Crypter, DbHandler, FakeContext, \
    get_start_options, str2bool, update_logger

LOGGER = getLogger(__name__)


def _exit(message):
    """ Exits printing a message """
    print(message)
    sys.exit(0)


def _remove_files():
    """ Removes database and macaroons """
    print('Removing database and macaroons')
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
    rm_sec = input("A passwprd for eclair is already stored, "
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


def _set_macaroons(password):
    """ Handles macaroons and their root key """



def _encrypt_token(crypter):
    encrypted_token = crypter.crypt(settings.ACCESS_TOKEN)
    DbHandler.save_token_in_db(FakeContext(), encrypted_token)
    LOGGER.info('Root key generation parameters and encrypted token '
                'stored in the DB')


def _recover_secrets(password):
    """ Recovers secrets from db, making sure password is correct """
    ecl_sec = lnd_sec = None
    crypter = Crypter(password)
    try:
        ecl_sec, _ = DbHandler.get_secret_from_db(FakeContext(), 'eclair_data')
        if ecl_sec:
            ecl_sec = crypter.decrypt(FakeContext(), ecl_sec)
        lnd_sec, _ = DbHandler.get_secret_from_db(FakeContext(), 'lnd_data')
        if lnd_sec:
            lnd_sec = crypter.decrypt(FakeContext(), lnd_sec)
    except RuntimeError as err:
        _exit(err)
    return ecl_sec, lnd_sec


def secure():
    """ Handles Lighter and implementation secrets """
    update_logger()
    get_start_options()
    no_db = environ.get('NO_DB')
    rm_db = environ.get('RM_DB')
    if rm_db: _remove_files()
    if no_db or rm_db:
        password = getpass('Insert a safe password for Lighter: ')
        password_check = getpass('Repeat password: ')
        if password != password_check:
            _exit("Passwords do not match")
        crypter = Crypter(password)
        _encrypt_token(crypter)
        ecl_sec = lnd_sec = None
    else:
        password = getpass("Insert Lighter's password: ")
        crypter = Crypter(password)
        check_password(FakeContext(), crypter)
        ecl_sec, lnd_sec = _recover_secrets(password)
    if not settings.DISABLE_MACAROONS:
        create_lightning_macaroons(crypter)
    data = crypt_data = None
    activate_secret = 1
    if settings.IMPLEMENTATION == 'eclair':
        data = _set_eclair(ecl_sec)
    if settings.IMPLEMENTATION == 'lnd':
        data, activate_secret = _set_lnd(lnd_sec)
    if data:
        crypter = Crypter(password)
        crypt_data = crypter.crypt(data)
    table = '{}_data'.format(settings.IMPLEMENTATION)
    DbHandler.save_secret_in_db(
        FakeContext(), table, activate_secret, crypt_data)
    _exit('All done!')
