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

""" Security utils module """

from marshal import dumps as mdumps, loads as mloads

from .. import settings as sett
from ..errors import Err
from .db import get_secret_from_db, get_token_from_db


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
