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

""" Tests for utils.security module """

from importlib import import_module
from unittest import TestCase
from unittest.mock import patch

from nacl.exceptions import CryptoError

from . import proj_root

CTX = 'context'
ImplementationSecret = getattr(
    import_module(proj_root + '.db'), 'ImplementationSecret')
settings = import_module(proj_root + '.settings')

MOD = import_module(proj_root + '.utils.security')


class UtilsSecurityTests(TestCase):
    """ Tests for utils.security module """

    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.Crypter')
    @patch(MOD.__name__ + '.ScryptParams', autospec=True)
    @patch(MOD.__name__ + '.get_token_from_db', autospec=True)
    def test_check_password(self, mocked_db_tok, mocked_params, mocked_crypter,
                            mocked_err):
        pwd = 'password'
        ses = 'session'
        # Correct
        mocked_db_tok.return_value = ['token', 'params']
        mocked_crypter.decrypt.return_value = settings.ACCESS_TOKEN
        MOD.check_password(CTX, ses, pwd)
        mocked_err().wrong_password.assert_not_called()
        # Wrong
        wrong_token = 'wrong_token'
        mocked_crypter.decrypt.return_value = wrong_token
        MOD.check_password(CTX, ses, pwd)
        mocked_err().wrong_password.assert_called_once_with(CTX)

    @patch(MOD.__name__ + '.Crypter')
    @patch(MOD.__name__ + '.ScryptParams', autospec=True)
    @patch(MOD.__name__ + '.get_secret_from_db', autospec=True)
    def test_get_secret(self, mocked_db_sec, mocked_params, mocked_crypter):
        ses = 'session'
        pwd = 'password'
        impl = 'implementation'
        sec_type = 'macaroon'
        # active_only=False (default) with secret case
        res = MOD.get_secret(CTX, ses, pwd, impl, sec_type)
        self.assertEqual(res, mocked_crypter.decrypt.return_value)
        # active_only=False (default) with no secret case
        mocked_db_sec.return_value = None
        res = MOD.get_secret(CTX, ses, pwd, impl, sec_type)
        self.assertEqual(res, None)
        # active_only=True and inactive secret case
        mocked_db_sec.return_value = ImplementationSecret(
            implementation=impl, active=0, secret=b'sec')
        res = MOD.get_secret(CTX, ses, pwd, impl, sec_type, active_only=True)
        self.assertEqual(res, None)

    @patch(MOD.__name__ + '.Err')
    def test_Crypter(self, mocked_err):
        password = 'lighterrocks'
        plain_data = b'lighter is cool'
        params = MOD.ScryptParams(b'salt')
        # Crypt
        derived_key = MOD.Crypter.gen_derived_key(password, params)
        crypt_data = MOD.Crypter.crypt(plain_data, derived_key)
        # Decrypt
        decrypted_data = MOD.Crypter.decrypt(CTX, crypt_data, derived_key)
        self.assertEqual(plain_data, decrypted_data)
        # Error case
        with patch('nacl.secret.SecretBox') as mocked_box:
            mocked_box.return_value.decrypt.side_effect = CryptoError
            decrypted_data = MOD.Crypter.decrypt(CTX, crypt_data, derived_key)
            mocked_err().wrong_password.assert_called_once_with(CTX)
            mocked_err().reset_mock()
        # Wrong version case
        wrong_data = 'random_wrong_stuff'
        MOD.Crypter.decrypt(CTX, wrong_data, derived_key)
        mocked_err().wrong_password.assert_called_once_with(CTX)

    def test_ScryptParams(self):
        salt = b'salt'
        scrypt_params = MOD.ScryptParams(salt)
        serialized = scrypt_params.serialize()
        scrypt_params = MOD.ScryptParams('')
        scrypt_params.deserialize(serialized)
        self.assertEqual(scrypt_params.salt, salt)
