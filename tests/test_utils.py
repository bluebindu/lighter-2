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
""" Tests for utils module """

from codecs import encode
from decimal import InvalidOperation
from importlib import import_module
from nacl.exceptions import CryptoError
from sqlite3 import Error
from subprocess import PIPE, TimeoutExpired
from time import sleep
from unittest import TestCase, skip
from unittest.mock import Mock, mock_open, patch

from lighter import lighter_pb2 as pb
from lighter import settings, utils
from lighter.utils import Enforcer as Enf

MOD = import_module('lighter.utils')
CTX = 'context'

class UtilsTests(TestCase):
    """ Tests for the utils module """

    @patch('lighter.utils.dictConfig')
    def test_update_logger(self, mocked_dictConfig):
        # Correct case: absolute path
        values = {'LOGS_DIR': '/path'}
        with patch.dict('os.environ', values):
            MOD.update_logger()
        mocked_dictConfig.assert_called_once_with(settings.LOGGING)
        self.assertEqual(settings.LOGS_DIR, '/path')
        self.assertIn('file', settings.LOGGING['loggers']['']['handlers'])
        self.assertEqual(settings.LOGGING['handlers']['file']['filename'],
                         '/path/lighter.log')
        # Correct case: relative path
        reset_mocks(vars())
        values = {'LOGS_DIR': './lighter-data/logs'}
        with patch.dict('os.environ', values):
            MOD.update_logger()
        mocked_dictConfig.assert_called_once_with(settings.LOGGING)
        self.assertEqual(settings.LOGS_DIR, './lighter-data/logs')
        self.assertIn('file', settings.LOGGING['loggers']['']['handlers'])
        self.assertEqual(settings.LOGGING['handlers']['file']['filename'],
                         '/srv/app/lighter-data/logs/lighter.log')

    @patch('lighter.utils.LOGGER', autospec=True)
    def test_log_intro(self, mocked_logger):
        MOD.log_intro('7.7.7')
        self.assertEqual(mocked_logger.info.call_count, 11)

    @patch('lighter.utils.LOGGER', autospec=True)
    def test_log_outro(self, mocked_logger):
        MOD.log_outro()
        self.assertEqual(mocked_logger.info.call_count, 2)

    @patch('lighter.utils.slow_exit', autospec=True)
    @patch('lighter.utils.sleep', autospec=True)
    @patch('lighter.utils.LOGGER', autospec=True)
    @patch('lighter.utils.getattr')
    @patch('lighter.utils.import_module')
    def test_check_connection(self, mocked_import, mocked_getattr,
                              mocked_logger, mocked_sleep, mocked_slow_exit):
        # Correct case (with version)
        settings.IMPLEMENTATION = 'imp'
        mocked_import.return_value = 'mod'
        func = Mock()
        func.return_value = pb.GetInfoResponse(
            identity_pubkey='777', version='v1')
        mocked_getattr.return_value = func
        MOD.check_connection()
        mocked_import.assert_called_once_with('lighter.light_imp')
        # Correct case (no version)
        reset_mocks(vars())
        settings.IMPLEMENTATION = 'imp'
        mocked_import.return_value = 'mod'
        info = pb.GetInfoResponse(identity_pubkey='777')
        func = Mock()
        func.return_value = info
        mocked_getattr.return_value = func
        MOD.check_connection()
        mocked_import.assert_called_once_with('lighter.light_imp')
        # No response case
        reset_mocks(vars())
        mocked_getattr.side_effect = [RuntimeError(), func]
        MOD.check_connection()
        assert mocked_logger.error.called

    def test_FakeContext(self):
        with self.assertRaises(RuntimeError):
            MOD.FakeContext().abort(7, 'error')

    def test_get_start_options(self):
        settings.INSECURE_CONNECTION = 0
        # Secure connection case with macaroons enabled
        reset_mocks(vars())
        values = {
            'IMPLEMENTATION': 'asd',
            'SERVER_CRT': 'crt',
            'SERVER_KEY': 'key',
            'DB_DIR': 'mac_db_dir',
            'MACAROONS_DIR': 'mac_dir',
        }
        with patch.dict('os.environ', values):
            MOD.get_start_options()
        self.assertEqual(settings.INSECURE_CONNECTION, False)
        # Insecure connection case
        values = {
            'IMPLEMENTATION': 'asd',
            'INSECURE_CONNECTION': '1',
        }
        with patch.dict('os.environ', values):
            MOD.get_start_options()
        self.assertEqual(settings.INSECURE_CONNECTION, True)
        self.assertEqual(settings.DISABLE_MACAROONS, True)
        # No secrets case
        reset_mocks(vars())
        values = {
            'IMPLEMENTATION': 'clightning',
            'INSECURE_CONNECTION': '1',
            'DISABLE_MACAROONS': '1',
        }
        with patch.dict('os.environ', values):
            MOD.get_start_options()
        self.assertEqual(settings.NO_SECRETS, True)

    def test_str2bool(self):
        ## force_true=False
        # Empty string case
        res = MOD.str2bool('')
        self.assertEqual(res, False)
        # Yes case
        res = MOD.str2bool('yes')
        self.assertEqual(res, True)
        # No case
        res = MOD.str2bool('no')
        self.assertEqual(res, False)
        # Random string case
        res = MOD.str2bool('p')
        self.assertEqual(res, False)
        ## force_true=True
        # Empty string case
        res = MOD.str2bool('', force_true=True)
        self.assertEqual(res, True)
        # Yes case
        res = MOD.str2bool('yes', force_true=True)
        self.assertEqual(res, True)
        # No case
        res = MOD.str2bool('no', force_true=True)
        self.assertEqual(res, False)
        # Random string case
        res = MOD.str2bool('p', force_true=True)
        self.assertEqual(res, True)

    @patch('lighter.utils.Err')
    @patch('lighter.utils.Popen', autospec=True)
    def test_command(self, mocked_popen, mocked_err):
        # Correct case
        mocked_popen.return_value.communicate.return_value = (b'mocked!', b'')
        settings.CMD_BASE = ['eclair-cli']
        cmd = ['getinfo']
        CMD = settings.CMD_BASE + list(cmd)
        res = MOD.command('context', *cmd)
        mocked_popen.assert_called_with(
            CMD, env=None, stdout=PIPE, stderr=PIPE, universal_newlines=False)
        mocked_popen.return_value.communicate.assert_called_with(
            timeout=settings.IMPL_TIMEOUT)
        self.assertEqual(res.strip(), 'mocked!')
        self.assertNotEqual(res.strip(), 'not mocked!')
        # Error from command case
        reset_mocks(vars())
        mocked_err.side_effect = RuntimeError()
        mocked_popen.return_value.communicate.return_value = (b'', b'error')
        settings.CMD_BASE = ['eclair-cli']
        cmd = ['getinfo']
        CMD = settings.CMD_BASE + list(cmd)
        with self.assertRaises(RuntimeError):
            res = MOD.command('context', *cmd)
        mocked_popen.assert_called_with(
            CMD, env=None, stdout=PIPE, stderr=PIPE, universal_newlines=False)
        mocked_popen.return_value.communicate.assert_called_with(
            timeout=settings.IMPL_TIMEOUT)
        # Timeout case
        reset_mocks(vars())
        mocked_err.side_effect = None
        settings.CMD_BASE = ['eclair-cli']
        cmd = ['getinfo']
        CMD = settings.CMD_BASE + list(cmd)

        def slow_func(*args, **kwargs):
            raise TimeoutExpired(cmd, settings.IMPL_TIMEOUT)

        mocked_popen.return_value.communicate = slow_func
        res = MOD.command('context', *cmd)
        mocked_popen.assert_called_with(
            CMD, env=None, stdout=PIPE, stderr=PIPE, universal_newlines=False)
        mocked_popen.return_value.kill.assert_called_with()
        mocked_err().unexpected_error.assert_called_once_with(
            'context', 'Empty result from command')
        # Command empty case
        reset_mocks(vars())
        settings.CMD_BASE = []
        with self.assertRaises(RuntimeError):
            MOD.command('context', 'command')

    @patch('lighter.utils.Enforcer.check_value')
    @patch('lighter.utils._convert_value', autospec=True)
    def test_convert(self, mocked_conv_val, mocked_check_val):
        # Correct case: bits to msats
        mocked_conv_val.return_value = 777000000
        res = MOD.convert('context', Enf.MSATS, 777, enforce=Enf.LN_TX)
        mocked_conv_val.assert_called_once_with('context', Enf.BITS, Enf.MSATS,
                                                777, Enf.MSATS)
        mocked_check_val('context', 777000000, Enf.LN_TX)
        self.assertEqual(res, 777000000)
        # Correct case: msats to bits
        reset_mocks(vars())
        mocked_conv_val.return_value = 777
        res = MOD.convert('context', Enf.MSATS, 777000000)
        mocked_conv_val.assert_called_once_with('context', Enf.MSATS, Enf.BITS,
                                                777000000, Enf.MSATS)
        assert not mocked_check_val.called
        self.assertEqual(res, 777)

    @patch('lighter.utils.Err')
    def test_convert_value(self, mocked_err):
        # Correct case: Decimal output
        res = MOD._convert_value('context', Enf.BITS, Enf.SATS, 777, Enf.MSATS)
        self.assertEqual(res, 77700)
        assert not mocked_err().value_error.called
        # Correct case: int output
        reset_mocks(vars())
        res = MOD._convert_value(
            'context', Enf.BITS, Enf.SATS, 777, max_precision=Enf.SATS)
        self.assertEqual(type(res), int)
        # Error case: string input
        reset_mocks(vars())
        mocked_err().value_error.side_effect = InvalidOperation()
        with self.assertRaises(InvalidOperation):
            res = MOD._convert_value('context', Enf.BITS, Enf.SATS, 'err',
                                     Enf.MSATS)
        mocked_err().value_error.assert_called_once_with('context')
        # Error case: too big number input
        reset_mocks(vars())
        mocked_err().value_error.side_effect = InvalidOperation()
        with self.assertRaises(InvalidOperation):
            res = MOD._convert_value('context', Enf.BITS, Enf.SATS,
                                     777777777777777777777777777, Enf.SATS)
        mocked_err().value_error.assert_called_once_with('context')

    @patch('lighter.utils.Err')
    def test_check_value(self, mocked_err):
        mocked_err().value_too_low.side_effect = Exception()
        mocked_err().value_too_high.side_effect = Exception()
        # Correct case, default type
        Enf.check_value('context', 7)
        # Correct case, specific type
        Enf.check_value('context', 7, enforce=Enf.LN_TX)
        # Error value_too_low case
        reset_mocks(vars())
        with self.assertRaises(Exception):
            Enf.check_value('context', 0.001, enforce=Enf.LN_TX)
        mocked_err().value_too_low.assert_called_once_with('context')
        assert not mocked_err().value_too_high.called
        # Error value_too_high case
        reset_mocks(vars())
        with self.assertRaises(Exception):
            Enf.check_value('context', 2**32 + 1, enforce=Enf.LN_TX)
        assert not mocked_err().value_too_low.called
        mocked_err().value_too_high.assert_called_once_with('context')
        # Check disabled case
        reset_mocks(vars())
        settings.ENFORCE = False
        Enf.check_value('context', 7)
        assert not mocked_err().value_too_low.called
        assert not mocked_err().value_too_high.called

    @patch('lighter.utils.Err')
    def test_check_req_params(self, mocked_err):
        # Raising error case
        mocked_err().missing_parameter.side_effect = Exception()
        request = pb.OpenChannelRequest()
        with self.assertRaises(Exception):
            MOD.check_req_params(CTX, request, 'node_uri', 'funding_bits')
        mocked_err().missing_parameter.assert_called_once_with(CTX, 'node_uri')

    @patch('lighter.utils.sleep', autospec=True)
    @patch('lighter.utils.LOGGER', autospec=True)
    def test_slow_exit(self, mocked_logger, mocked_sleep):
        # Filled message
        with self.assertRaises(SystemExit):
            MOD.slow_exit('msg')
        mocked_logger.error.assert_called_once_with('msg')
        mocked_sleep.assert_called_once_with(settings.RESTART_THROTTLE)
        # Empty message
        reset_mocks(vars())
        with self.assertRaises(SystemExit):
            MOD.slow_exit('')
        mocked_logger.error.assert_called_once_with('')
        mocked_sleep.assert_called_once_with(settings.RESTART_THROTTLE)

    @patch('lighter.utils.slow_exit', autospec=True)
    def test_handle_keyboardinterrupt(self, mocked_slow_exit):
        grpc_server = Mock()
        # Correct case
        func = Mock()
        wrapped = MOD.handle_keyboardinterrupt(func)
        res = wrapped(grpc_server)
        self.assertEqual(res, None)
        self.assertEqual(func.call_count, 1)
        # KeyboardInterrupt case
        reset_mocks(vars())
        func.side_effect = KeyboardInterrupt()
        wrapped = MOD.handle_keyboardinterrupt(func)
        res = wrapped(grpc_server)
        self.assertEqual(res, None)
        self.assertEqual(func.call_count, 1)
        grpc_server.stop.assert_called_once_with(settings.GRPC_GRACE_TIME)
        mocked_slow_exit.assert_called_once_with(
            'Keyboard interrupt detected. Exiting...', wait=False)

    def test_gen_random_data(self):
        length = 7
        res = MOD.gen_random_data(length)
        self.assertEqual(len(res), length)
        self.assertTrue(isinstance(res, bytes))

    @patch('lighter.utils.Err')
    def test_crypter(self, mocked_err):
        password = 'lighterrocks'
        plain_data = b'lighter is cool'
        # Crypt
        crypter = MOD.Crypter(password)
        crypt_data = crypter.crypt(plain_data)
        # Decrypt
        crypter = MOD.Crypter(password)
        decrypted_data = crypter.decrypt(CTX, crypt_data)
        self.assertEqual(plain_data, decrypted_data)
        # Error case
        with patch('lighter.utils.SecretBox') as mocked_box:
            mocked_box.return_value.decrypt.side_effect = CryptoError
            crypter = MOD.Crypter(password)
            decrypted_data = crypter.decrypt(CTX, crypt_data)
            mocked_err().wrong_password.assert_called_once_with(CTX)
        # Wrong version case
        wrong_data = crypt_data.replace(b'v1', b'v2', 1)
        crypter = MOD.Crypter(password)
        with self.assertRaises(RuntimeError):
            wrong_decrypted_data = crypter.decrypt(CTX, wrong_data)

    @patch('lighter.utils.Err')
    def test_handle_db_errors(self, mocked_err):
        func = Mock()
        # Db error case
        func.side_effect = Error()
        wrapped = MOD._handle_db_errors(func)
        mocked_err.side_effect = RuntimeError()
        with self.assertRaises(RuntimeError):
            res = wrapped()
            self.assertEqual(res, None)
        self.assertEqual(func.call_count, 1)
        # Correct case
        reset_mocks(vars())
        mocked_err.side_effect = None
        smt = '777'
        func.side_effect = None
        func.return_value = smt
        wrapped = MOD._handle_db_errors(func)
        res = wrapped()
        self.assertEqual(res, smt)
        self.assertEqual(func.call_count, 1)

    def test_save_key_in_db(self):
        data = b'data'
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            res = MOD.DbHandler.save_key_in_db(CTX, data)
            self.assertEqual(connection.execute.call_count, 3)

    def test_get_key_from_db(self):
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.return_value = ('a',)
            res = MOD.DbHandler.get_key_from_db(CTX)
            self.assertEqual(res, 'a')
        # missing entry case
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = None
            cursor.fetchone.return_value = (0,)
            res = MOD.DbHandler.get_key_from_db(CTX)
            self.assertEqual(res, None)

    def test_save_secret_in_db(self):
        data = b'data'
        table = 'tbl'
        index = '0'
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            res = MOD.DbHandler.save_secret_in_db(CTX, table, 1, data)
            self.assertEqual(connection.execute.call_count, 3)

    def test_get_secret_from_db(self):
        table = 'tbl'
        index = '0'
        sec = 'secret'
        # with entry case
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = [(1,), (1,), (sec,)]
            secret, active = MOD.DbHandler.get_secret_from_db(CTX, table)
            self.assertEqual(sec, secret)
            self.assertEqual(active, 1)
        # missing entry case
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = None
            cursor.fetchone.return_value = (0,)
            secret, active = MOD.DbHandler.get_secret_from_db(CTX, table)
            self.assertEqual(secret, None)
            self.assertEqual(active, None)
        # inactive secret case
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = [(1,), (0,), (sec,)]
            secret, active = MOD.DbHandler.get_secret_from_db(CTX, table)
            self.assertEqual(sec, secret)
            self.assertEqual(active, 0)

def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
