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
from os import urandom

from nacl.exceptions import CryptoError
from sqlite3 import Error
from subprocess import PIPE, TimeoutExpired
from time import sleep
from unittest import TestCase, skip
from unittest.mock import Mock, mock_open, patch

from lighter import lighter_pb2 as pb
from lighter import settings, utils
from lighter.utils import Enforcer as Enf
from tests import fixtures_utils as fix

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
        # abort test
        with self.assertRaises(RuntimeError):
            MOD.FakeContext().abort(7, 'error')
        # time_remaining test
        res = MOD.FakeContext().time_remaining()
        self.assertEqual(res, None)

    @patch('lighter.utils._detect_impl_secret', autospec=True)
    def test_get_start_options(self, mocked_detect):
        settings.INSECURE_CONNECTION = 0
        mocked_detect.return_value = False
        # Secure connection case with macaroons enabled and detect
        reset_mocks(vars())
        values = {
            'IMPLEMENTATION': 'asd',
            'SERVER_CRT': 'crt',
            'SERVER_KEY': 'key',
            'DB_DIR': 'mac_db_dir',
            'MACAROONS_DIR': 'mac_dir',
            'CLI_HOST': 'cli',
        }
        with patch.dict('os.environ', values):
            MOD.get_start_options(detect=True)
        self.assertEqual(settings.INSECURE_CONNECTION, False)
        # Insecure connection case
        settings.IMPLEMENTATION_SECRETS = False
        values = {
            'IMPLEMENTATION': 'asd',
            'INSECURE_CONNECTION': '1',
            'CLI_HOST': 'cli',
        }
        with patch.dict('os.environ', values):
            MOD.get_start_options()
        self.assertEqual(settings.INSECURE_CONNECTION, True)
        self.assertEqual(settings.DISABLE_MACAROONS, True)
        # No secrets case (with warning)
        reset_mocks(vars())
        values = {
            'IMPLEMENTATION': 'clightning',
            'INSECURE_CONNECTION': '1',
            'DISABLE_MACAROONS': '1',
            'CLI_HOST': 'cli',
        }
        with patch.dict('os.environ', values):
            MOD.get_start_options(warning=True)

    @patch('lighter.utils.slow_exit', autospec=True)
    @patch('lighter.utils.DbHandler', autospec=True)
    def test_detect_impl_secret(self, mocked_db, mocked_exit):
        sec = 'secret'
        mocked_exit.side_effect = Exception()
        # c-lightning case
        settings.IMPLEMENTATION = 'clightning'
        res = MOD._detect_impl_secret()
        self.assertEqual(res, False)
        # lnd with no secrets case
        settings.IMPLEMENTATION = 'lnd'
        mocked_db.get_secret_from_db.return_value = None, None, None
        res = MOD._detect_impl_secret()
        self.assertEqual(res, False)
        # lnd with secrets case
        mocked_db.get_secret_from_db.return_value = sec, 1, None
        res = MOD._detect_impl_secret()
        self.assertEqual(res, True)
        # lnd with active but no secret
        mocked_db.get_secret_from_db.return_value = None, 1, None
        with self.assertRaises(Exception):
            res = MOD._detect_impl_secret()
        assert mocked_exit.called
        # eclair with secrets case
        settings.IMPLEMENTATION = 'eclair'
        mocked_db.get_secret_from_db.return_value = sec, 1, None
        res = MOD._detect_impl_secret()
        self.assertEqual(res, True)
        # eclair with no secrets case
        mocked_db.get_secret_from_db.return_value = None, None, None
        with self.assertRaises(Exception):
            res = MOD._detect_impl_secret()
        assert mocked_exit.called

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

    @patch('lighter.utils.LOGGER', autospec=True)
    @patch('lighter.utils.Err')
    @patch('lighter.utils.Popen', autospec=True)
    @patch('lighter.utils.get_node_timeout', autospec=True)
    def test_command(self, mocked_get_time, mocked_popen, mocked_err,
                     mocked_logger):
        time = 10
        mocked_get_time.return_value = time
        # Correct case
        mocked_popen.return_value.communicate.return_value = (b'mocked!', b'')
        settings.CMD_BASE = ['eclair-cli']
        cmd = ['getinfo']
        CMD = settings.CMD_BASE + list(cmd)
        res = MOD.command(CTX, *cmd)
        mocked_popen.assert_called_with(
            CMD, env=None, stdout=PIPE, stderr=PIPE, universal_newlines=False)
        mocked_popen.return_value.communicate.assert_called_with(timeout=time)
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
            res = MOD.command(CTX, *cmd)
        mocked_popen.assert_called_with(
            CMD, env=None, stdout=PIPE, stderr=PIPE, universal_newlines=False)
        mocked_popen.return_value.communicate.assert_called_with(timeout=time)
        # Empty result from command
        reset_mocks(vars())
        mocked_popen.return_value.communicate.return_value = (b'', b'')
        res = MOD.command(CTX, *cmd)
        mocked_logger.debug.assert_called_once_with(
            'Empty result from command')
        # Timeout case
        reset_mocks(vars())
        mocked_err.side_effect = None
        mocked_err().node_error.side_effect = Exception()
        settings.CMD_BASE = ['eclair-cli']
        cmd = ['getinfo']
        CMD = settings.CMD_BASE + list(cmd)

        def slow_func(*args, **kwargs):
            raise TimeoutExpired(cmd, 100)

        mocked_popen.return_value.communicate = slow_func
        with self.assertRaises(Exception):
            res = MOD.command(CTX, *cmd)
        mocked_popen.assert_called_with(
            CMD, env=None, stdout=PIPE, stderr=PIPE, universal_newlines=False)
        mocked_popen.return_value.kill.assert_called_with()
        mocked_err().node_error.assert_called_once_with(CTX, 'Timeout')
        # Command empty case
        reset_mocks(vars())
        settings.CMD_BASE = []
        with self.assertRaises(RuntimeError):
            MOD.command(CTX, 'command')

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

    @patch('lighter.utils.log_outro', autospec=True)
    @patch('lighter.utils.sleep', autospec=True)
    @patch('lighter.utils.LOGGER', autospec=True)
    def test_slow_exit(self, mocked_logger, mocked_sleep, mocked_logoutro):
        msg = 'message'
        # Waiting
        with self.assertRaises(SystemExit):
            MOD.slow_exit(msg)
        mocked_logger.error.assert_called_once_with(msg)
        mocked_sleep.assert_called_once_with(settings.RESTART_THROTTLE)
        # Not waiting
        reset_mocks(vars())
        with self.assertRaises(SystemExit):
            MOD.slow_exit(msg, wait=False)
        mocked_logger.error.assert_called_once_with(msg)
        assert not mocked_sleep.called

    def test_get_node_timeout(self):
        # Client without timeout
        ctx = Mock()
        ctx.time_remaining.return_value = None
        res = MOD.get_node_timeout(ctx)
        self.assertEqual(res, settings.IMPL_MIN_TIMEOUT)
        # Client with long timeout
        ctx.time_remaining.return_value = 100
        res = MOD.get_node_timeout(ctx)
        self.assertEqual(res, 100 - settings.RESPONSE_RESERVED_TIME)
        # Client with not enough timeout
        ctx.time_remaining.return_value = 0.01
        res = MOD.get_node_timeout(ctx)
        self.assertEqual(res, settings.IMPL_MIN_TIMEOUT)

    def test_get_thread_timeout(self):
        # Client without timeout
        ctx = Mock()
        ctx.time_remaining.return_value = None
        res = MOD.get_thread_timeout(ctx)
        self.assertEqual(res, settings.THREAD_TIMEOUT)
        # Client with enough timeout
        ctx.time_remaining.return_value = 10
        res = MOD.get_thread_timeout(ctx)
        self.assertEqual(res, 10 - settings.RESPONSE_RESERVED_TIME)
        # Client with not enough timeout
        ctx.time_remaining.return_value = 0.01
        res = MOD.get_thread_timeout(ctx)
        self.assertEqual(res, 0)

    @patch('lighter.utils.slow_exit', autospec=True)
    @patch('lighter.utils.sleep', autospec=True)
    def test_handle_keyboardinterrupt(self, mocked_sleep, mocked_slow_exit):
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
        close_event = Mock()
        close_event.is_set.side_effect = [False, True]
        grpc_server.stop.return_value = close_event
        wrapped = MOD.handle_keyboardinterrupt(func)
        res = wrapped(grpc_server)
        assert mocked_sleep.called
        self.assertEqual(res, None)
        self.assertEqual(func.call_count, 1)
        grpc_server.stop.assert_called_once_with(settings.GRPC_GRACE_TIME)
        assert mocked_slow_exit.called

    def test_handle_logs(self):
        req = pb.GetInfoRequest()
        ctx = Mock()
        ctx.peer.return_value = 'ipv4:0.0.0.0'
        ctx.invocation_metadata.return_value = fix.METADATA
        response = pb.GetInfoResponse()
        func = Mock(return_value=response)
        wrapped = MOD.handle_logs(func)
        res = wrapped('self', req, ctx)
        self.assertEqual(res, response)
        self.assertEqual(func.call_count, 1)

    def test_handle_thread(self):
        # return case
        response = 'response'
        func = Mock(return_value=response)
        req = 'request'
        wrapped = MOD.handle_thread(func)
        res = wrapped(req)
        self.assertEqual(res, response)
        self.assertEqual(func.call_count, 1)
        # raise case
        func.side_effect = RuntimeError()
        with self.assertRaises(RuntimeError):
            wrapped = MOD.handle_thread(func)
            res = wrapped(req)
            self.assertEqual(res, None)

    @patch('lighter.utils._has_numbers', autospec=True)
    def test_has_amount_encoded(self, mocked_has_num):
        pay_req = 'lntb5n1pw3mupk'
        mocked_has_num.return_value = True
        res = MOD.has_amount_encoded(pay_req)
        self.assertEqual(res, True)
        pay_req = 'lntb1pw3mumupk'
        mocked_has_num.return_value = False
        res = MOD.has_amount_encoded(pay_req)
        self.assertEqual(res, False)

    def test_has_numbers(self):
        res = MOD._has_numbers('light3r')
        self.assertEqual(res, True)
        res = MOD._has_numbers('lighter')
        self.assertEqual(res, False)

    def test_get_channel_balances(self):
        # Full channel list case
        channels = fix.LISTCHANNELRESPONSE.channels
        res = MOD.get_channel_balances(CTX, channels)
        self.assertEqual(res.balance, 3824.3)
        self.assertEqual(res.out_tot_now, 3158.3)
        self.assertEqual(res.out_max_now, 3110.71)
        self.assertEqual(res.in_tot, 1244.71)
        self.assertEqual(res.in_tot_now, 689.71)
        self.assertEqual(res.in_max_now, 659.34)
        # Empty channel list case
        reset_mocks(vars())
        res = MOD.get_channel_balances(CTX, [])
        self.assertEqual(res, pb.ChannelBalanceResponse())

    def test_ScryptParams(self):
        salt = b'salt'
        scrypt_params = MOD.ScryptParams(salt)
        serialized = scrypt_params.serialize()
        scrypt_params = MOD.ScryptParams('')
        scrypt_params.deserialize(serialized)
        self.assertEqual(scrypt_params.salt, salt)

    @patch('lighter.utils.Err')
    @patch('lighter.utils.Crypter')
    @patch('lighter.utils.ScryptParams', autospec=True)
    @patch('lighter.utils.DbHandler', autospec=True)
    def test_check_password(self, mocked_db, mocked_params, mocked_crypter,
                            mocked_err):
        pwd = 'password'
        # Correct
        mocked_db.get_token_from_db.return_value = ['token', 'params']
        mocked_crypter.decrypt.return_value = settings.ACCESS_TOKEN
        MOD.check_password(CTX, pwd)
        mocked_err().wrong_password.assert_not_called()
        # Wrong
        wrong_token = 'wrong_token'
        mocked_crypter.decrypt.return_value = wrong_token
        MOD.check_password(CTX, pwd)
        mocked_err().wrong_password.assert_called_once_with(CTX)

    @patch('lighter.utils.Err')
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
        with patch('lighter.utils.SecretBox') as mocked_box:
            mocked_box.return_value.decrypt.side_effect = CryptoError
            decrypted_data = MOD.Crypter.decrypt(CTX, crypt_data, derived_key)
            mocked_err().wrong_password.assert_called_once_with(CTX)
            mocked_err().reset_mock()
        # Wrong version case
        wrong_data = 'random_wrong_stuff'
        MOD.Crypter.decrypt(CTX, wrong_data, derived_key)
        mocked_err().wrong_password.assert_called_once_with(CTX)

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

    def test_save_in_db(self):
        data = params = b'data'
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            res = MOD.DbHandler._save_in_db(CTX, 'table', data, params)
            self.assertEqual(connection.execute.call_count, 2)

    @patch('lighter.utils.path', autospec=True)
    def test_is_db_ok(self, mocked_path):
        mocked_path.isfile.return_value = True
        # correct case
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = [(1,), (0,)]
            res = MOD.DbHandler.is_db_ok(CTX)
            self.assertEqual(res, True)
        # missing token case
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = [(0,), (0,)]
            res = MOD.DbHandler.is_db_ok(CTX)
            self.assertEqual(res, False)
        # existing old salt table
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = [(0,), (1,)]
            res = MOD.DbHandler.is_db_ok(CTX)
            self.assertEqual(res, False)
        # missing database case
        mocked_path.isfile.return_value = False
        res = MOD.DbHandler.is_db_ok(CTX)
        self.assertEqual(res, False)


    def test_get_from_db(self):
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = [(1,), 'a']
            res = MOD.DbHandler._get_from_db(CTX, 'table')
            self.assertEqual(res, 'a')
        # missing entry case
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = [(None,)]
            res = MOD.DbHandler._get_from_db(CTX, 'table')
            self.assertEqual(res, (None, None))

    @patch('lighter.utils.DbHandler._save_in_db')
    def test_save_token_in_db(self, mocked_save):
        data = b'data'
        MOD.DbHandler.save_token_in_db(CTX, 1, data)
        assert mocked_save.called

    def test_get_token_from_db(self):
        data = b'data'
        with patch('lighter.utils.DbHandler._get_from_db') as mocked_get:
            mocked_get.return_value = data
            res = MOD.DbHandler.get_token_from_db(CTX)
            self.assertEqual(res, data)

    @patch('lighter.utils.DbHandler._save_in_db')
    def test_save_mac_params_in_db(self, mocked_save):
        params = b'data'
        MOD.DbHandler.save_mac_params_in_db(CTX, params)
        assert mocked_save.called

    def test_get_mac_params_from_db(self):
        data = (b'data', b'params')
        with patch('lighter.utils.DbHandler._get_from_db') as mocked_get:
            mocked_get.return_value = data
            res = MOD.DbHandler.get_mac_params_from_db(CTX)
            self.assertEqual(res, data[1])

    def test_save_secret_in_db(self):
        data = params = b'data'
        implementation = 'impl'
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            res = MOD.DbHandler.save_secret_in_db(
                CTX, implementation, 1, data, params)
            self.assertEqual(connection.execute.call_count, 2)

    @patch('lighter.utils.path', autospec=True)
    def test_get_secret_from_db(self, mocked_path):
        impl = 'implementation'
        sec = 'secret'
        act = 1
        par = b'params'
        mocked_path.isfile.return_value = True
        # with entry case
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = [(1,), (impl,act,sec,par,)]
            secret, active, params = \
                MOD.DbHandler.get_secret_from_db(CTX, impl)
            self.assertEqual(sec, secret)
            self.assertEqual(active, act)
            self.assertEqual(par, params)
        # missing table case
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = [(None,)]
            secret, active, params = \
                MOD.DbHandler.get_secret_from_db(CTX, impl)
            self.assertEqual(secret, None)
            self.assertEqual(active, None)
            self.assertEqual(params, None)
        # missing entry for implementation case
        with patch('lighter.utils.connect') as mocked_connect:
            connection = mocked_connect.return_value.__enter__.return_value
            cursor = connection.cursor.return_value
            cursor.fetchone.side_effect = [(1,), ()]
            secret, active, params = \
                MOD.DbHandler.get_secret_from_db(CTX, impl)
            self.assertEqual(secret, None)
            self.assertEqual(active, None)
            self.assertEqual(params, None)
        # missing db case
        mocked_path.isfile.return_value = False
        secret, active, params = \
            MOD.DbHandler.get_secret_from_db(CTX, impl)
        self.assertEqual(secret, None)
        self.assertEqual(active, None)
        self.assertEqual(params, None)


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
