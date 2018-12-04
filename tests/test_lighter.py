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

""" Tests for lighter module """

from concurrent import futures
from grpc import ssl_server_credentials
from importlib import import_module
from unittest import TestCase, skip
from unittest.mock import Mock, mock_open, patch

from lighter import lighter_pb2 as pb
from lighter import lighter, settings, utils

MOD = import_module('lighter.lighter')


class LighterTests(TestCase):
    """ Tests for lighter module """

    @patch('lighter.lighter.Err')
    @patch('lighter.lighter.getattr')
    @patch('lighter.lighter.import_module')
    def test_dispatcher(self, mocked_import, mocked_getattr, mocked_err):
        # Correct case
        settings.IMPLEMENTATION = ''
        mocked_import.return_value = 'module'
        grpc_server = MOD.LightningServicer()
        func = Mock()
        func.return_value = 'dispatcher'
        mocked_getattr.return_value = func
        res = grpc_server.unexistent('request', 'context')
        mocked_import.assert_called_once_with('lighter.light_')
        mocked_getattr.assert_called_once_with('module', 'unexistent')
        assert not mocked_err().unimplemented_method.called
        self.assertEqual(res, 'dispatcher')
        # Error case
        reset_mocks(vars())
        grpc_server = MOD.LightningServicer()
        mocked_import.return_value = 'module'
        mocked_getattr.side_effect = AttributeError()
        mocked_err().unimplemented_method.side_effect = Exception()
        with self.assertRaises(Exception):
            res = grpc_server.unexistent('request', 'context')
        mocked_import.assert_called_once_with('lighter.light_')
        mocked_getattr.assert_called_once_with('module', 'unexistent')
        mocked_err().unimplemented_method.assert_called_once_with('context')

    @patch('lighter.lighter.LOGGER', autospec=True)
    @patch('lighter.lighter.ssl_server_credentials', autospec=True)
    @patch('lighter.lighter.sleep', autospec=True)
    @patch('lighter.lighter.pb_grpc.add_LightningServicer_to_server')
    @patch('lighter.lighter.server', autospec=True)
    def test_serve(self, mocked_server, mocked_add_to_server, mocked_sleep,
                   mocked_creds, mocked_logger):
        # Insecure connection case
        settings.INSECURE_CONN = 1
        info = pb.GetInfoResponse(identity_pubkey='abc', version='v7')
        mocked_sleep.side_effect = KeyboardInterrupt()
        MOD._serve(info)
        assert mocked_server.called
        assert mocked_add_to_server.called
        mocked_server.return_value.add_insecure_port.assert_called_with(
            '{}:{}'.format(settings.HOST, settings.INSECURE_PORT))
        mocked_server.return_value.start.assert_called_with()
        mocked_sleep.assert_called_once_with(settings.ONE_DAY_IN_SECONDS)
        mocked_server.return_value.stop.assert_called_with(
            settings.GRPC_GRACE_TIME)
        self.assertEqual(mocked_logger.info.call_count, 3)
        # Secure connection case
        reset_mocks(vars())
        settings.SECURE_CONN = 1
        settings.INSECURE_CONN = 0
        info = pb.GetInfoResponse()
        values = {
            'SERVER_KEY': '/certs/server.key',
            'SERVER_CRT': '/certs/server.crt'}
        files = [b'KEY', b'CRT']
        mimes = []
        for file in files:
            mimes.append(mock_open(read_data=file).return_value)
        mopen = mock_open()
        mopen.side_effect = mimes
        creds = ssl_server_credentials(((
            b'KEY',
            b'CRT',), ))
        mocked_creds.return_value = creds
        mocked_sleep.side_effect = KeyboardInterrupt()
        with patch.dict('os.environ', values):
            with patch('lighter.lighter.open', mopen):
                MOD._serve(info)
        assert mocked_server.called
        assert mocked_add_to_server.called
        mopen.assert_called_with(settings.SERVER_CRT, 'rb')
        for m in mimes:
            m.read.assert_called_once_with()
        mocked_server.return_value.add_secure_port.assert_called_with(
            '{}:{}'.format(settings.HOST, settings.SECURE_PORT), creds)
        mocked_server.return_value.start.assert_called_with()
        mocked_sleep.assert_called_once_with(settings.ONE_DAY_IN_SECONDS)
        mocked_server.return_value.stop.assert_called_with(
            settings.GRPC_GRACE_TIME)
        self.assertEqual(mocked_logger.info.call_count, 3)

    @patch('lighter.lighter.sleep', autospec=True)
    @patch('lighter.lighter.LOGGER', autospec=True)
    def test_slow_exit(self, mocked_logger, mocked_sleep):
        # Filled message
        with self.assertRaises(SystemExit):
            MOD._slow_exit('msg')
        mocked_logger.error.assert_called_once_with('msg')
        mocked_sleep.assert_called_once_with(settings.RESTART_THROTTLE)
        # Empty message
        reset_mocks(vars())
        with self.assertRaises(SystemExit):
            MOD._slow_exit('')
        mocked_logger.error.assert_called_once_with('')
        mocked_sleep.assert_called_once_with(settings.RESTART_THROTTLE)

    @patch('lighter.lighter._slow_exit', autospec=True)
    @patch('lighter.utils.get_connection_modes', autospec=True)
    @patch('lighter.lighter._serve', autospec=True)
    @patch('lighter.utils.check_connection', autospec=True)
    @patch('lighter.lighter.LOGGER', autospec=True)
    @patch('lighter.lighter.import_module')
    def test_start(self, mocked_import, mocked_logger, mocked_check_err_conn,
                   mocked_serve, mocked_get_conn_modes, mocked_slow_exit):
        # Correct case
        values = {'IMPLEMENTATION': 'LND'}
        info = pb.GetInfoResponse(identity_pubkey='abc')
        mocked_check_err_conn.return_value = info
        with patch.dict('os.environ', values):
            MOD.start()
        mocked_import.assert_called_once_with('lighter.light_lnd')
        mocked_import.return_value.update_settings.assert_called_once_with()
        mocked_check_err_conn.assert_called_once_with()
        mocked_get_conn_modes.assert_called_once_with()
        mocked_serve.assert_called_once_with(info)
        assert not mocked_slow_exit.called
        self.assertEqual(settings.IMPLEMENTATION, 'lnd')
        self.assertEqual(mocked_logger.info.call_count, 2)
        # Exceptions handling case
        reset_mocks(vars())
        exceptions = [ImportError, KeyError, RuntimeError, FileNotFoundError]
        for exc in exceptions:
            reset_mocks(vars())
            mocked_import.side_effect = exc('msg')
            with patch.dict('os.environ', values):
                MOD.start()
            mocked_import.assert_called_once_with('lighter.light_lnd')
            assert not mocked_import.return_value.update_settings.called
            assert not mocked_check_err_conn.called
            assert not mocked_serve.called
            assert not mocked_get_conn_modes.called
            assert mocked_slow_exit.called
            self.assertEqual(mocked_logger.info.call_count, 0)


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
