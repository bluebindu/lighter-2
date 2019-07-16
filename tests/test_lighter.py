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
from grpc import ssl_server_credentials, StatusCode
from importlib import import_module
from unittest import TestCase, skip
from unittest.mock import Mock, mock_open, patch

from lighter import lighter_pb2 as pb
from lighter import settings, utils
from tests import fixtures_lighter as fix

MOD = import_module('lighter.lighter')
CTX = 'context'


class LighterTests(TestCase):
    """ Tests for lighter module """

    @patch('lighter.lighter.check_password', autospec=True)
    @patch('lighter.lighter.slow_exit', autospec=True)
    @patch('lighter.lighter.import_module', autospec=True)
    @patch('lighter.lighter.ScryptParams', autospec=True)
    @patch('lighter.lighter.get_baker', autospec=True)
    @patch('lighter.lighter.DbHandler', autospec=True)
    @patch('lighter.lighter.Crypter', autospec=True)
    @patch('lighter.lighter.check_req_params', autospec=True)
    def test_UnlockLighter(self, mocked_check_par, mocked_crypter,
                               mocked_db, mocked_baker, mocked_params,
                               mocked_import, mocked_slow_exit,
                               mocked_check_password):
        password = 'password'
        params = b'params'
        # with macaroon enabled but no implementation secrets
        request = pb.UnlockLighterRequest(password=password)
        mocked_db.get_mac_params_from_db.return_value = params
        mocked_db.get_secret_from_db.return_value = ('secret', 1, params)
        mocked_check_password.return_value = True
        res = MOD.UnlockerServicer().UnlockLighter(request, CTX)
        mocked_import.return_value.update_settings.assert_called_once_with(
            None)
        # with macaroon enabled and implementation secrets
        reset_mocks(vars())
        settings.IMPLEMENTATION_SECRETS = True
        request = pb.UnlockLighterRequest(password=password)
        mocked_db.get_mac_params_from_db.return_value = params
        mocked_db.get_secret_from_db.return_value = ('secret', 1, params)
        mocked_crypter.decrypt.return_value = 'plain_data'
        mocked_check_password.return_value = True
        res = MOD.UnlockerServicer().UnlockLighter(request, CTX)
        mocked_import.return_value.update_settings.assert_called_once_with(
            'plain_data')



    @patch('lighter.lighter.Err')
    @patch('lighter.lighter.getattr')
    @patch('lighter.lighter.import_module')
    def test_dispatcher(self, mocked_import, mocked_getattr, mocked_err):
        ctx = Mock()
        ctx.peer.return_value = 'ipv4:0.0.0.0'
        ctx.invocation_metadata.return_value = fix.METADATA
        request = pb.GetInfoRequest()
        response = pb.GetInfoResponse()
        # Correct case
        settings.IMPLEMENTATION = ''
        mocked_import.return_value = 'module'
        grpc_server = MOD.LightningServicer()
        func = Mock()
        func.return_value = response
        mocked_getattr.return_value = func
        res = grpc_server.unexistent(request, ctx)
        mocked_import.assert_called_once_with('lighter.light_')
        mocked_getattr.assert_called_once_with('module', 'unexistent')
        assert not mocked_err().unimplemented_method.called
        self.assertEqual(res, response)
        # Error case
        reset_mocks(vars())
        grpc_server = MOD.LightningServicer()
        mocked_import.return_value = 'module'
        mocked_getattr.side_effect = AttributeError()
        mocked_err().unimplemented_method.side_effect = Exception()
        with self.assertRaises(Exception):
            res = grpc_server.unexistent(request, ctx)
        mocked_import.assert_called_once_with('lighter.light_')
        mocked_getattr.assert_called_once_with('module', 'unexistent')
        mocked_err().unimplemented_method.assert_called_once_with(ctx)

    @patch('lighter.lighter.check_macaroons', autospec=True)
    @patch('lighter.lighter.unary_unary_rpc_method_handler')
    def test_intercept_service(self, mocked_rpc_handler, mocked_check_mac):
        settings.DISABLE_MACAROONS = False
        continuation = Mock()
        ok = 'ok'
        continuation.return_value = ok
        method = '/lighter.Lightning/GetInfo'
        md = 'invocation_metadata'
        handler_call_details = Mock()
        handler_call_details.method = method
        handler_call_details.invocation_metadata = md
        interceptor = MOD.Interceptor()
        # Accepted request
        mocked_check_mac.return_value = True
        res = interceptor.intercept_service(continuation, handler_call_details)
        continuation.assert_called_once_with(handler_call_details)
        mocked_check_mac.assert_called_once_with(md, method)
        self.assertEqual(res, ok)
        # Unaccepted request
        reset_mocks(vars())
        handler_call_details.method = 'Unacceptable'
        nok = 'not ok'
        ign_req = 'ignored_request'
        ctx = Mock()

        def func(callback):
            callback(ign_req, ctx)

        mocked_rpc_handler.side_effect = func
        interceptor = MOD.Interceptor()
        res = interceptor.intercept_service(continuation, handler_call_details)
        self.assertEqual(res, None)
        ctx.abort.assert_called_once_with(StatusCode.UNAUTHENTICATED,
                                          'Access denied')
        # Macaroons disabled
        reset_mocks(vars())
        settings.DISABLE_MACAROONS = True
        handler_call_details.method = method
        res = interceptor.intercept_service(continuation, handler_call_details)
        self.assertEqual(res, ok)
        assert not mocked_check_mac.called
        settings.DISABLE_MACAROONS = False

    @patch('lighter.lighter.ssl_server_credentials', autospec=True)
    @patch('lighter.lighter._add_servicer_to_server', autospec=True)
    @patch('lighter.lighter.server', autospec=True)
    def test_create_server(self, mocked_server, mocked_add_servicer,
                           mocked_creds):
        servicer = 'servicer'
        interceptors = ['interceptor']
        grpc_server = Mock()
        # Insecure connection case
        settings.INSECURE_CONNECTION = 1
        mocked_server.return_value = grpc_server
        res = MOD._create_server(servicer, interceptors)
        assert mocked_server.called
        mocked_add_servicer.assert_called_once_with(servicer, grpc_server)
        mocked_server.return_value.add_insecure_port.assert_called_with(
            settings.LIGHTER_ADDR)
        self.assertEqual(res, grpc_server)
        # Secure connection case
        reset_mocks(vars())
        settings.INSECURE_CONNECTION = 0
        settings.SERVER_KEY = '/certs/server.key',
        settings.SERVER_CRT = '/certs/server.crt'
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
        with patch('lighter.lighter.open', mopen):
            res = MOD._create_server(servicer, interceptors)
        assert mocked_server.called
        mocked_add_servicer.assert_called_once_with(servicer, grpc_server)
        mopen.assert_called_with(settings.SERVER_CRT, 'rb')
        for m in mimes:
            m.read.assert_called_once_with()
        mocked_server.return_value.add_secure_port.assert_called_with(
            settings.LIGHTER_ADDR, creds)

    @patch('lighter.lighter.pb_grpc.add_UnlockerServicer_to_server')
    @patch('lighter.lighter.pb_grpc.add_LightningServicer_to_server')
    def test_add_servicer_to_server(self, mocked_lightning, mocked_unlocker):
        ln_servicer = MOD.LightningServicer()
        un_servicer = MOD.UnlockerServicer()
        grpc_server = 'grpc_server'
        # LightningServicer
        MOD._add_servicer_to_server(ln_servicer, grpc_server)
        mocked_lightning.assert_called_once_with(ln_servicer, grpc_server)
        # UnlockerServicer
        reset_mocks(vars())
        MOD._add_servicer_to_server(un_servicer, grpc_server)
        mocked_unlocker.assert_called_once_with(un_servicer, grpc_server)

    @patch('lighter.lighter._unlocker_wait', autospec=True)
    @patch('lighter.lighter.LOGGER', autospec=True)
    @patch('lighter.lighter._log_listening', autospec=True)
    @patch('lighter.lighter._create_server')
    def test_serve_unlocker(self, mocked_create_srv, mocked_log,
                            mocked_logger, mocked_wait):
        grpc_server = Mock()
        mocked_create_srv.return_value = grpc_server
        MOD._serve_unlocker()
        mocked_log.assert_called_once_with('Unlocker service')
        mocked_logger.info.assert_called_once_with(
            'Waiting for password to unlock Lightning service...')
        mocked_wait.assert_called_once_with(grpc_server)

    @patch('lighter.lighter._lightning_wait', autospec=True)
    @patch('lighter.lighter._log_listening', autospec=True)
    @patch('lighter.lighter._create_server')
    def test_serve_lightning(self, mocked_create_srv, mocked_log, mocked_wait):
        grpc_server = Mock()
        mocked_create_srv.return_value = grpc_server
        MOD._serve_lightning()
        mocked_log.assert_called_once_with('Lightning service')
        mocked_wait.assert_called_once_with(grpc_server)

    @patch('lighter.lighter.LOGGER', autospec=True)
    def test_log_listening(self, mocked_logger):
        s_name = 'servicer_name'
        # Insecure connection
        settings.INSECURE_CONNECTION = 1
        MOD._log_listening(s_name)
        assert mocked_logger.info.called
        # Secure connection
        reset_mocks(vars())
        settings.INSECURE_CONNECTION = 0
        MOD._log_listening(s_name)
        assert mocked_logger.info.called

    @patch('lighter.lighter.sleep', autospec=True)
    def test_unlocker_wait(self, mocked_sleep):
        settings.UNLOCKER_STOP = False
        grpc_server = Mock()

        def unlock(*args):
            settings.UNLOCKER_STOP = True

        mocked_sleep.side_effect = unlock
        MOD._unlocker_wait(grpc_server)
        grpc_server.stop.assert_called_once_with(0)

    @patch('lighter.lighter.sleep', autospec=True)
    def test_lightning_wait(self, mocked_sleep):
        grpc_server = Mock()
        mocked_sleep.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD._lightning_wait(grpc_server)

    @patch('lighter.lighter.slow_exit', autospec=True)
    @patch('lighter.lighter._serve_lightning', autospec=True)
    @patch('lighter.lighter._serve_unlocker', autospec=True)
    @patch('lighter.lighter.Thread', autospec=True)
    @patch('lighter.lighter.import_module')
    @patch('lighter.lighter.DbHandler', autospec=True)
    @patch('lighter.lighter.get_start_options', autospec=True)
    def test_start(self, mocked_get_start_opt, mocked_db, mocked_import,
                   mocked_thread, mocked_serve_unlocker, mocked_serve_lightning,
                   mocked_slow_exit):
        mocked_slow_exit.side_effect = Exception()
        # with secrets case
        settings.ENABLE_UNLOCKER = True
        mocked_db.is_db_ok.return_value = True
        MOD.start()
        mocked_get_start_opt.assert_called_once_with(warning=True, detect=True)
        mocked_serve_unlocker.assert_called_once_with()
        mocked_serve_lightning.assert_called_once_with()
        assert not mocked_slow_exit.called
        # no secrets case
        reset_mocks(vars())
        settings.ENABLE_UNLOCKER = False
        settings.IMPLEMENTATION = 'asd'
        MOD.start()
        mocked_get_start_opt.assert_called_once_with(warning=True, detect=True)
        mocked_import.assert_called_once_with('lighter.light_asd')
        mocked_import.return_value.update_settings.assert_called_once_with(None)
        mocked_thread.assert_called_once_with(target=utils.check_connection)
        mocked_thread.return_value.start.assert_called_once_with()
        mocked_serve_lightning.assert_called_once_with()
        assert not mocked_slow_exit.called
        # no encrypted token in db
        reset_mocks(vars())
        settings.ENABLE_UNLOCKER = True
        mocked_db.is_db_ok.return_value = False
        settings.DISABLE_MACAROONS = False
        with self.assertRaises(Exception):
            MOD.start()
        assert mocked_slow_exit.called
        # old db version case
        reset_mocks(vars())
        mocked_db.is_db_ok.return_value = False
        with self.assertRaises(Exception):
            MOD.start()
        assert mocked_slow_exit.called
        mocked_get_start_opt.assert_called_once_with(warning=True, detect=True)
        # Exceptions handling case
        reset_mocks(vars())
        mocked_slow_exit.side_effect = None
        exceptions = [ImportError, KeyError, RuntimeError, FileNotFoundError]
        for exc in exceptions:
            reset_mocks(vars())
            mocked_get_start_opt.side_effect = exc('msg')
            MOD.start()
            assert mocked_slow_exit.called
        reset_mocks(vars())
        mocked_db.return_value.is_db_ok.return_value = None
        MOD.start()
        assert mocked_slow_exit.called

def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
