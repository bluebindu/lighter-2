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

from concurrent.futures import TimeoutError as TimeoutFutError
from configparser import Error as ConfigError
from grpc import ssl_server_credentials, StatusCode
from importlib import import_module
from inspect import unwrap
from unittest import TestCase, skip
from unittest.mock import Mock, mock_open, patch

from . import proj_root

pb = import_module(proj_root + '.lighter_pb2')
utils = import_module(proj_root + '.utils')
settings = import_module(proj_root + '.settings')
MOD = import_module(proj_root + '.lighter')
CTX = 'context'


class LighterTests(TestCase):
    """ Tests for lighter module """

    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.ThreadPoolExecutor', autospec=True)
    @patch(MOD.__name__ + '.import_module', autospec=True)
    @patch(MOD.__name__ + '.ScryptParams', autospec=True)
    @patch(MOD.__name__ + '.get_baker', autospec=True)
    @patch(MOD.__name__ + '.get_secret', autospec=True)
    @patch(MOD.__name__ + '.get_mac_params_from_db', autospec=True)
    @patch(MOD.__name__ + '.Crypter', autospec=True)
    @patch(MOD.__name__ + '.check_password', autospec=True)
    @patch(MOD.__name__ + '.session_scope', autospec=True)
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_UnlockLighter(self, mocked_check_par, mocked_ses,
                           mocked_check_password, mocked_crypter,
                           mocked_db_mac, mocked_get_sec, mocked_baker,
                           mocked_params, mocked_import, mocked_thread,
                           mocked_log):
        unlock_self = MOD.UnlockerServicer()
        unlock_func = unwrap(unlock_self.UnlockLighter)
        password = 'password'
        params = b'params'
        # with macaroon enabled but no implementation secrets
        request = pb.UnlockLighterRequest(password=password)
        mocked_db_mac.return_value = params
        mocked_get_sec.return_value = 'plain_data'
        mocked_check_password.return_value = True
        res = unlock_func(unlock_self, request, CTX)
        mocked_import.return_value.update_settings.assert_called_once_with(
            None)
        # with macaroon enabled and implementation secrets (lnd macaroon)
        reset_mocks(vars())
        settings.IMPLEMENTATION = 'lnd'
        settings.IMPLEMENTATION_SECRETS = True
        request = pb.UnlockLighterRequest(password=password)
        mocked_db_mac.return_value = params
        mocked_get_sec.return_value = 'plain_data'
        mocked_check_password.return_value = True
        res = unlock_func(unlock_self, request, CTX)
        mocked_import.return_value.update_settings.assert_called_once_with(
            'plain_data')
        # with macaroon disabled and implementation secrets (eclair password)
        reset_mocks(vars())
        settings.IMPLEMENTATION = 'eclair'
        settings.DISABLE_MACAROONS = True
        res = unlock_func(unlock_self, request, CTX)
        assert not mocked_db_mac.called
        # with unlock_node, no implementation secrets and disabled macaroons
        future = Mock()
        executor = Mock()
        executor.submit.return_value = future
        mocked_thread.return_value = executor
        ## result within timeout
        reset_mocks(vars())
        request = pb.UnlockLighterRequest(password=password, unlock_node=True)
        res = unlock_func(unlock_self, request, CTX)
        assert mocked_thread.return_value.submit.called
        assert not executor.shutdown.called
        future.result.assert_called_once_with(timeout=1)
        self.assertEqual(res, pb.UnlockLighterResponse())
        ## result times out
        reset_mocks(vars())
        future.result.side_effect = TimeoutFutError()
        res = unlock_func(unlock_self, request, CTX)
        executor.shutdown.assert_called_once_with(wait=False)
        self.assertEqual(res, pb.UnlockLighterResponse())
        ## result throws RuntimeError
        reset_mocks(vars())
        future.result.side_effect = RuntimeError()
        res = unlock_func(unlock_self, request, CTX)
        assert not executor.shutdown.called
        assert mocked_log.info.called
        self.assertEqual(res, pb.UnlockLighterResponse())
        ## unimplemented method
        reset_mocks(vars())
        executor.submit.side_effect = AttributeError()
        res = unlock_func(unlock_self, request, CTX)
        assert not executor.shutdown.called
        assert not mocked_log.called

    @patch(MOD.__name__ + '.Thread', autospec=True)
    @patch(MOD.__name__ + '.check_password', autospec=True)
    @patch(MOD.__name__ + '.session_scope', autospec=True)
    @patch(MOD.__name__ + '.check_req_params', autospec=True)
    def test_LockLighter(self, mocked_check_par, mocked_ses,
                         mocked_check_password, mocked_thread):
        password = 'password'
        settings.RUNTIME_SERVER = Mock()
        request = pb.LockLighterRequest(password=password)
        lock_self = MOD.LockerServicer()
        lock_func = unwrap(lock_self.LockLighter)
        res = lock_func(lock_self, request, CTX)
        settings.RUNTIME_SERVER.stop.assert_called_once_with(
            settings.GRPC_GRACE_TIME)
        self.assertEqual(res, pb.LockLighterResponse())

    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.getattr')
    @patch(MOD.__name__ + '.import_module')
    def test_dispatcher(self, mocked_import, mocked_getattr, mocked_err):
        lightning_self = MOD.LightningServicer()
        lightning_func = unwrap(lightning_self.unexistent)
        request = pb.GetInfoRequest()
        response = pb.GetInfoResponse()
        # Correct case
        settings.IMPLEMENTATION = 'impl'
        mocked_import.return_value = 'module'
        grpc_server = MOD.LightningServicer()
        func = Mock()
        func.return_value = response
        mocked_getattr.return_value = func
        res = lightning_func(request, CTX)
        mocked_import.assert_called_once_with('..light_impl', MOD.__name__)
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
            res = lightning_func(request, CTX)
        mocked_getattr.assert_called_once_with('module', 'unexistent')
        mocked_err().unimplemented_method.assert_called_once_with(
            CTX, 'unexistent')

    @patch(MOD.__name__ + '.check_macaroons', autospec=True)
    @patch(MOD.__name__ + '.unary_unary_rpc_method_handler')
    def test_RuntimeInterceptor(self, mocked_rpc_handler, mocked_check_mac):
        settings.DISABLE_MACAROONS = False
        continuation = Mock()
        ok = 'ok'
        continuation.return_value = ok
        method = '/lighter.Lightning/GetInfo'
        md = 'invocation_metadata'
        handler_call_details = Mock()
        handler_call_details.method = method
        handler_call_details.invocation_metadata = md
        interceptor = MOD.RuntimeInterceptor()
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
        interceptor = MOD.RuntimeInterceptor()
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

    @patch(MOD.__name__ + '.unary_unary_rpc_method_handler')
    def test_UnlockerInterceptor(self, mocked_rpc_handler):
        interceptor = MOD.UnlockerInterceptor()
        continuation = Mock()
        ok = 'ok'
        continuation.return_value = ok
        handler_call_details = Mock()
        # Correct API
        method = '/lighter.Unlocker/UnlockLighter'
        handler_call_details.method = method
        res = interceptor.intercept_service(continuation, handler_call_details)
        continuation.assert_called_once_with(handler_call_details)
        self.assertEqual(res, ok)
        # Wrong API
        reset_mocks(vars())
        ign_req = 'ignored_request'
        ctx = Mock()

        def func(callback):
            callback(ign_req, ctx)

        mocked_rpc_handler.side_effect = func
        interceptor = MOD.UnlockerInterceptor()
        method = '/lighter.Lightning/GetInfo'
        handler_call_details.method = method
        res = interceptor.intercept_service(continuation, handler_call_details)
        assert not continuation.called
        self.assertEqual(res, None)

    @patch(MOD.__name__ + '.ssl_server_credentials', autospec=True)
    @patch(MOD.__name__ + '.server', autospec=True)
    def test_create_server(self, mocked_server, mocked_creds):
        servicer = 'servicer'
        interceptors = ['interceptor']
        grpc_server = Mock()
        # Insecure connection case
        settings.INSECURE_CONNECTION = 1
        mocked_server.return_value = grpc_server
        res = MOD._create_server(interceptors)
        assert mocked_server.called
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
        with patch(MOD.__name__ + '.open', mopen):
            res = MOD._create_server(interceptors)
        assert mocked_server.called
        mopen.assert_called_with(settings.SERVER_CRT, 'rb')
        for m in mimes:
            m.read.assert_called_once_with()
        mocked_server.return_value.add_secure_port.assert_called_with(
            settings.LIGHTER_ADDR, creds)

    @patch(MOD.__name__ + '._unlocker_wait', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '._log_listening', autospec=True)
    @patch(MOD.__name__ + '.pb_grpc.add_UnlockerServicer_to_server')
    @patch(MOD.__name__ + '._create_server')
    def test_serve_unlocker(self, mocked_create_srv, mocked_add_unlocker,
                            mocked_log, mocked_logger, mocked_wait):
        grpc_server = Mock()
        mocked_create_srv.return_value = grpc_server
        MOD._serve_unlocker()
        mocked_log.assert_called_once_with('Unlocker service')
        mocked_logger.info.assert_called_once_with(
            'Waiting for password to unlock Lightning service...')
        mocked_wait.assert_called_once_with(grpc_server)

    @patch(MOD.__name__ + '._lightning_wait', autospec=True)
    @patch(MOD.__name__ + '._log_listening', autospec=True)
    @patch(MOD.__name__ + '.pb_grpc.add_LockerServicer_to_server')
    @patch(MOD.__name__ + '.pb_grpc.add_LightningServicer_to_server')
    @patch(MOD.__name__ + '._create_server')
    def test_serve_runtime(self, mocked_create_srv, mocked_add_lightning,
                           mocked_add_locker, mocked_log, mocked_wait):
        grpc_server = Mock()
        mocked_create_srv.return_value = grpc_server
        MOD._serve_runtime()
        mocked_log.assert_called_once_with('Lightning service')
        mocked_wait.assert_called_once_with(grpc_server)

    @patch(MOD.__name__ + '.LOGGER', autospec=True)
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

    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.sleep', autospec=True)
    def test_interrupt_threads(self, mocked_sleep, mocked_logger):
        # Correct case
        settings.RUNTIME_SERVER = Mock()
        close_event = Mock()
        close_event.is_set.side_effect = [False, True]
        settings.RUNTIME_SERVER.stop.return_value = close_event
        MOD._interrupt_threads()
        assert mocked_sleep.called
        settings.RUNTIME_SERVER.stop.assert_called_once_with(
            settings.GRPC_GRACE_TIME)
        assert mocked_logger.info.called

    @patch(MOD.__name__ + '.sleep', autospec=True)
    def test_unlocker_wait(self, mocked_sleep):
        settings.UNLOCKER_STOP = False
        grpc_server = Mock()

        def unlock(*args):
            settings.UNLOCKER_STOP = True

        mocked_sleep.side_effect = unlock
        MOD._unlocker_wait(grpc_server)
        grpc_server.stop.assert_called_once_with(0)

    @patch(MOD.__name__ + '.sleep', autospec=True)
    def test_lightning_wait(self, mocked_sleep):
        grpc_server = Mock()
        mocked_sleep.side_effect = Exception()
        with self.assertRaises(Exception):
            MOD._lightning_wait(grpc_server)

    @patch(MOD.__name__ + '._serve_runtime', autospec=True)
    @patch(MOD.__name__ + '._serve_unlocker', autospec=True)
    @patch(MOD.__name__ + '.Thread', autospec=True)
    @patch(MOD.__name__ + '.import_module')
    @patch(MOD.__name__ + '.is_db_ok', autospec=True)
    @patch(MOD.__name__ + '.session_scope', autospec=True)
    @patch(MOD.__name__ + '.init_db', autospec=True)
    @patch(MOD.__name__ + '.log_intro', autospec=True)
    @patch(MOD.__name__ + '.init_common', autospec=True)
    def test_start_lighter(self, mocked_init_common, mocked_logintro, mocked_init_db,
                   mocked_ses, mocked_db_ok, mocked_import, mocked_thread,
                   mocked_serve_unlocker, mocked_serve_runtime):
        # with secrets case
        mocked_db_ok.return_value = True
        config = Mock()
        MOD._start_lighter()
        msg = "Start Lighter's gRPC server"
        mocked_init_common.assert_called_once_with(msg)
        mocked_logintro.assert_called_once_with()
        mocked_init_db.assert_called_once_with()
        mocked_serve_unlocker.assert_called_once_with()
        mocked_serve_runtime.assert_called_once_with()
        # no secrets case
        reset_mocks(vars())
        settings.IMPLEMENTATION = 'asd'
        MOD._start_lighter()
        mocked_import.assert_called_once_with('..light_asd', MOD.__name__)
        mocked_thread.assert_called_once_with(target=utils.check_connection)
        mocked_thread.return_value.start.assert_called_once_with()
        mocked_serve_runtime.assert_called_once_with()
        # no encrypted token in db
        reset_mocks(vars())
        mocked_db_ok.return_value = False
        settings.DISABLE_MACAROONS = False
        with self.assertRaises(RuntimeError):
            MOD._start_lighter()

    @patch(MOD.__name__ + '.log_outro', autospec=True)
    @patch(MOD.__name__ + '._interrupt_threads', autospec=True)
    @patch(MOD.__name__ + '.die', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '._start_lighter', autospec=True)
    def test_start(self, mocked_start, mocked_log, mockedd_die,
                   mocked_int_threads, mocked_logoutro):
        mockedd_die.side_effect = SystemExit(1)
        # Correct case
        MOD.start()
        mocked_start.assert_called_once_with()
        # Exceptions handling case
        reset_mocks(vars())
        exceptions = [ImportError, KeyError, RuntimeError, FileNotFoundError,
                      ConfigError]
        for exc in exceptions:
            reset_mocks(vars())
            mocked_start.side_effect = exc('msg')
            with self.assertRaises(SystemExit) as err:
                MOD.start()
            self.assertEqual(err.exception.code, 1)
            assert mocked_log.error.called
        # InterruptException case
        reset_mocks(vars())
        mocked_start.side_effect = MOD.InterruptException()
        with self.assertRaises(SystemExit) as err:
            MOD.start()
        self.assertEqual(err.exception.code, 0)
        mocked_int_threads.assert_called_once_with()
        mocked_logoutro.assert_called_once_with()


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
