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

""" The Python implementation of the gRPC Lighter server """

import sys

from concurrent.futures import TimeoutError as TimeoutFutError, \
    ThreadPoolExecutor
from configparser import Error as ConfigError
from importlib import import_module
from logging import getLogger
from os import environ
from signal import signal, SIGTERM
from threading import active_count, Thread, Lock
from time import sleep

from grpc import server, ServerInterceptor, ssl_server_credentials, \
    StatusCode, unary_unary_rpc_method_handler
from sqlalchemy.exc import SQLAlchemyError

from . import lighter_pb2_grpc as pb_grpc
from . import lighter_pb2 as pb
from . import settings as sett
from .db import get_mac_params_from_db, init_db, is_db_ok, session_scope
from .errors import Err
from .macaroons import check_macaroons, get_baker
from .utils import check_connection, check_password, check_req_params, \
    Crypter, detect_impl_secret, die, FakeContext, get_secret, \
    handle_keyboardinterrupt, handle_logs, handle_sigterm, init_common, \
    InterruptException, log_intro, log_outro, ScryptParams

signal(SIGTERM, handle_sigterm)

LOGGER = getLogger(__name__)

environ["GRPC_SSL_CIPHER_SUITES"] = (
    "HIGH+ECDSA:"
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384")


class UnlockerServicer(pb_grpc.UnlockerServicer):
    """
    UnlockerServicer provides an implementation of the Unlocker service
    defined by protobuf.

    This service does not require macaroons authentication.
    """

    # pylint: disable=too-few-public-methods

    @handle_logs
    def UnlockLighter(self, request, context):
        """
        If password is correct, unlocks Lighter database, checks connection
        to node (continuing even if node is not reachable) and finally stops
        the UnlockerServicer.
        """
        check_req_params(context, request, 'password')
        password = request.password
        mod = import_module('..light_{}'.format(sett.IMPLEMENTATION), __name__)
        plain_secret = None
        with session_scope(context) as session:
            check_password(context, session, password)
            if not sett.DISABLE_MACAROONS:
                mac_params = ScryptParams('')
                mac_params.deserialize(get_mac_params_from_db(session))
                sett.MAC_ROOT_KEY = Crypter.gen_derived_key(
                    password, mac_params)
                baker = get_baker(sett.MAC_ROOT_KEY, put_ops=True)
                sett.RUNTIME_BAKER = baker
            if sett.IMPLEMENTATION_SECRETS:
                plain_secret = get_secret(
                    context, session, password, sett.IMPLEMENTATION,
                    sett.IMPL_SEC_TYPE, active_only=True)
        # Calls the implementation specific update method
        mod.update_settings(plain_secret)
        if request.unlock_node:
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(
                    mod.unlock_node, FakeContext(), password)
                future.result(timeout=1)  # max 1 second to unlock node
            except TimeoutFutError:
                executor.shutdown(wait=False)
            except RuntimeError as err:
                # don't fail lighter unlock if node unlock fails
                LOGGER.info(err)
            except AttributeError:
                pass  # don't fail if node unlock is unimplemented
        sett.UNLOCKER_STOP = True
        return pb.UnlockLighterResponse()


class LockerServicer(pb_grpc.LockerServicer):
    """
    LockerServicer provides an implementation of the Locker service
    defined by protobuf.
    """

    # pylint: disable=too-few-public-methods

    @handle_logs
    def LockLighter(self, request, context):
        """
        Locks Lighter on correct password, stops runtime server
        (LightningServicer + LockerServicer), deletes secrets from memory and
        starts Unlocker.
        """
        check_req_params(context, request, 'password')
        password = request.password
        with session_scope(context) as session:
            check_password(context, session, password)
        sett.MAC_ROOT_KEY = None
        sett.RUNTIME_BAKER = None
        sett.ECL_PASS = None
        sett.LND_MAC = None
        sett.RUNTIME_STOP = True
        return pb.LockLighterResponse()


class LightningServicer():  # pylint: disable=too-few-public-methods
    """
    LightningServicer provides an implementation of the methods of the
    Lightning service.

    Not deriving from the protobuf generated class to allow dynamic dispatching
    """

    def __getattr__(self, name):
        """ Dispatches gRPC request dynamically. """

        @handle_logs
        def dispatcher(request, context):
            # Importing module for specific implementation
            module = import_module('..light_{}'.format(sett.IMPLEMENTATION),
                                   __name__)
            # Searching client requested function in module
            try:
                func = getattr(module, name)
            except AttributeError:
                Err().unimplemented_method(context, name)
            # Return requested function if implemented
            return func(request, context)

        return dispatcher


def _access_denied_terminator():
    """ Returns an RpcMethodHandler if request is not accepted """
    def terminate(_ignored_request, context):
        """ Terminates gRPC call, denying access """
        context.abort(StatusCode.UNAUTHENTICATED, 'Access denied')

    return unary_unary_rpc_method_handler(terminate)


def _service_locked_terminator():
    """ Returns an RpcMethodHandler if service is locked """
    def terminate(_ignored_request, context):
        """ Terminates gRPC call """
        LOGGER.error('- Not an Unlocker operation')
        context.abort(StatusCode.UNIMPLEMENTED, 'Service is locked')

    return unary_unary_rpc_method_handler(terminate)


def _request_accepted(handler):
    """
    Checks if request is authorized: it is defined in ALL_PERMS and
    macaroons are disabled or macaroons correctly verify.
    """
    if handler.method not in sett.ALL_PERMS:
        LOGGER.error('- Not a runtime operation')
        return False
    if sett.DISABLE_MACAROONS:
        return True
    return check_macaroons(handler.invocation_metadata, handler.method)


class RuntimeInterceptor(ServerInterceptor):
    """
    gRPC interceptor that checks whether the request
    is authorized by the included macaroons
    """

    # pylint: disable=too-few-public-methods

    def __init__(self):
        self._terminator = _access_denied_terminator()

    def intercept_service(self, continuation, handler_call_details):
        """ Intercepts gRPC request to decide if request is authorized """
        if _request_accepted(handler_call_details):
            return continuation(handler_call_details)
        return self._terminator


class UnlockerInterceptor(ServerInterceptor):
    """
    gRPC interceptor that informs that Lighter is locked
    """

    # pylint: disable=too-few-public-methods

    def __init__(self):
        self._terminator = _service_locked_terminator()

    def intercept_service(self, continuation, handler_call_details):
        """
        Intercepts gRPC request to eventually inform client that service is
        locked
        """
        if handler_call_details.method == '/lighter.Unlocker/UnlockLighter':
            return continuation(handler_call_details)
        return self._terminator


def _create_server(interceptors):
    """ Creates a gRPC server in insecure or secure mode """
    if sett.INSECURE_CONNECTION:
        grpc_server = server(
            ThreadPoolExecutor(max_workers=sett.GRPC_WORKERS),
            interceptors=interceptors)
        grpc_server.add_insecure_port(sett.LIGHTER_ADDR)
    else:
        grpc_server = server(
            ThreadPoolExecutor(max_workers=sett.GRPC_WORKERS),
            interceptors=interceptors)
        with open(sett.SERVER_KEY, 'rb') as key:
            private_key = key.read()
        with open(sett.SERVER_CRT, 'rb') as cert:
            certificate_chain = cert.read()
        server_credentials = ssl_server_credentials(((
            private_key,
            certificate_chain,
        ), ))
        grpc_server.add_secure_port(sett.LIGHTER_ADDR, server_credentials)
    return grpc_server


def _serve_unlocker():
    """
    Starts a UnlockerServicer gRPC server
    """
    grpc_server = _create_server([UnlockerInterceptor()])
    pb_grpc.add_UnlockerServicer_to_server(UnlockerServicer(), grpc_server)
    grpc_server.start()
    _log_listening('Unlocker service')
    LOGGER.info('Waiting for password to unlock Lightning service...')
    _unlocker_wait(grpc_server)


def _serve_runtime():
    """
    Starts the runtime gRPC server composed by a LightningServicer and a
    LockerServicer
    """
    grpc_server = _create_server([RuntimeInterceptor()])
    pb_grpc.add_LightningServicer_to_server(LightningServicer(), grpc_server)
    pb_grpc.add_LockerServicer_to_server(LockerServicer(), grpc_server)
    sett.RUNTIME_SERVER = grpc_server
    grpc_server.start()
    _log_listening('Lightning service')
    _runtime_wait(grpc_server)


def _log_listening(servicer_name):
    """ Logs at which host and port the servicer is listening """
    if sett.INSECURE_CONNECTION:
        LOGGER.info(
            '%s listening on %s (insecure connection)',
            servicer_name, sett.LIGHTER_ADDR)
    else:
        LOGGER.info(
            '%s listening on %s (secure connection)',
            servicer_name, sett.LIGHTER_ADDR)


def _interrupt_threads():
    """ Tries to gracefully stop all pending threads of the runtime server """
    close_event = None
    if sett.RUNTIME_SERVER:
        close_event = sett.RUNTIME_SERVER.stop(sett.GRPC_GRACE_TIME)
    if close_event:
        while not close_event.is_set() or sett.THREADS:
            LOGGER.error('Waiting for %s threads to complete...',
                         active_count())
            sleep(3)
    LOGGER.info('All threads shutdown correctly')


def _unlocker_wait(grpc_server):
    """ Waits a signal to stop the UnlockerServicer """
    while not sett.UNLOCKER_STOP:
        sleep(1)
    grpc_server.stop(0)
    sett.UNLOCKER_STOP = False


def _runtime_wait(grpc_server):
    """ Waits a signal to stop the runtime server """
    while not sett.RUNTIME_STOP:
        sleep(1)
    grpc_server.stop(0)
    sett.RUNTIME_STOP = False


def _start_services(lock):
    """ Handles the unlocker and the runtime servers start """
    _serve_unlocker()
    con_thread = Thread(target=check_connection, args=(lock,))
    con_thread.daemon = True
    con_thread.start()
    _serve_runtime()


@handle_keyboardinterrupt
def _start_lighter():
    """
    Starts Lighter.

    Checks if a module for the requested implementation exists and imports it.
    Initializes Lighter and starts the Unlocker gRPC service.
    """
    init_common("Start Lighter's gRPC server")
    log_intro()
    init_db()
    with session_scope(FakeContext()) as session:
        if not is_db_ok(session):
            raise RuntimeError(
                'Your database configuration is incomplete or old. '
                'Update it by running lighter-secure (and deleting db)')
        sett.IMPLEMENTATION_SECRETS = detect_impl_secret(session)
    lock = Lock()
    while True:
        _start_services(lock)


def start():
    """
    Lighter entrypoint.

    Any raised and uncaught exception will be handled here.
    """
    try:
        _start_lighter()
    except ImportError:
        LOGGER.error(
            "Implementation '%s' is not supported", sett.IMPLEMENTATION)
        die()
    except KeyError as err:
        LOGGER.error("The environment variable '%s' needs to be set", err)
        die()
    except RuntimeError as err:
        if str(err):
            LOGGER.error(str(err))
        die()
    except FileNotFoundError as err:
        LOGGER.error(str(err))
        die()
    except ConfigError as err:
        err_msg = ''
        if str(err):
            err_msg = str(err)
        LOGGER.error('Configuration error: %s', err_msg)
        die()
    except SQLAlchemyError as err:
        err_msg = ''
        if str(err):
            err_msg = str(err)
        LOGGER.error('DB error: %s', err_msg)
        die()
    except InterruptException:
        _interrupt_threads()
        log_outro()
        sys.exit(0)
