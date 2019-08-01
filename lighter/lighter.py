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

from concurrent import futures
from importlib import import_module
from logging import getLogger
from threading import Thread
from time import sleep

from grpc import server, ServerInterceptor, ssl_server_credentials, \
    StatusCode, unary_unary_rpc_method_handler

from . import lighter_pb2_grpc as pb_grpc
from . import lighter_pb2 as pb
from . import settings as sett
from .errors import Err
from .macaroons import check_macaroons, get_baker
from .utils import check_connection, check_password, check_req_params, \
    Crypter, DbHandler, FakeContext, get_start_options, \
    handle_keyboardinterrupt, handle_logs, ScryptParams, slow_exit

LOGGER = getLogger(__name__)


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
        check_password(context, password)
        if not sett.DISABLE_MACAROONS:
            mac_params = ScryptParams('')
            mac_params.deserialize(DbHandler.get_mac_params_from_db(context))
            sett.MAC_ROOT_KEY = Crypter.gen_derived_key(password, mac_params)
            baker = get_baker(sett.MAC_ROOT_KEY, put_ops=True)
            sett.RUNTIME_BAKER = baker
        plain_secret = None
        if sett.IMPLEMENTATION_SECRETS:
            secret, active, params = DbHandler.get_secret_from_db(
                context, sett.IMPLEMENTATION)
            if secret and active:
                secret_params = ScryptParams('')
                secret_params.deserialize(params)
                derived_key = Crypter.gen_derived_key(password, secret_params)
                plain_secret = Crypter.decrypt(context, secret, derived_key)
        # Checks if implementation is supported, could throw an ImportError
        mod = import_module('lighter.light_{}'.format(sett.IMPLEMENTATION))
        # Calls the implementation specific update method
        mod.update_settings(plain_secret)
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
        check_password(context, password)
        sett.RUNTIME_SERVER.stop(sett.GRPC_GRACE_TIME)
        restart_thread = Thread(target=start)
        restart_thread.daemon = True
        restart_thread.start()
        sett.MAC_ROOT_KEY = None
        sett.RUNTIME_BAKER = None
        sett.ECL_ENV = None
        sett.LND_MAC = None
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
            module = import_module('lighter.light_{}'.format(
                sett.IMPLEMENTATION))
            # Searching client requested function in module
            try:
                func = getattr(module, name)
            except AttributeError:
                Err().unimplemented_method(context)
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
            futures.ThreadPoolExecutor(max_workers=sett.GRPC_WORKERS),
            interceptors=interceptors)
        grpc_server.add_insecure_port(sett.LIGHTER_ADDR)
    else:
        grpc_server = server(
            futures.ThreadPoolExecutor(max_workers=sett.GRPC_WORKERS),
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
    _lightning_wait(grpc_server)


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


@handle_keyboardinterrupt
def _unlocker_wait(grpc_server):
    """ Waits a signal to stop the UnlockerServicer """
    while not sett.UNLOCKER_STOP:
        sleep(1)
    grpc_server.stop(0)
    sett.UNLOCKER_STOP = False


@handle_keyboardinterrupt
def _lightning_wait(_grpc_server):
    """ Keeps the LightningServicer on until a KeyboardInterrupt occurs """
    while True:
        sleep(sett.ONE_DAY_IN_SECONDS)


def start():
    """
    Starts the Lighter server.

    Checks if a module for the requested implementation exists and imports it.
    Updates settings and starts the Lighter gRPC server.

    Any raised exception will be handled with a slow exit.
    """
    try:
        get_start_options(warning=True, detect=True)
        if not DbHandler.is_db_ok(FakeContext()):
            slow_exit('Your database configuration is incomplete or old. '
                      'Update it by running make secure (and deleting db)')
        # Checks if implementation is supported, could throw an ImportError
        import_module('lighter.light_{}'.format(sett.IMPLEMENTATION))
        _serve_unlocker()
        con_thread = Thread(target=check_connection)
        con_thread.daemon = True
        con_thread.start()
        _serve_runtime()
    except ImportError:
        slow_exit('{} is not supported'.format(sett.IMPLEMENTATION))
    except KeyError as err:
        slow_exit('{} environment variable needs to be set'.format(err))
    except RuntimeError as err:
        slow_exit(str(err))
    except FileNotFoundError as err:
        slow_exit(str(err))
