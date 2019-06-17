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
from contextlib import suppress
from importlib import import_module
from logging import getLogger
from threading import Thread
from time import sleep, time

from grpc import server, ServerInterceptor, ssl_server_credentials, \
    StatusCode, unary_unary_rpc_method_handler

from . import lighter_pb2_grpc as pb_grpc
from . import lighter_pb2 as pb
from . import settings
from .errors import Err
from .macaroons import check_macaroons, get_baker
from .utils import check_connection, check_password, check_req_params, \
    Crypter, DbHandler, FakeContext, get_start_options, \
    handle_keyboardinterrupt, slow_exit

LOGGER = getLogger(__name__)


class UnlockerServicer(pb_grpc.UnlockerServicer):
    """
    UnlockerServicer provides an implementation of the Unlocker service
    defined with protobuf.

    This service does not require macaroons authentication.
    """

    # pylint: disable=too-few-public-methods

    def UnlockLighter(self, request, context):
        """
        If password is correct, unlocks Lighter database, checks connection
        to node (continuing even if node is not reachable) and finally stops
        the UnlockerServicer.
        """
        check_req_params(context, request, 'password')
        password = request.password
        for version, salt in DbHandler.get_salt_from_db(context):
            Crypter.gen_access_key(version, password, salt)
        check_password(context)
        if not settings.DISABLE_MACAROONS:
            baker = get_baker(settings.ACCESS_KEY_V1, put_ops=True)
            settings.LIGHTNING_BAKERY = baker
        plain_secret = None
        if settings.IMPLEMENTATION_SECRETS:
            version, secret, active = DbHandler.get_secret_from_db(
                context, settings.IMPLEMENTATION)
            if secret and active:
                plain_secret = Crypter.decrypt(context, version, secret)
        # Checks if implementation is supported, could throw an ImportError
        mod = import_module('lighter.light_{}'.format(settings.IMPLEMENTATION))
        # Calls the implementation specific update method
        mod.update_settings(plain_secret)
        settings.UNLOCKER_STOP = True
        return pb.UnlockLighterResponse()


class LightningServicer():  # pylint: disable=too-few-public-methods
    """
    LightningServicer provides an implementation of the methods of the
    Lightning service.

    Not deriving from the protobuf generated class to allow dynamic dispatching
    """

    def __getattr__(self, name):
        """ Dispatches gRPC request dynamically. """

        def dispatcher(request, context):
            start_time = time()
            peer = user_agent = 'unknown'
            with suppress(ValueError):
                peer = context.peer().split(':', 1)[1]
            for data in context.invocation_metadata():
                if data.key == 'user-agent':
                    user_agent = data.value
            LOGGER.info('< %-24s %s %s',
                        request.DESCRIPTOR.name, peer, user_agent)
            # Importing module for specific implementation
            module = import_module('lighter.light_{}'.format(
                settings.IMPLEMENTATION))
            # Searching client requested function in module
            try:
                func = getattr(module, name)
            except AttributeError:
                Err().unimplemented_method(context)
            # Return requested function if implemented
            response = func(request, context)
            response_name = response.DESCRIPTOR.name
            stop_time = time()
            call_time = round(stop_time - start_time, 3)
            LOGGER.info('> %-24s %s %2.3fs',
                        response_name, peer, call_time)
            LOGGER.debug('Full response: %s', str(response).replace('\n', ' '))
            return response

        return dispatcher


def _unary_unary_rpc_terminator():
    """ Returns an RpcMethodHandler if request is not accepted """
    def terminate(_ignored_request, context):
        """ Terminates gRPC call, denying access"""
        context.abort(StatusCode.UNAUTHENTICATED, 'Access denied')

    return unary_unary_rpc_method_handler(terminate)


def _request_accepted(handler):
    """
    Checks if request is authorized: it is defined in ALL_PERMS and
    macaroons are disabled or macaroons correctly verify.
    """
    if handler.method not in settings.ALL_PERMS:
        LOGGER.error('- Not a Lightning operation')
        return False
    if settings.DISABLE_MACAROONS:
        return True
    return check_macaroons(handler.invocation_metadata, handler.method)


class Interceptor(ServerInterceptor):  # pylint: disable=too-few-public-methods
    """ gRPC interceptor that checks whether the request
    is authorized by the included macaroons """

    def __init__(self):
        self._terminator = _unary_unary_rpc_terminator()

    def intercept_service(self, continuation, handler_call_details):
        """ Intercepts gRPC request to decide if request is authorized """
        if _request_accepted(handler_call_details):
            return continuation(handler_call_details)
        return self._terminator


def _create_server(servicer, interceptors):
    """ Creates a gRPC server in insecure or secure mode """
    if settings.INSECURE_CONNECTION:
        grpc_server = server(
            futures.ThreadPoolExecutor(max_workers=settings.GRPC_WORKERS))
        grpc_server.add_insecure_port(settings.LIGHTER_ADDR)
        _add_servicer_to_server(servicer, grpc_server)
    else:
        grpc_server = server(
            futures.ThreadPoolExecutor(max_workers=settings.GRPC_WORKERS),
            interceptors=interceptors)
        with open(settings.SERVER_KEY, 'rb') as key:
            private_key = key.read()
        with open(settings.SERVER_CRT, 'rb') as cert:
            certificate_chain = cert.read()
        server_credentials = ssl_server_credentials(((
            private_key,
            certificate_chain,
        ), ))
        grpc_server.add_secure_port(settings.LIGHTER_ADDR, server_credentials)
        _add_servicer_to_server(servicer, grpc_server)
    return grpc_server


def _add_servicer_to_server(servicer, grpc_server):
    """ Adds an Unlocker or Lightning servicer to a gRPC server """
    if isinstance(servicer, LightningServicer):
        pb_grpc.add_LightningServicer_to_server(servicer, grpc_server)
    elif isinstance(servicer, UnlockerServicer):
        pb_grpc.add_UnlockerServicer_to_server(servicer, grpc_server)


def _serve_unlocker():
    """
    Starts a UnlockerServicer gRPC server at the ip and port specified in
    settings
    """
    grpc_server = _create_server(UnlockerServicer(), None)
    grpc_server.start()
    _log_listening('Unlocker service')
    LOGGER.info('Waiting for password to unlock Lightning service...')
    _unlocker_wait(grpc_server)


def _serve_lightning():
    """
    Starts a LightningServicer gRPC server at the ip and port specified in
    settings
    """
    grpc_server = _create_server(LightningServicer(), [Interceptor()])
    grpc_server.start()
    _log_listening('Lightning service')
    _lightning_wait(grpc_server)


def _log_listening(servicer_name):
    """ Logs at which host and port the servicer is listening """
    if settings.INSECURE_CONNECTION:
        LOGGER.info(
            '%s listening on %s (insecure connection)',
            servicer_name, settings.LIGHTER_ADDR)
    else:
        LOGGER.info(
            '%s listening on %s (secure connection)',
            servicer_name, settings.LIGHTER_ADDR)


@handle_keyboardinterrupt
def _unlocker_wait(grpc_server):
    """ Waits a signal to stop the UnlockerServicer """
    while not settings.UNLOCKER_STOP:
        sleep(1)
    grpc_server.stop(0)


@handle_keyboardinterrupt
def _lightning_wait(_grpc_server):
    """ Keeps the LightningServicer on until a KeyboardInterrupt occurs """
    while True:
        sleep(settings.ONE_DAY_IN_SECONDS)


def start():
    """
    Starts the Lighter server.

    Checks if a module for the requested implementation exists and imports it.
    Updates settings and starts the Lighter gRPC server.

    Any raised exception will be handled with a slow exit.
    """
    try:
        get_start_options(warning=True, detect=True)
        if settings.ENABLE_UNLOCKER:
            if not DbHandler.has_token(FakeContext()):
                slow_exit('Your database configuration results incomplete or '
                          'old. Update it by running make secure (and '
                          'deleting db)')
            _serve_unlocker()
        else:
            # Checks if implementation is supported, could throw an ImportError
            mod = import_module(
                'lighter.light_{}'.format(settings.IMPLEMENTATION))
            # Calls the implementation specific update method
            mod.update_settings(None)
        con_thread = Thread(target=check_connection)
        con_thread.daemon = True
        con_thread.start()
        _serve_lightning()
    except ImportError:
        slow_exit('{} is not supported'.format(settings.IMPLEMENTATION))
    except KeyError as err:
        slow_exit('{} environment variable needs to be set'.format(err))
    except RuntimeError as err:
        slow_exit(str(err))
    except FileNotFoundError as err:
        slow_exit(str(err))
