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

from concurrent import futures
from importlib import import_module
from logging import getLogger
from os import environ
from time import sleep

from grpc import server, ssl_server_credentials

from . import lighter_pb2_grpc as pb_grpc
from . import settings, utils
from .errors import Err

LOGGER = getLogger(__name__)


class LightningServicer():  # pylint: disable=too-few-public-methods
    """
    LightningServicer provides an implementation of the methods of the
    Lightning service.

    Not deriving from the protobuf generated class to allow dynamic dispatching
    """

    def __getattr__(self, name):
        """ Dispatches gRPC request dynamically. """

        def dispatcher(request, context):
            # Importing module for specific implementation
            module = import_module('lighter.light_{}'.format(
                settings.IMPLEMENTATION))
            # Searching client requested function in module
            try:
                func = getattr(module, name)
            except AttributeError:
                Err().unimplemented_method(context)
            # Return requested function if implemented
            return func(request, context)

        return dispatcher


def _serve(info):
    """ Starts a gRPC server at the ip and port specified in settings """
    grpc_server = server(
        futures.ThreadPoolExecutor(max_workers=settings.GRPC_WORKERS))
    pb_grpc.add_LightningServicer_to_server(LightningServicer(), grpc_server)
    if settings.INSECURE_CONN:
        grpc_server.add_insecure_port('{}:{}'.format(settings.HOST,
                                                     settings.INSECURE_PORT))
    if settings.SECURE_CONN:
        settings.SERVER_KEY = environ['SERVER_KEY']
        with open(settings.SERVER_KEY, 'rb') as key:
            private_key = key.read()
        settings.SERVER_CRT = environ['SERVER_CRT']
        with open(settings.SERVER_CRT, 'rb') as cert:
            certificate_chain = cert.read()
        server_credentials = ssl_server_credentials(((
            private_key,
            certificate_chain,
        ), ))
        grpc_server.add_secure_port(
            '{}:{}'.format(settings.HOST, settings.SECURE_PORT),
            server_credentials)
    if info.version:
        LOGGER.info(
            'Using %s version %s', settings.IMPLEMENTATION, info.version)
    else:
        LOGGER.info('Using %s', settings.IMPLEMENTATION)
    grpc_server.start()
    if settings.INSECURE_CONN:
        LOGGER.info(
            'Listening on %s:%s (insecure connection)',
            settings.HOST, settings.INSECURE_PORT)
    if settings.SECURE_CONN:
        LOGGER.info(
            'Listening on %s:%s (secure connection)',
            settings.HOST, settings.SECURE_PORT)
    try:
        while True:
            sleep(settings.ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        grpc_server.stop(settings.GRPC_GRACE_TIME)
        _slow_exit('Keyboard interrupt detected. Exiting...')


def _slow_exit(message):
    """ Goes to sleep before exiting, useful when autorestarting (docker) """
    LOGGER.error(message)
    LOGGER.info(
        'Sleeping for %s secs before exiting...', settings.RESTART_THROTTLE)
    sleep(settings.RESTART_THROTTLE)
    sys.exit(1)


def start():
    """
    Starts the Lighter server.

    Checks if a module for the requested implementation exists and imports it.
    Updates settings and starts the Lighter gRPC server.

    Any raised exception will be handled with a slow exit.
    """
    try:
        settings.IMPLEMENTATION = environ['IMPLEMENTATION'].lower()
        # Checks if implementation is supported, could throw an ImportError
        mod = import_module('lighter.light_{}'.format(settings.IMPLEMENTATION))
        # Calls the implementation specific update method
        mod.update_settings()
        LOGGER.info(
            'Checking connection to %s node...', settings.IMPLEMENTATION)
        info = utils.check_connection()
        if info.identity_pubkey:
            LOGGER.info(
                'Connection to node "%s" successful', info.identity_pubkey)
        utils.get_connection_modes()
        _serve(info)
    except ImportError:
        _slow_exit('{} is not supported'.format(settings.IMPLEMENTATION))
    except KeyError as err:
        _slow_exit('{} environment variable needs to be set'.format(err))
    except RuntimeError as err:
        _slow_exit(str(err))
    except FileNotFoundError as err:
        _slow_exit(str(err))
