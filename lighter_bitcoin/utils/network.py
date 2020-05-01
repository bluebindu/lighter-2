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

""" Network utils module """

from importlib import import_module
from logging import getLogger
from time import sleep

from requests import Session as ReqSession
from requests.exceptions import ConnectionError as ReqConnectionErr, \
    Timeout

from .. import lighter_pb2 as pb, settings as sett
from ..errors import Err
from .misc import disable_logger

LOGGER = getLogger(__name__)


def check_connection(lock):
    """
    Calls a GetInfo in order to check if connection to node is successful
    """
    try:
        acquired = lock.acquire(blocking=False)
        if not acquired:
            return
        request = pb.GetInfoRequest()
        module = import_module(
            '...light_{}'.format(sett.IMPLEMENTATION), __name__)
        info = None
        LOGGER.info('Checking connection to %s node...', sett.IMPLEMENTATION)
        attempts = 0
        while not info:
            try:
                with disable_logger():
                    info = getattr(module, 'GetInfo')(request, FakeContext())
            except RuntimeError as err:
                LOGGER.error(
                    'Connection to LN node failed: %s', str(err).strip())
            attempts += 1
            if not info:
                sleep(min(attempts * 2, 60 * 60))
                continue
            if info.identity_pubkey:
                LOGGER.info(
                    'Connection to node "%s" successful', info.identity_pubkey)
            if info.version:
                LOGGER.info(
                    'Using %s version %s', sett.IMPLEMENTATION, info.version)
            else:
                LOGGER.info('Using %s', sett.IMPLEMENTATION)
    finally:
        if acquired:
            lock.release()


def check_req_params(context, request, *parameters):
    """
    Raises a missing_parameter error if one of parameters is not given in the
    request
    """
    for param in parameters:
        if not getattr(request, param):
            Err().missing_parameter(context, param)


def get_node_timeout(context, min_time=sett.IMPL_MIN_TIMEOUT):
    """
    Calculates timeout to use when calling LN node considering client's
    timeout
    """
    node_timeout = min_time
    client_time = context.time_remaining()
    if client_time and client_time > node_timeout:
        node_timeout = client_time - sett.RESPONSE_RESERVED_TIME
    node_timeout = min(sett.IMPL_MAX_TIMEOUT, node_timeout)
    return node_timeout


def get_thread_timeout(context):
    """ Calculates timeout for future.result() """
    wait_time = sett.THREAD_TIMEOUT
    if context.time_remaining():
        # subtracting time to do the request and answer to the client
        wait_time = context.time_remaining() - sett.RESPONSE_RESERVED_TIME
    if wait_time < 0:
        wait_time = 0
    return wait_time


class FakeContext():  # pylint: disable=too-few-public-methods
    """
    Simulates a grpc server context in order to (re)define abort()

    This allows checking connection to node before a context is available from
    a client request
    """
    @staticmethod
    def abort(scode, msg):
        """ Raises a runtime error """
        assert scode
        raise RuntimeError(msg)

    @staticmethod
    def time_remaining():
        """ Acts as no timeout has been set by client """
        return None


class RPCSession():  # pylint: disable=too-few-public-methods
    """ Creates and mantains an RPC session open """

    def __init__(self, auth=None, headers=None, jsonrpc_ver='2.0'):
        self._session = ReqSession()
        self._auth = auth
        self._headers = headers
        self._jsonrpc_ver = jsonrpc_ver
        self._id_count = 0

    def call(self, context, data=None, url=None, timeout=None):
        """
        Makes an RPC call using the opened session.

        It returns the response message and a boolean to signal if it
        contains an error.
        """
        self._id_count += 1
        if url is None:
            url = sett.RPC_URL
        if timeout is None:
            timeout = get_node_timeout(context)
        tries = sett.RPC_TRIES
        while True:
            try:
                response = self._session.post(
                    url, data=data, auth=self._auth, headers=self._headers,
                    timeout=(sett.RPC_CONN_TIMEOUT, timeout))
                break
            except ReqConnectionErr:
                tries -= 1
                if tries == 0:
                    Err().node_error(
                        context, 'RPC call failed: max retries reached')
                LOGGER.debug(
                    'Connection failed, sleeping for %.1f secs (%d tries '
                    'left)', sett.RPC_SLEEP, tries)
                sleep(sett.RPC_SLEEP)
            except Timeout:
                Err().node_error(context, 'RPC call timed out')
        if response.status_code not in (200, 500):
            err_msg = 'RPC call failed: {} {}'.format(
                response.status_code, response.reason)
            Err().node_error(context, err_msg)
        json_response = response.json()
        if 'error' in json_response and json_response['error'] is not None:
            err = json_response['error']
            if 'message' in err:
                err = json_response['error']['message']
            LOGGER.debug('RPC err: %s', err)
            return err, True
        if 'result' in json_response:
            LOGGER.debug('RPC res: %s', json_response['result'])
            return json_response['result'], False
        LOGGER.debug('RPC res: %s', json_response)
        return json_response, response.status_code == 500
