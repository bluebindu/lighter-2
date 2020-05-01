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

""" Tests for utils.network module """

from importlib import import_module
from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

from . import proj_root

CTX = 'context'
pb = import_module(proj_root + '.lighter_pb2')
settings = import_module(proj_root + '.settings')

MOD = import_module(proj_root + '.utils.network')


class UtilsNetworkTests(TestCase):
    """ Tests for utils.network module """

    @patch(MOD.__name__ + '.sleep', autospec=True)
    @patch(MOD.__name__ + '.disable_logger', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.getattr')
    @patch(MOD.__name__ + '.import_module')
    def test_check_connection(self, mocked_import, mocked_getattr,
                              mocked_logger, mocked_dis_log, mocked_sleep):
        lock = MagicMock()
        # Correct case (with version)
        settings.IMPLEMENTATION = 'imp'
        mocked_import.return_value = 'mod'
        func = Mock()
        func.return_value = pb.GetInfoResponse(
            identity_pubkey='777', version='v1')
        mocked_getattr.return_value = func
        MOD.check_connection(lock)
        lock.acquire.assert_called_once_with(blocking=False)
        mocked_import.assert_called_once_with('...light_imp', MOD.__name__)
        mocked_dis_log.assert_called_once_with()
        lock.release.assert_called_once_with()
        # Correct case (no version)
        reset_mocks(vars())
        mocked_import.return_value = 'mod'
        info = pb.GetInfoResponse(identity_pubkey='777')
        func = Mock()
        func.return_value = info
        mocked_getattr.return_value = func
        MOD.check_connection(lock)
        # lock not acquired
        reset_mocks(vars())
        lock.acquire.return_value = False
        MOD.check_connection(lock)
        assert not mocked_import.called
        assert not lock.release.called
        lock.acquire.return_value = True
        # No response case
        reset_mocks(vars())
        mocked_getattr.side_effect = [RuntimeError(), func]
        MOD.check_connection(lock)
        assert mocked_logger.error.called

    @patch(MOD.__name__ + '.Err')
    def test_check_req_params(self, mocked_err):
        # Raising error case
        mocked_err().missing_parameter.side_effect = Exception()
        request = pb.OpenChannelRequest()
        with self.assertRaises(Exception):
            MOD.check_req_params(CTX, request, 'node_uri', 'funding_bits')
        mocked_err().missing_parameter.assert_called_once_with(CTX, 'node_uri')

    def test_get_node_timeout(self):
        # Client without timeout
        ctx = Mock()
        ctx.time_remaining.return_value = None
        res = MOD.get_node_timeout(ctx)
        self.assertEqual(res, settings.IMPL_MIN_TIMEOUT)
        # Client with timeout
        ctx.time_remaining.return_value = 100
        res = MOD.get_node_timeout(ctx)
        self.assertEqual(res, 100 - settings.RESPONSE_RESERVED_TIME)
        # Client with timeout too long
        ctx.time_remaining.return_value = 100000000
        res = MOD.get_node_timeout(ctx)
        self.assertEqual(res, settings.IMPL_MAX_TIMEOUT)
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

    def test_FakeContext(self):
        # abort test
        with self.assertRaises(RuntimeError):
            MOD.FakeContext().abort(7, 'error')
        # time_remaining test
        res = MOD.FakeContext().time_remaining()
        self.assertEqual(res, None)

    @patch(MOD.__name__ + '.sleep', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.get_node_timeout', autospec=True)
    @patch(MOD.__name__ + '.ReqSession', autospec=True)
    def test_RPCSession(self, mocked_ses, mocked_time, mocked_err, mocked_log,
                        mocked_sleep):
        url = 'http://host:port/method'
        timeout = 7
        ctx = Mock()
        auth = Mock()
        mocked_err().node_error.side_effect = Exception()
        headers = {'content-type': 'application/json'}
        rpc_ses = MOD.RPCSession(auth=auth, headers=headers)
        mocked_post = rpc_ses._session.post
        # With url, timeout, auth, headers and data case
        mocked_post.return_value.status_code = 200
        json_response = {'result': 'lighter'}
        mocked_post.return_value.json.return_value = json_response
        data = {}
        res, is_err = rpc_ses.call(ctx, data, url, timeout)
        mocked_post.assert_called_once_with(
            url, data=data, auth=auth, headers=headers,
            timeout=(settings.RPC_CONN_TIMEOUT, timeout))
        self.assertEqual(res, 'lighter')
        self.assertEqual(is_err, False)
        # Without url, timeout, auth and data case
        reset_mocks(vars())
        rpc_ses = MOD.RPCSession()
        mocked_post = rpc_ses._session.post
        rpc_ses.call(ctx)
        mocked_post.assert_called_once_with(
            settings.RPC_URL, data=None, auth=None, headers=None,
            timeout=(settings.RPC_CONN_TIMEOUT, mocked_time.return_value))
        # Connection error case
        reset_mocks(vars())
        mocked_post.side_effect = MOD.ReqConnectionErr()
        with self.assertRaises(Exception):
            rpc_ses.call(ctx)
        self.assertEqual(mocked_sleep.call_count, settings.RPC_TRIES - 1)
        self.assertEqual(mocked_log.debug.call_count, settings.RPC_TRIES - 1)
        mocked_sleep.assert_called_with(settings.RPC_SLEEP)
        mocked_err().node_error.assert_called_once_with(
            ctx, 'RPC call failed: max retries reached')
        # Timeout error case
        reset_mocks(vars())
        mocked_post.side_effect = MOD.Timeout()
        with self.assertRaises(Exception):
            rpc_ses.call(ctx)
        mocked_err().node_error.assert_called_once_with(
            ctx, 'RPC call timed out')
        mocked_post.side_effect = None
        # Error 500 case
        reset_mocks(vars())
        mocked_post.return_value.status_code = 500
        json_response = {'error': {'code': 1, 'message': 'invalid'}}
        mocked_post.return_value.json.return_value = json_response
        res, is_err = rpc_ses.call(ctx)
        self.assertEqual(res, 'invalid')
        self.assertEqual(is_err, True)
        # Error response not respecting jsonrpc protocol
        reset_mocks(vars())
        json_response = {'error': 'invalid'}
        mocked_post.return_value.json.return_value = json_response
        res, is_err = rpc_ses.call(ctx)
        self.assertEqual(res, 'invalid')
        self.assertEqual(is_err, True)
        # String response not respecting jsonrpc protocol
        reset_mocks(vars())
        mocked_post.return_value.status_code = 200
        json_response = 'invalid'
        mocked_post.return_value.json.return_value = json_response
        res, is_err = rpc_ses.call(ctx)
        self.assertEqual(res, 'invalid')
        self.assertEqual(is_err, False)
        # Status code 403 (Forbidden)
        reset_mocks(vars())
        mocked_post.return_value.status_code = 403
        res, is_err = rpc_ses.call(ctx)
        self.assertEqual(res, mocked_post.return_value.reason)
        self.assertEqual(is_err, True)
        # Status code not 200 nor 500 error case
        reset_mocks(vars())
        mocked_post.return_value.status_code = 666
        with self.assertRaises(Exception):
            rpc_ses.call(ctx)
        err_msg = 'RPC call failed: {} {}'.format(
            mocked_post.return_value.status_code,
            mocked_post.return_value.reason)
        mocked_err().node_error.assert_called_once_with(ctx, err_msg)


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
