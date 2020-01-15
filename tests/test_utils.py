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

from argparse import Namespace
from codecs import encode
from decimal import InvalidOperation
from importlib import import_module
from os import urandom
from subprocess import PIPE, TimeoutExpired

from nacl.exceptions import CryptoError
from unittest import TestCase, skip
from unittest.mock import call, Mock, mock_open, patch
from requests.exceptions import ConnectionError as ReqConnectionErr, Timeout

from tests import fixtures_utils as fix

from . import proj_root

Enf = getattr(import_module(proj_root + '.utils'), 'Enforcer')
ImplementationSecret = getattr(
    import_module(proj_root + '.db'), 'ImplementationSecret')
LND_PAYREQ = getattr(import_module(proj_root + '.light_lnd'), 'LND_PAYREQ')
pb = import_module(proj_root + '.lighter_pb2')
settings = import_module(proj_root + '.settings')
MOD = import_module(proj_root + '.utils')
CTX = 'context'


class UtilsTests(TestCase):
    """ Tests for the utils module """

    @patch(MOD.__name__ + '.migrate', autospec=True)
    @patch(MOD.__name__ + '.get_start_options', autospec=True)
    @patch(MOD.__name__ + '.get_config_parser', autospec=True)
    @patch(MOD.__name__ + '.init_tree', autospec=True)
    @patch(MOD.__name__ + '.parse_args', autospec=True)
    @patch(MOD.__name__ + '.update_logger', autospec=True)
    def test_init_common(self, mocked_update_log, mocked_parse_args,
                         mocked_init_tree, mocked_get_config,
                         mocked_get_start_opt, mocked_migrate):
        # core=True
        msg = 'help message'
        MOD.init_common(msg)
        mocked_parse_args.assert_called_once_with(msg, False)
        calls = [call(), call(mocked_get_config.return_value),
                 call(mocked_get_config.return_value)]
        mocked_update_log.assert_has_calls(calls)
        self.assertEqual(mocked_update_log.call_count, 3)
        # core=False, write_perms=True
        reset_mocks(vars())
        MOD.init_common(msg, core=False, write_perms=True)
        mocked_parse_args.assert_called_once_with(msg, True)
        self.assertEqual(mocked_update_log.call_count, 2)
        assert not mocked_init_tree.called
        assert not mocked_migrate.called

    @patch(MOD.__name__ + '.dictConfig')
    @patch(MOD.__name__ + '.path', autospec=True)
    @patch(MOD.__name__ + '.get_path', autospec=True)
    def test_update_logger(self, mocked_get_path, mocked_path,
                           mocked_dictConfig):
        # Correct case: config provided
        logs_dir = '/srv/app/logs'
        lvl = 'INFO'
        config = Mock()
        config.get.side_effect = [lvl, logs_dir]
        log_path = logs_dir + '/lighter.log'
        mocked_get_path.return_value = logs_dir
        mocked_path.join.return_value = log_path
        MOD.update_logger(config)
        mocked_get_path.assert_called_once_with(logs_dir)
        self.assertEqual(settings.LOGGING['handlers']['console']['level'], lvl)
        mocked_dictConfig.assert_called_once_with(settings.LOGGING)
        self.assertEqual(settings.LOGS_DIR, logs_dir)
        self.assertIn('file', settings.LOGGING['loggers']['']['handlers'])
        self.assertEqual(settings.LOGGING['handlers']['file']['filename'],
                         log_path)
        # Correct case: no config provided
        reset_mocks(vars())
        MOD.update_logger()
        mocked_dictConfig.assert_called_once_with(settings.LOGGING)
        assert not mocked_get_path.called
        # Error case
        reset_mocks(vars())
        mocked_dictConfig.side_effect = ValueError
        with self.assertRaises(RuntimeError):
            MOD.update_logger()

    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    def test_log_intro(self, mocked_logger):
        MOD.log_intro()
        self.assertEqual(mocked_logger.info.call_count, 11)

    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    def test_log_outro(self, mocked_logger):
        MOD.log_outro()
        self.assertEqual(mocked_logger.info.call_count, 2)

    @patch(MOD.__name__ + '.access', autospec=True)
    @patch(MOD.__name__ + '.path', autospec=True)
    @patch(MOD.__name__ + '.ArgumentParser', autospec=True)
    def test_parse_args(self, mocked_argparse, mocked_path, mocked_access):
        msg = 'help message'
        # without args
        MOD.parse_args(msg, False)
        mocked_argparse.assert_called_once_with(description=msg)
        mocked_argparse.return_value.add_argument.assert_called_once_with(
            '--lighterdir', metavar='PATH',
            help="Path containing config file and other data")
        mocked_argparse.return_value.parse_args.assert_called_once_with()
        # with args
        reset_mocks(vars())
        mocked_path.isdir.return_value = True
        mocked_access.return_value = True
        ldir = '/srv/lighter'
        mocked_argparse.return_value.parse_args.return_value = Namespace(
            lighterdir=ldir)
        MOD.parse_args(msg, True)
        self.assertEqual(settings.L_DATA, ldir)
        mocked_path.isdir.assert_called_once_with(ldir)
        mocked_access.assert_called_once_with(ldir, MOD.W_OK)
        # with no access to path
        reset_mocks(vars())
        mocked_access.return_value = False
        with self.assertRaises(RuntimeError):
            MOD.parse_args(msg, False)
        # with path that is not a directory
        reset_mocks(vars())
        mocked_path.isdir.return_value = False
        with self.assertRaises(RuntimeError):
            MOD.parse_args(msg, False)
        # with empty path
        reset_mocks(vars())
        ldir = ''
        mocked_argparse.return_value.parse_args.return_value = Namespace(
            lighterdir=ldir)
        with self.assertRaises(RuntimeError):
            MOD.parse_args(msg, False)

    @patch(MOD.__name__ + '.sleep', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.getattr')
    @patch(MOD.__name__ + '.import_module')
    def test_check_connection(self, mocked_import, mocked_getattr,
                              mocked_logger, mocked_sleep):
        # Correct case (with version)
        settings.IMPLEMENTATION = 'imp'
        mocked_import.return_value = 'mod'
        func = Mock()
        func.return_value = pb.GetInfoResponse(
            identity_pubkey='777', version='v1')
        mocked_getattr.return_value = func
        MOD.check_connection()
        mocked_import.assert_called_once_with('..light_imp', MOD.__name__)
        # Correct case (no version)
        reset_mocks(vars())
        settings.IMPLEMENTATION = 'imp'
        mocked_import.return_value = 'mod'
        info = pb.GetInfoResponse(identity_pubkey='777')
        func = Mock()
        func.return_value = info
        mocked_getattr.return_value = func
        MOD.check_connection()
        # No response case
        reset_mocks(vars())
        mocked_getattr.side_effect = [RuntimeError(), func]
        MOD.check_connection()
        assert mocked_logger.error.called

    @patch(MOD.__name__ + '.set_defaults', autospec=True)
    @patch(MOD.__name__ + '.ConfigParser', autospec=True)
    @patch(MOD.__name__ + '.copyfile', autospec=True)
    @patch(MOD.__name__ + '.get_data_files_path', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.path', autospec=True)
    def test_get_config_parser(self, mocked_path, mocked_logger,
                               mocked_get_df, mocked_copy, mocked_config,
                               mocked_set_def):
        l_values = ['INSECURE_CONNECTION', 'PORT', 'SERVER_KEY', 'SERVER_CRT',
                    'LOGS_DIR', 'LOGS_LEVEL', 'DB_DIR', 'MACAROONS_DIR',
                    'DISABLE_MACAROONS']
        # config exists
        mocked_path.exists.return_value = True
        res = MOD.get_config_parser()
        assert not mocked_logger.error.called
        mocked_config.assert_called_once_with()
        mocked_config.return_value.read.assert_called_once_with(
            settings.L_CONFIG)
        mocked_set_def.assert_called_once_with(
            mocked_config.return_value, l_values)
        self.assertEqual(res, mocked_config.return_value)
        # config not exists
        reset_mocks(vars())
        mocked_path.exists.return_value = False
        res = MOD.get_config_parser()
        assert mocked_logger.error.called
        mocked_get_df.assert_called_once_with(
            'share/doc/' + settings.PKG_NAME, 'examples/config.sample')
        mocked_copy.assert_called_once_with(
            mocked_get_df.return_value, settings.L_CONFIG)
        self.assertEqual(res, mocked_config.return_value)

    @patch(MOD.__name__ + '.glob', autospec=True)
    @patch(MOD.__name__ + '.path', autospec=True)
    def test_get_data_files_path(self, mocked_path, mocked_glob):
        inst_dir = 'share/doc/pkg'
        rel_path = 'examples/config.sample'
        # normal install
        mocked_path.exists.return_value = True
        res = MOD.get_data_files_path(inst_dir, rel_path)
        self.assertEqual(res, mocked_path.join.return_value)
        # editable install
        reset_mocks(vars())
        mocked_path.exists.side_effect = [False, True]
        egg_link = ['/srv/app/.virtualenvs/lighter-env/lib/python3.5/'
                   'site-packages/{}.egg-link'.format(settings.PIP_NAME)]
        mocked_glob.return_value = egg_link
        mopen = mock_open(read_data=egg_link[0])
        realpath = '/srv/app/lighter'
        mopen.return_value.readline.return_value = realpath
        with patch(MOD.__name__ + '.open', mopen):
            res = MOD.get_data_files_path(inst_dir, rel_path)
            mopen.return_value.readline.assert_called_once_with()
            self.assertEqual(res, mocked_path.join.return_value)
        # file not found case
        reset_mocks(vars())
        mocked_path.exists.side_effect = None
        mocked_path.exists.return_value = False
        mocked_glob.return_value = []
        with self.assertRaises(RuntimeError):
            res = MOD.get_data_files_path(inst_dir, rel_path)

    def test_set_defaults(self):
        config = Mock()
        values = ['INSECURE_CONNECTION', 'PORT']
        MOD.set_defaults(config, values)
        def_dict = {'DEFAULT':
            {'INSECURE_CONNECTION': settings.INSECURE_CONNECTION,
            'PORT': settings.PORT}}
        config.read_dict.assert_called_once_with(def_dict)

    @patch(MOD.__name__ + '.getattr')
    @patch(MOD.__name__ + '.import_module', autospec=True)
    def test_get_start_options(self, mocked_import, mocked_getattr):
        settings.INSECURE_CONNECTION = 0
        # Secure connection case with macaroons enabled
        impl = 'funny'
        ins_conn = dis_mac = 0
        port = 1708
        server_crt = 'crt'
        server_key = 'key'
        db_dir = 'db_dir'
        mac_dir = 'mac_dir'
        config = Mock()
        config.get.side_effect = [impl, ins_conn, dis_mac, port, server_key,
                                  server_crt, mac_dir, db_dir]
        MOD.get_start_options(config)
        self.assertEqual(settings.INSECURE_CONNECTION, False)
        mocked_import.assert_called_once_with('..light_' + impl, MOD.__name__)
        mocked_getattr.assert_called_with(
            mocked_import.return_value, 'get_settings')
        mocked_getattr.return_value.assert_called_once_with(config, impl)
        # Insecure connection case, with only default config
        reset_mocks(vars())
        settings.IMPLEMENTATION_SECRETS = False
        ins_conn = 1
        config = Mock()
        config.get.side_effect = [impl, ins_conn, dis_mac, port, db_dir]
        MOD.get_start_options(config)
        self.assertEqual(settings.INSECURE_CONNECTION, True)
        self.assertEqual(settings.DISABLE_MACAROONS, True)
        # No secrets case (with warning)
        reset_mocks(vars())
        dis_mac = 1
        config.get.side_effect = [impl, ins_conn, dis_mac, port, db_dir]
        MOD.get_start_options(config)

    @patch(MOD.__name__ + '.get_secret_from_db', autospec=True)
    def test_detect_impl_secret(self, mocked_db_sec):
        sec = 'secret'
        ses = 'session'
        # c-lightning case
        settings.IMPLEMENTATION = 'clightning'
        res = MOD.detect_impl_secret(ses)
        self.assertEqual(res, False)
        # lnd with no secrets case
        settings.IMPLEMENTATION = 'lnd'
        mocked_db_sec.return_value = ImplementationSecret(
            implementation='lnd', active=0)
        res = MOD.detect_impl_secret(ses)
        self.assertEqual(res, False)
        # lnd with secrets case
        mocked_db_sec.return_value = ImplementationSecret(
            implementation='lnd', active=1, secret=sec)
        res = MOD.detect_impl_secret(ses)
        self.assertEqual(res, True)
        # lnd with active but no secret
        mocked_db_sec.return_value = ImplementationSecret(
            implementation='lnd', active=1)
        with self.assertRaises(RuntimeError):
            res = MOD.detect_impl_secret(ses)
        # eclair with secrets case
        settings.IMPLEMENTATION = 'eclair'
        mocked_db_sec.return_value = ImplementationSecret(
            implementation='eclair', active=1, secret=sec)
        res = MOD.detect_impl_secret(ses)
        self.assertEqual(res, True)
        # eclair with no secrets case
        mocked_db_sec.return_value = None
        with self.assertRaises(RuntimeError):
            res = MOD.detect_impl_secret(ses)

    @patch(MOD.__name__ + '.path', autospec=True)
    @patch(MOD.__name__ + '._try_mkdir', autospec=True)
    def test_init_tree(self, mocked_try_mkdir, mocked_path):
        MOD.init_tree()
        calls = [call(settings.L_DATA, 'certs'),
                 call(settings.L_DATA, 'db'),
                 call(settings.L_DATA, 'logs'),
                 call(settings.L_DATA, 'macaroons')]
        mocked_path.join.assert_has_calls(calls)
        calls = [call(settings.L_DATA), call(mocked_path.join.return_value),
                 call(mocked_path.join.return_value),
                 call(mocked_path.join.return_value),
                 call(mocked_path.join.return_value)]
        mocked_try_mkdir.assert_has_calls(calls)

    @patch(MOD.__name__ + '.mkdir', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.path', autospec=True)
    def test_try_mkdir(self, mocked_path, mocked_logger, mocked_mkdir):
        dir_path = '/srv/app/certs'
        # dir doesn't exist
        mocked_path.exists.return_value = False
        MOD._try_mkdir(dir_path)
        assert mocked_logger.info.called
        mocked_mkdir.assert_called_once_with(dir_path)
        # dir exists
        reset_mocks(vars())
        mocked_path.exists.return_value = True
        MOD._try_mkdir(dir_path)
        assert not mocked_logger.info.called
        assert not mocked_mkdir.called

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
        rpc_ses = MOD.RPCSession(auth=auth)
        mocked_post = rpc_ses._session.post
        # With url, timeout, auth and data case
        mocked_post.return_value.status_code = 200
        json_response = {'result': 'lighter'}
        mocked_post.return_value.json.return_value = json_response
        data = {}
        res, is_err = rpc_ses.call(ctx, data, url, timeout)
        mocked_post.assert_called_once_with(
            url, data=data, auth=auth,
            timeout=(settings.RPC_CONN_TIMEOUT, timeout))
        self.assertEqual(res, 'lighter')
        self.assertEqual(is_err, False)
        # Without url, timeout, auth and data case
        reset_mocks(vars())
        rpc_ses = MOD.RPCSession()
        mocked_post = rpc_ses._session.post
        rpc_ses.call(ctx)
        mocked_post.assert_called_once_with(
            settings.RPC_URL, data=None, auth=None,
            timeout=(settings.RPC_CONN_TIMEOUT, mocked_time.return_value))
        # Connection error case
        reset_mocks(vars())
        mocked_post.side_effect = ReqConnectionErr()
        with self.assertRaises(Exception):
            rpc_ses.call(ctx)
        self.assertEqual(mocked_sleep.call_count, settings.RPC_TRIES - 1)
        self.assertEqual(mocked_log.info.call_count, settings.RPC_TRIES - 1)
        mocked_sleep.assert_called_with(settings.RPC_SLEEP)
        mocked_err().node_error.assert_called_once_with(
            ctx, 'RPC call failed: max retries reached')
        # Timeout error case
        reset_mocks(vars())
        mocked_post.side_effect = Timeout()
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
        # Status code not 200 nor 500 error case
        reset_mocks(vars())
        mocked_post.return_value.status_code = 666
        with self.assertRaises(Exception):
            rpc_ses.call(ctx)
        err_msg = 'RPC call failed: {} {}'.format(
            mocked_post.return_value.status_code,
            mocked_post.return_value.reason)
        mocked_err().node_error.assert_called_once_with(ctx, err_msg)

    @patch(MOD.__name__ + '.Err')
    def test_conversion(self, mocked_err):
        mocked_err().value_error.side_effect = Exception()
        # Correct case: bits to msats
        res = MOD.convert(CTX, Enf.MSATS, 777, enforce=Enf.LN_TX)
        self.assertEqual(res, 77700000)
        # Correct case: msats to bits
        res = MOD.convert(CTX, Enf.MSATS, 77700000)
        self.assertEqual(res, 777)
        # Correct case: bits to btc
        res = MOD.convert(
            CTX, Enf.BTC, 777000, enforce=Enf.OC_TX,
            max_precision=Enf.SATS)
        self.assertEqual(res, 0.777000)
        # Correct case: btc to bits
        res = MOD.convert(CTX, Enf.BTC, 0.777, max_precision=Enf.BITS)
        self.assertEqual(res, 777000)
        # Error case: bits to sats, losing precision
        with self.assertRaises(Exception):
            res = MOD.convert(CTX, Enf.SATS, 0.009, enforce=LND_PAYREQ,
                              max_precision=Enf.SATS)

    @patch(MOD.__name__ + '.Enforcer.check_value')
    @patch(MOD.__name__ + '._convert_value', autospec=True)
    def test_convert(self, mocked_conv_val, mocked_check_val):
        # Correct case: bits to msats
        mocked_conv_val.return_value = 77700000
        res = MOD.convert(CTX, Enf.MSATS, 777, enforce=Enf.LN_TX)
        calls = [
            call(CTX, Enf.BITS, Enf.MSATS, 777, Enf.MSATS),
            call(CTX, Enf.BITS, Enf.MSATS, 777, Enf.MSATS)]
        mocked_conv_val.assert_has_calls(calls)
        self.assertEqual(res, 77700000)
        # Correct case: msats to bits
        reset_mocks(vars())
        mocked_conv_val.return_value = 777
        res = MOD.convert(CTX, Enf.MSATS, 777000000)
        mocked_conv_val.assert_called_once_with(CTX, Enf.MSATS, Enf.BITS,
                                                777000000, Enf.MSATS)
        assert not mocked_check_val.called
        self.assertEqual(res, 777)
        # Correct case: bits to btc
        reset_mocks(vars())
        mocked_conv_val.side_effect = [77700000, 0.777]
        res = MOD.convert(CTX, Enf.BTC, 777000, enforce=Enf.OC_TX)
        calls = [
            call(CTX, Enf.BITS, Enf.OC_TX['unit'], 777000, Enf.SATS),
            call(CTX, Enf.BITS, Enf.BTC, 777000, Enf.SATS)]
        mocked_conv_val.assert_has_calls(calls)
        self.assertEqual(res, 0.777000)

    @patch(MOD.__name__ + '.Err')
    def test_convert_value(self, mocked_err):
        mocked_err().value_error.side_effect = Exception()
        # Correct case: Decimal output
        res = MOD._convert_value(CTX, Enf.BITS, Enf.SATS, 777, Enf.MSATS)
        self.assertEqual(res, 77700)
        assert not mocked_err().value_error.called
        # Correct case: int output
        reset_mocks(vars())
        res = MOD._convert_value(
            CTX, Enf.BITS, Enf.SATS, 777, max_precision=Enf.SATS)
        self.assertEqual(type(res), int)
        # Error case: string input
        reset_mocks(vars())
        with self.assertRaises(Exception):
            res = MOD._convert_value(CTX, Enf.BITS, Enf.SATS, 'err',
                                     Enf.MSATS)
        mocked_err().value_error.assert_called_once_with(CTX)
        # Error case: too big number input
        reset_mocks(vars())
        with self.assertRaises(Exception):
            res = MOD._convert_value(CTX, Enf.BITS, Enf.SATS,
                                     777777777777777777777777777, Enf.SATS)
        mocked_err().value_error.assert_called_once_with(CTX)
        # Error case: number gets truncated
        reset_mocks(vars())
        with self.assertRaises(Exception):
            res = MOD._convert_value(CTX, Enf.BITS, Enf.SATS, 0.009, Enf.SATS)
        mocked_err().value_error.assert_called_once_with(CTX)

    @patch(MOD.__name__ + '.Err')
    def test_check_value(self, mocked_err):
        mocked_err().value_too_low.side_effect = Exception()
        mocked_err().value_too_high.side_effect = Exception()
        # Correct case, default type
        Enf.check_value(CTX, 7)
        # Correct case, specific type
        Enf.check_value(CTX, 7, enforce=Enf.LN_TX)
        # Error value_too_low case
        reset_mocks(vars())
        with self.assertRaises(Exception):
            Enf.check_value(CTX, 0.001, enforce=Enf.LN_TX)
        mocked_err().value_too_low.assert_called_once_with(CTX)
        assert not mocked_err().value_too_high.called
        # Error value_too_high case
        reset_mocks(vars())
        with self.assertRaises(Exception):
            Enf.check_value(CTX, 2**32 + 1, enforce=Enf.LN_TX)
        assert not mocked_err().value_too_low.called
        mocked_err().value_too_high.assert_called_once_with(CTX)
        # Check disabled case
        reset_mocks(vars())
        settings.ENFORCE = False
        Enf.check_value(CTX, 7)
        assert not mocked_err().value_too_low.called
        assert not mocked_err().value_too_high.called

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

    def test_handle_sigterm(self):
        with self.assertRaises(MOD.InterruptException):
            MOD.handle_sigterm(15, None)

    def test_handle_keyboardinterrupt(self):
        # KeyboardInterrupt case
        func = Mock()
        func.side_effect = KeyboardInterrupt()
        wrapped = MOD.handle_keyboardinterrupt(func)
        with self.assertRaises(MOD.InterruptException):
            wrapped()
        self.assertEqual(func.call_count, 1)

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

    @patch(MOD.__name__ + '._has_numbers', autospec=True)
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

    def test_get_address_type(self):
        # Bech32 address case
        addr = 'bcrt1q9s8pfy8ktptz2'
        res = MOD.get_address_type(addr)
        self.assertEqual(res, pb.P2WKH)
        addr = 'tb1qw508d6qejxtdg4y'
        res = MOD.get_address_type(addr)
        self.assertEqual(res, pb.P2WKH)
        # Legacy address case
        addr = 'm2gfudf487cn5acf284'
        res = MOD.get_address_type(addr)
        self.assertEqual(res, pb.NP2WKH)

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

    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.Crypter')
    @patch(MOD.__name__ + '.ScryptParams', autospec=True)
    @patch(MOD.__name__ + '.get_token_from_db', autospec=True)
    def test_check_password(self, mocked_db_tok, mocked_params, mocked_crypter,
                            mocked_err):
        pwd = 'password'
        ses = 'session'
        # Correct
        mocked_db_tok.return_value = ['token', 'params']
        mocked_crypter.decrypt.return_value = settings.ACCESS_TOKEN
        MOD.check_password(CTX, ses, pwd)
        mocked_err().wrong_password.assert_not_called()
        # Wrong
        wrong_token = 'wrong_token'
        mocked_crypter.decrypt.return_value = wrong_token
        MOD.check_password(CTX, ses, pwd)
        mocked_err().wrong_password.assert_called_once_with(CTX)

    @patch(MOD.__name__ + '.Crypter')
    @patch(MOD.__name__ + '.ScryptParams', autospec=True)
    @patch(MOD.__name__ + '.get_secret_from_db', autospec=True)
    def test_get_secret(self, mocked_db_sec, mocked_params, mocked_crypter):
        ses = 'session'
        pwd = 'password'
        impl = 'implementation'
        sec_type = 'macaroon'
        # active_only=False (default) with secret case
        res = MOD.get_secret(CTX, ses, pwd, impl, sec_type)
        self.assertEqual(res, mocked_crypter.decrypt.return_value)
        # active_only=False (default) with no secret case
        mocked_db_sec.return_value = None
        res = MOD.get_secret(CTX, ses, pwd, impl, sec_type)
        self.assertEqual(res, None)
        # active_only=True and inactive secret case
        mocked_db_sec.return_value = ImplementationSecret(
            implementation=impl, active=0, secret=b'sec')
        res = MOD.get_secret(CTX, ses, pwd, impl, sec_type, active_only=True)
        self.assertEqual(res, None)

    @patch(MOD.__name__ + '.Err')
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
        with patch('nacl.secret.SecretBox') as mocked_box:
            mocked_box.return_value.decrypt.side_effect = CryptoError
            decrypted_data = MOD.Crypter.decrypt(CTX, crypt_data, derived_key)
            mocked_err().wrong_password.assert_called_once_with(CTX)
            mocked_err().reset_mock()
        # Wrong version case
        wrong_data = 'random_wrong_stuff'
        MOD.Crypter.decrypt(CTX, wrong_data, derived_key)
        mocked_err().wrong_password.assert_called_once_with(CTX)


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
