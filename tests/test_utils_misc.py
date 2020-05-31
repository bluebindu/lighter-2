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

""" Tests for utils.misc module """

from argparse import Namespace
from importlib import import_module
from unittest import TestCase
from unittest.mock import call, Mock, mock_open, patch

from . import proj_root

CTX = 'context'
pb = import_module(proj_root + '.lighter_pb2')
settings = import_module(proj_root + '.settings')

MOD = import_module(proj_root + '.utils.misc')


class UtilsMiscTests(TestCase):
    """ Tests for utils.misc module """

    def test_handle_keyboardinterrupt(self):
        # KeyboardInterrupt case
        func = Mock()
        func.side_effect = KeyboardInterrupt()
        wrapped = MOD.handle_keyboardinterrupt(func)
        with self.assertRaises(MOD.InterruptException):
            wrapped()
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

    @patch(MOD.__name__ + '.disable', autospec=True)
    def test_disable_logger(self, mocked_disable):
        with MOD.disable_logger():
            pass
        calls = [call(MOD.CRITICAL), call(MOD.NOTSET)]
        mocked_disable.assert_has_calls(calls)

    @patch(MOD.__name__ + '.copyfile', autospec=True)
    @patch(MOD.__name__ + '.get_data_files_path', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.die', autospec=True)
    @patch(MOD.__name__ + '.str2bool', autospec=True)
    @patch(MOD.__name__ + '.input')
    def test_copy_config_sample(self, mocked_input, mocked_str2bool,
                                mocked_die, mocked_logger, mocked_get_df,
                                mocked_copy):
        mocked_die.side_effect = Exception()
        # interactive copy - user wants copy
        mocked_str2bool.return_value = True
        with self.assertRaises(Exception):
            MOD.copy_config_sample(True)
        mocked_str2bool.assert_called_once_with(
            mocked_input.return_value, force_true=True)
        assert not mocked_logger.error.called
        mocked_get_df.assert_called_once_with(
            'share/doc/' + settings.PKG_NAME, 'examples/config.sample')
        mocked_copy.assert_called_once_with(
            mocked_get_df.return_value, settings.L_CONFIG)
        assert mocked_die.called
        # interactive copy - user doesn't want copy
        reset_mocks(vars())
        mocked_str2bool.return_value = False
        with self.assertRaises(Exception):
            MOD.copy_config_sample(True)
        assert mocked_die.called
        assert not mocked_get_df.called
        # not interactive copy
        reset_mocks(vars())
        with self.assertRaises(Exception):
            MOD.copy_config_sample(False)
        assert mocked_logger.error.called
        assert not mocked_str2bool.called
        mocked_get_df.assert_called_once_with(
            'share/doc/' + settings.PKG_NAME, 'examples/config.sample')
        mocked_copy.assert_called_once_with(
            mocked_get_df.return_value, settings.L_CONFIG)
        assert mocked_die.called
        # not interactive copy - failure on copy
        reset_mocks(vars())
        mocked_copy.side_effect = OSError
        with self.assertRaises(Exception):
            MOD.copy_config_sample(False)
        assert mocked_logger.error.called
        assert not mocked_str2bool.called
        mocked_get_df.assert_called_once_with(
            'share/doc/' + settings.PKG_NAME, 'examples/config.sample')
        mocked_copy.assert_called_once_with(
            mocked_get_df.return_value, settings.L_CONFIG)
        assert mocked_die.called

    @patch(MOD.__name__ + '.sys', autospec=True)
    def test_die(self, mocked_sys):
        # with message
        msg = 'message'
        MOD.die(msg)
        mocked_sys.stderr.write.assert_called_once_with(msg + '\n')
        mocked_sys.exit.assert_called_once_with(1)
        # without message
        reset_mocks(vars())
        MOD.die()
        assert not mocked_sys.stderr.write.called
        mocked_sys.exit.assert_called_once_with(1)

    @patch(MOD.__name__ + '.set_defaults', autospec=True)
    @patch(MOD.__name__ + '.ConfigParser', autospec=True)
    @patch(MOD.__name__ + '.copy_config_sample', autospec=True)
    @patch(MOD.__name__ + '.path', autospec=True)
    def test_get_config_parser(self, mocked_path, mocked_copy_cfg,
                               mocked_config, mocked_set_def):
        l_values = ['INSECURE_CONNECTION', 'PORT', 'SERVER_KEY', 'SERVER_CRT',
                    'LOGS_DIR', 'LOGS_LEVEL', 'DB_DIR', 'MACAROONS_DIR',
                    'DISABLE_MACAROONS']
        # config exists
        mocked_path.exists.return_value = True
        res = MOD.get_config_parser()
        assert not mocked_copy_cfg.called
        mocked_config.assert_called_once_with()
        mocked_config.return_value.read.assert_called_once_with(
            settings.L_CONFIG)
        mocked_set_def.assert_called_once_with(
            mocked_config.return_value, l_values)
        self.assertEqual(res, mocked_config.return_value)
        # config not exists
        reset_mocks(vars())
        mocked_path.exists.return_value = False
        res = MOD.get_config_parser(interactive=True)
        mocked_copy_cfg.assert_called_once_with(True)
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

    def test_get_path(self):
        # with base_path and relative input
        ipath = 'input/path'
        bpath = '/base/path/'
        res = MOD.get_path(ipath, base_path=bpath)
        self.assertEqual(res, bpath + ipath)
        # with base_path and relative input with ~
        reset_mocks(vars())
        ipath = '~/input/path'
        bpath = '/base/path'
        res = MOD.get_path(ipath, base_path=bpath)
        self.assertEqual(res, MOD.Path(ipath).expanduser().as_posix())
        # without base_path
        reset_mocks(vars())
        ipath = 'input/path'
        res = MOD.get_path(ipath)
        self.assertEqual(res, MOD.path.join(settings.L_DATA, ipath))

    @patch(MOD.__name__ + '.die', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    def test_handle_importerrror(self, mocked_logger, mocked_die):
        err = ImportError('import error')
        MOD.handle_importerror(err)
        assert mocked_logger.debug.called
        assert mocked_logger.error.called
        mocked_die.assert_called_once_with()

    def test_handle_sigterm(self):
        with self.assertRaises(MOD.InterruptException):
            MOD.handle_sigterm(15, None)

    @patch(MOD.__name__ + '.migrate', autospec=True)
    @patch(MOD.__name__ + '._get_start_options', autospec=True)
    @patch(MOD.__name__ + '.get_config_parser', autospec=True)
    @patch(MOD.__name__ + '._init_tree', autospec=True)
    @patch(MOD.__name__ + '.access', autospec=True)
    @patch(MOD.__name__ + '._parse_args', autospec=True)
    @patch(MOD.__name__ + '._update_logger', autospec=True)
    def test_init_common(self, mocked_update_log, mocked_parse_args,
                         mocked_acc, mocked_init_tree, mocked_get_config,
                         mocked_get_start_opt, mocked_migrate):
        # core=True
        msg = 'help message'
        MOD.init_common(msg)
        mocked_parse_args.assert_called_once_with(msg, False)
        calls = [call(), call(mocked_get_config.return_value),
                 call(mocked_get_config.return_value)]
        mocked_update_log.assert_has_calls(calls)
        self.assertEqual(mocked_update_log.call_count, 3)
        mocked_init_tree.assert_called_once_with()
        mocked_get_start_opt.assert_called_once_with(
            mocked_get_config.return_value, False)
        # core=False, write_perms=True, runtime=True with access
        reset_mocks(vars())
        mocked_acc.return_value = True
        MOD.init_common(msg, core=False, write_perms=True, runtime=True)
        mocked_parse_args.assert_called_once_with(msg, True)
        self.assertEqual(mocked_update_log.call_count, 2)
        mocked_init_tree.assert_called_once_with()
        mocked_get_start_opt.assert_called_once_with(
            mocked_get_config.return_value, True)
        assert not mocked_migrate.called
        # core=False, write_perms=True, without access
        reset_mocks(vars())
        mocked_acc.return_value = False
        with self.assertRaises(RuntimeError):
            MOD.init_common(msg, core=False, write_perms=True)
        mocked_parse_args.assert_called_once_with(msg, True)
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
        MOD._update_logger(config)
        mocked_get_path.assert_called_once_with(logs_dir)
        self.assertEqual(settings.LOGGING['handlers']['console']['level'], lvl)
        mocked_dictConfig.assert_called_once_with(settings.LOGGING)
        self.assertEqual(settings.LOGS_DIR, logs_dir)
        self.assertIn('file', settings.LOGGING['loggers']['']['handlers'])
        self.assertEqual(settings.LOGGING['handlers']['file']['filename'],
                         log_path)
        # Correct case: no config provided
        reset_mocks(vars())
        MOD._update_logger()
        mocked_dictConfig.assert_called_once_with(settings.LOGGING)
        assert not mocked_get_path.called
        # Error case
        reset_mocks(vars())
        mocked_dictConfig.side_effect = ValueError
        with self.assertRaises(RuntimeError):
            MOD._update_logger()

    @patch(MOD.__name__ + '.access', autospec=True)
    @patch(MOD.__name__ + '.path', autospec=True)
    @patch(MOD.__name__ + '.ArgumentParser', autospec=True)
    def test_parse_args(self, mocked_argparse, mocked_path, mocked_access):
        msg = 'help message'
        # without args
        MOD._parse_args(msg, False)
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
        MOD._parse_args(msg, True)
        self.assertEqual(settings.L_DATA, ldir)
        mocked_path.isdir.assert_called_once_with(ldir)
        mocked_access.assert_called_once_with(ldir, MOD.W_OK)
        # with no access to path
        reset_mocks(vars())
        mocked_access.return_value = False
        with self.assertRaises(RuntimeError):
            MOD._parse_args(msg, False)
        # with path that is not a directory
        reset_mocks(vars())
        mocked_path.isdir.return_value = False
        with self.assertRaises(RuntimeError):
            MOD._parse_args(msg, False)
        # with empty path
        reset_mocks(vars())
        ldir = ''
        mocked_argparse.return_value.parse_args.return_value = Namespace(
            lighterdir=ldir)
        with self.assertRaises(RuntimeError):
            MOD._parse_args(msg, False)

    @patch(MOD.__name__ + '.path', autospec=True)
    @patch(MOD.__name__ + '._try_mkdir', autospec=True)
    def test_init_tree(self, mocked_try_mkdir, mocked_path):
        MOD._init_tree()
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

    @patch(MOD.__name__ + '.getattr')
    @patch(MOD.__name__ + '.import_module', autospec=True)
    @patch(MOD.__name__ + '.get_path', autospec=True)
    @patch(MOD.__name__ + '.str2bool', autospec=True)
    def test_get_start_options(self, mocked_str2bool, mocked_get_path,
                               mocked_import, mocked_getattr):
        # Secure connection case with macaroons enabled
        impl = 'funny'
        ins_conn = dis_mac = 0
        port = 1708
        server_crt = 'crt'
        server_key = 'key'
        db_dir = 'db_dir'
        mac_dir = 'mac_dir'
        mocked_str2bool.return_value = False
        config = Mock()
        config.get.side_effect = [impl, ins_conn, dis_mac, port, server_key,
                                  server_crt, mac_dir, db_dir]
        mocked_get_path.side_effect = [server_key, server_crt, mac_dir, db_dir]
        MOD._get_start_options(config, True)
        self.assertEqual(settings.INSECURE_CONNECTION, False)
        mocked_import.assert_called_once_with('...light_' + impl, MOD.__name__)
        mocked_getattr.assert_called_with(
            mocked_import.return_value, 'get_settings')
        mocked_getattr.return_value.assert_called_once_with(config, impl)
        # Insecure connection case, with only default config
        reset_mocks(vars())
        settings.IMPLEMENTATION_SECRETS = False
        ins_conn = 1
        config.get.side_effect = [impl, ins_conn, dis_mac, port, server_key,
                                  server_crt, mac_dir, db_dir]
        mocked_get_path.side_effect = [server_key, server_crt, mac_dir, db_dir]
        mocked_str2bool.return_value = True
        MOD._get_start_options(config, False)
        assert not mocked_getattr.called
        self.assertEqual(settings.INSECURE_CONNECTION, True)
        self.assertEqual(settings.DISABLE_MACAROONS, True)
        # No secrets case (with warning)
        reset_mocks(vars())
        dis_mac = 1
        config.get.side_effect = [impl, ins_conn, dis_mac, port, server_key,
                                  server_crt, mac_dir, db_dir]
        mocked_get_path.side_effect = [server_key, server_crt, mac_dir, db_dir]
        MOD._get_start_options(config, True)

    def test_set_defaults(self):
        config = Mock()
        values = ['INSECURE_CONNECTION', 'PORT']
        MOD.set_defaults(config, values)
        def_dict = {'DEFAULT':
            {'INSECURE_CONNECTION': settings.INSECURE_CONNECTION,
             'PORT': settings.PORT}}
        config.read_dict.assert_called_once_with(def_dict)

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
        # Integer case
        res = MOD.str2bool(1)
        self.assertEqual(res, True)
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


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
