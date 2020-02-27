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

""" Tests for utils.db module """

from importlib import import_module
from unittest import TestCase
from unittest.mock import call, MagicMock, Mock, patch

from . import proj_root

CTX = 'context'
ImplementationSecret = getattr(
    import_module(proj_root + '.db'), 'ImplementationSecret')
SES = Mock()
settings = import_module(proj_root + '.settings')

MOD = import_module(proj_root + '.utils.db')


class UtilsDbTests(TestCase):
    """ Tests for utils.db module """

    @patch(MOD.__name__ + '.Err')
    @patch(MOD.__name__ + '.Session', autospec=False)
    def test_session_scope(self, mocked_ses, mocked_err):
        # correct case
        with MOD.session_scope(CTX) as ses:
            self.assertEqual(ses, mocked_ses.return_value)
        mocked_ses.return_value.commit.assert_called_once_with()
        mocked_ses.return_value.close.assert_called_once_with()
        # db error case
        reset_mocks(vars())
        mocked_ses.return_value.commit.side_effect = MOD.SQLAlchemyError()
        mocked_err().db_error.side_effect = Exception()
        with self.assertRaises(Exception):
            with MOD.session_scope(CTX) as ses:
                self.assertEqual(ses, mocked_ses.return_value)
        mocked_ses.return_value.rollback.assert_called_once_with()
        mocked_ses.return_value.close.assert_called_once_with()
        # general exception case
        reset_mocks(vars())
        mocked_ses.return_value.commit.side_effect = Exception()
        mocked_err().db_error.side_effect = Exception()
        with self.assertRaises(Exception):
            with MOD.session_scope(CTX) as ses:
                self.assertEqual(ses, mocked_ses.return_value)
        mocked_ses.return_value.rollback.assert_called_once_with()
        mocked_ses.return_value.close.assert_called_once_with()

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

    @patch(MOD.__name__ + '.stamp', autospec=True)
    @patch(MOD.__name__ + '.get_alembic_cfg', autospec=True)
    @patch(MOD.__name__ + '.Base', autospec=False)
    @patch(MOD.__name__ + '.sessionmaker', autospec=True)
    @patch(MOD.__name__ + '.create_engine', autospec=True)
    @patch(MOD.__name__ + '._get_db_url', autospec=True)
    def test_init_db(self, mocked_url, mocked_engine, mocked_ses_mak,
                     mocked_base, mocked_a_cfg, mocked_stamp):
        # new_db=False (default case)
        new = False
        MOD.init_db()
        mocked_url.assert_called_once_with(new)
        mocked_engine.assert_called_once_with(mocked_url.return_value)
        mocked_ses_mak.assert_called_once_with(
            bind=mocked_engine.return_value, autoflush=False, autocommit=False)
        assert not mocked_base.metadata.create_all.called
        # new_db=True
        reset_mocks(vars())
        new = True
        MOD.init_db(new_db=new)
        mocked_url.assert_called_once_with(new)
        mocked_engine.assert_called_once_with(mocked_url.return_value)
        mocked_ses_mak.assert_called_once_with(
            bind=mocked_engine.return_value, autoflush=False, autocommit=False)
        mocked_base.metadata.create_all.assert_called_once_with(
            mocked_engine.return_value)
        mocked_a_cfg.assert_called_once_with(new)
        mocked_stamp.assert_called_once_with(mocked_a_cfg.return_value, 'head')

    @patch(MOD.__name__ + '._get_db_url', autospec=True)
    @patch(MOD.__name__ + '.Config', autospec=True)
    def test_get_alembic_cfg(self, mocked_config, mocked_url):
        # new_db=False
        new = False
        MOD.get_alembic_cfg(new)
        mocked_config.assert_called_once_with(settings.ALEMBIC_CFG)
        mocked_url.assert_called_once_with(new)
        calls = [call('sqlalchemy.url', mocked_url.return_value),
                 call('script_location', settings.PKG_NAME + ':migrations')]
        mocked_config.return_value.set_main_option.assert_has_calls(calls)
        # new_db=True
        reset_mocks(vars())
        new = True
        MOD.get_alembic_cfg(new)
        mocked_url.assert_called_once_with(new)

    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.system', autospec=True)
    @patch(MOD.__name__ + '.Path', autospec=True)
    def test_get_db_url(self, mocked_path, mocked_system, mocked_log):
        # Linux case
        db_abspath = '/home/user/lighter-data/db/lighter.db'
        mocked_path().joinpath().resolve.return_value = db_abspath
        mocked_system.return_value = 'Linux'
        res = MOD._get_db_url(False)
        self.assertEqual(res, 'sqlite:///{}'.format(db_abspath))
        mocked_path().joinpath().resolve.assert_called_once_with(strict=True)
        # macOS case
        db_abspath = '/home/user/lighter-data/db/lighter.db'
        mocked_path().joinpath().resolve.return_value = db_abspath
        mocked_system.return_value = 'Darwin'
        res = MOD._get_db_url(False)
        self.assertEqual(res, 'sqlite:///{}'.format(db_abspath))
        # Windows case
        db_abspath = r"C:\Users\user\lighter-data\db\lighter.db"
        mocked_path().joinpath().resolve.return_value = db_abspath
        mocked_system.return_value = 'Windows'
        res = MOD._get_db_url(False)
        self.assertEqual(res, r'sqlite:///{}'.format(db_abspath))
        # unrecognized OS case, using in-memory DB
        mocked_system.return_value = 'unknown'
        res = MOD._get_db_url(False)
        self.assertEqual(res, 'sqlite://')
        assert mocked_log.warning.called
        # new DB case
        reset_mocks(vars())
        mocked_path().joinpath().resolve.side_effect = [
            FileNotFoundError(), None]
        res = MOD._get_db_url(True)
        mocked_path().joinpath().touch.assert_called_once_with()
        self.assertEqual(mocked_path().joinpath().resolve.call_count, 2)
        # existing DB case
        reset_mocks(vars())
        mocked_path().joinpath().resolve.side_effect = FileNotFoundError()
        with self.assertRaises(RuntimeError):
            res = MOD._get_db_url(False)
        assert not mocked_path().joinpath().touch.called
        # simulate case with python3.5 and existing DB
        reset_mocks(vars())
        mocked_path().joinpath().resolve.side_effect = [
            TypeError(), FileNotFoundError()]
        with self.assertRaises(RuntimeError):
            res = MOD._get_db_url(False)
        calls = [call(strict=True), call()]
        mocked_path().joinpath().resolve.assert_has_calls(calls)

    @patch(MOD.__name__ + '._is_db_at_head', autospec=True)
    @patch(MOD.__name__ + '.get_alembic_cfg', autospec=True)
    @patch(MOD.__name__ + '.LOGGER', autospec=True)
    @patch(MOD.__name__ + '.get_mac_params_from_db', autospec=True)
    @patch(MOD.__name__ + '.get_token_from_db', autospec=True)
    def test_is_db_ok(self, mocked_db_tok, mocked_db_mac, mocked_log,
                      mocked_a_cfg, mocked_db_head):
        settings.DISABLE_MACAROONS = False
        # correct case
        with patch(MOD.__name__ + '.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = \
                [False, True, True, True]
            mocked_db_tok.return_value = b'access_token'
            mocked_db_mac.return_value = 'mac_params'
            mocked_db_head.return_value = True
            res = MOD.is_db_ok(SES)
            self.assertEqual(res, True)
            mocked_a_cfg.assert_called_once_with(False)
            mocked_db_head.assert_called_once_with(
                mocked_a_cfg.return_value, mocked_engine)
        # missing token case
        with patch(MOD.__name__ + '.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = [False, False]
            res = MOD.is_db_ok(SES)
            self.assertEqual(res, False)
        # existing old salt table
        with patch(MOD.__name__ + '.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = [True]
            res = MOD.is_db_ok(SES)
            self.assertEqual(res, False)
        # missing macaroon
        with patch(MOD.__name__ + '.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = [False, True, False]
            res = MOD.is_db_ok(SES)
            self.assertEqual(res, False)
            assert mocked_log.error.called
        # missing macaroon but configuring=True
        reset_mocks(vars())
        with patch(MOD.__name__ + '.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = [False, True, True]
            res = MOD.is_db_ok(SES, configuring=True)
            self.assertEqual(res, True)
            assert not mocked_log.error.called
        # missing implementation_secrets table
        with patch(MOD.__name__ + '.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = \
                [False, True, True, False]
            res = MOD.is_db_ok(SES)
            self.assertEqual(res, False)
        # db revision not at head
        reset_mocks(vars())
        with patch(MOD.__name__ + '.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = \
                [False, True, True, True]
            mocked_db_head.return_value = False
            res = MOD.is_db_ok(SES)
            self.assertEqual(res, False)
            mocked_a_cfg.assert_called_once_with(False)
            mocked_db_head.assert_called_once_with(
                mocked_a_cfg.return_value, mocked_engine)

    @patch(MOD.__name__ + '.migration', autospec=True)
    @patch(MOD.__name__ + '.getLogger', autospec=True)
    @patch(MOD.__name__ + '.ScriptDirectory', autospec=True)
    def test_is_db_at_head(self, mocked_scr_dir, mocked_getlog, mocked_migr):
        a_cfg = 'alembic_cfg'
        con = 'connection'
        connectable = MagicMock()
        connectable.begin.return_value.__enter__.return_value = con
        # correct case
        mocked_migr.MigrationContext.configure.return_value\
            .get_current_heads.return_value = ('322a0daf8bcb',)
        mocked_scr_dir.from_config.return_value.get_heads.return_value = \
            ['322a0daf8bcb']
        res = MOD._is_db_at_head(a_cfg, connectable)
        mocked_scr_dir.from_config.assert_called_once_with(a_cfg)
        connectable.begin.assert_called_once_with()
        mocked_getlog.assert_called_once_with('alembic')
        mocked_migr.MigrationContext.configure.assert_called_once_with(con)
        mocked_migr.MigrationContext.configure.return_value\
            .get_current_heads.assert_called_once_with()
        mocked_scr_dir.from_config.return_value.get_heads\
            .assert_called_once_with()
        self.assertEqual(res, True)
        # db not at head case
        reset_mocks(vars())
        mocked_migr.MigrationContext.configure.return_value\
            .get_current_heads.return_value = ()
        res = MOD._is_db_at_head(a_cfg, connectable)
        self.assertEqual(res, False)

    def test_get_mac_params_from_db(self):
        data = b'data'
        params = b'scrypt_params'
        # correct case
        mac_par = Mock()
        mac_par.scrypt_params = params
        SES.query.return_value.first.return_value = mac_par
        res = MOD.get_mac_params_from_db(SES)
        self.assertEqual(res, params)
        # missing case
        reset_mocks(vars())
        SES.query.return_value.first.return_value = None
        res = MOD.get_mac_params_from_db(SES)
        self.assertEqual(res, None)

    def test_get_secret_from_db(self):
        impl = 'implementation'
        sec_type = 'password'
        impl_sec = MOD.ImplementationSecret(
            implementation=impl, secret_type=sec_type, active=1, secret=b'sec')
        # correct case
        SES.query.return_value.filter_by.return_value.first.return_value = \
            impl_sec
        res = MOD.get_secret_from_db(SES, impl, sec_type)
        self.assertEqual(res, impl_sec)
        # missing case
        reset_mocks(vars())
        SES.query.return_value.filter_by.return_value.first.return_value = \
            None
        res = MOD.get_secret_from_db(SES, impl, sec_type)
        self.assertEqual(res, None)

    def test_get_token_from_db(self):
        data = b'data'
        params = b'scrypt_params'
        # correct case
        acc_tok = Mock()
        acc_tok.data = data
        acc_tok.scrypt_params = params
        SES.query.return_value.first.return_value = acc_tok
        res_data, res_par = MOD.get_token_from_db(SES)
        self.assertEqual(res_data, data)
        self.assertEqual(res_par, params)
        # missing case
        reset_mocks(vars())
        SES.query.return_value.first.return_value = None
        res_data, res_par = MOD.get_token_from_db(SES)
        self.assertEqual(res_data, None)
        self.assertEqual(res_par, None)

    @patch(MOD.__name__ + '.MacRootKey', autospec=True)
    def test_save_mac_params_to_db(self, mocked_mac):
        params = b'scrypt_params'
        MOD.save_mac_params_to_db(SES, params)
        mocked_mac.assert_called_once_with(
            data='mac_params', scrypt_params=params)

    @patch(MOD.__name__ + '.ImplementationSecret', autospec=True)
    def test_save_secret_to_db(self, mocked_impl_sec):
        sec = b'secret'
        params = b'scrypt_params'
        impl = 'implementation'
        sec_type = 'password'
        act = 1
        MOD.save_secret_to_db(SES, impl, sec_type, act, sec, params)
        mocked_impl_sec.assert_called_once_with(
            implementation=impl, secret_type=sec_type, active=act, secret=sec,
            scrypt_params=params)

    @patch(MOD.__name__ + '.AccessToken', autospec=True)
    def test_save_token_to_db(self, mocked_acc_tok):
        tok = b'token'
        par = b'scrypt_params'
        MOD.save_token_to_db(SES, tok, par)
        mocked_acc_tok.assert_called_once_with(data=tok, scrypt_params=par)


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
