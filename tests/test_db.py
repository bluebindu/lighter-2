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
""" Tests for db module """

from importlib import import_module
from unittest import TestCase
from unittest.mock import Mock, patch

from sqlalchemy.exc import SQLAlchemyError

from lighter import settings

MOD = import_module('lighter.db')
CTX = 'context'
SES = Mock()


class DbTests(TestCase):
    """ Tests for the db module """

    @patch('lighter.db.LOGGER', autospec=True)
    @patch('lighter.db.system', autospec=True)
    @patch('lighter.db.Path', autospec=True)
    def test_get_db_url(self, mocked_path, mocked_system, mocked_log):
        # Linux case
        db_abspath = '/home/user/lighter-data/db/lighter.db'
        mocked_path().joinpath().resolve.return_value = db_abspath
        mocked_system.return_value = 'Linux'
        res = MOD._get_db_url(False)
        self.assertEqual(res, 'sqlite:///{}'.format(db_abspath))
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
        mocked_path().joinpath().resolve.assert_called_once_with()
        assert not mocked_path().joinpath().touch.called


    @patch('lighter.db.Base', autospec=False)
    @patch('lighter.db.sessionmaker', autospec=True)
    @patch('lighter.db.create_engine', autospec=True)
    @patch('lighter.db._get_db_url', autospec=True)
    def test_init_db(self, mocked_url, mocked_engine, mocked_ses_mak,
                     mocked_base):
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

    @patch('lighter.db.Err')
    @patch('lighter.db.Session', autospec=False)
    def test_session_scope(self, mocked_ses, mocked_err):
        # correct case
        with MOD.session_scope(CTX) as ses:
            self.assertEqual(ses, mocked_ses.return_value)
        mocked_ses.return_value.commit.assert_called_once_with()
        mocked_ses.return_value.close.assert_called_once_with()
        # db error case
        reset_mocks(vars())
        mocked_ses.return_value.commit.side_effect = SQLAlchemyError()
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

    @patch('lighter.db.LOGGER', autospec=True)
    @patch('lighter.db.get_mac_params_from_db', autospec=True)
    @patch('lighter.db.get_token_from_db', autospec=True)
    def test_is_db_ok(self, mocked_db_tok, mocked_db_mac, mocked_log):
        settings.DISABLE_MACAROONS = False
        # correct case
        with patch('lighter.db.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = [False, True, True]
            mocked_db_tok.return_value = b'access_token'
            mocked_db_mac.return_value = 'mac_params'
            res = MOD.is_db_ok(SES)
            self.assertEqual(res, True)
        # missing token case
        with patch('lighter.db.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = [False, False]
            res = MOD.is_db_ok(SES)
            self.assertEqual(res, False)
        # existing old salt table
        with patch('lighter.db.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = [True]
            res = MOD.is_db_ok(SES)
            self.assertEqual(res, False)
        # missing macaroon
        with patch('lighter.db.ENGINE') as mocked_engine:
            mocked_engine.dialect.has_table.side_effect = [False, True, False]
            res = MOD.is_db_ok(SES)
            self.assertEqual(res, False)
            assert mocked_log.error.called

    @patch('lighter.db.AccessToken', autospec=True)
    def test_save_token_to_db(self, mocked_acc_tok):
        tok = b'token'
        par = b'scrypt_params'
        MOD.save_token_to_db(SES, tok, par)
        mocked_acc_tok.assert_called_once_with(data=tok, scrypt_params=par)

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

    @patch('lighter.db.MacRootKey', autospec=True)
    def test_save_mac_params_to_db(self, mocked_mac):
        params = b'scrypt_params'
        MOD.save_mac_params_to_db(SES, params)
        mocked_mac.assert_called_once_with(
            data='mac_params', scrypt_params=params)

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

    @patch('lighter.db.ImplementationSecret', autospec=True)
    def test_save_secret_to_db(self, mocked_impl_sec):
        sec = b'secret'
        params = b'scrypt_params'
        impl = 'implementation'
        act = 1
        MOD.save_secret_to_db(SES, impl, act, sec, params)
        mocked_impl_sec.assert_called_once_with(
            implementation=impl, active=act, secret=sec, scrypt_params=params)

    def test_get_secret_from_db(self):
        impl = 'implementation'
        sec = b'secret'
        act = 1
        par = b'params'
        # correct case
        impl_sec = Mock()
        impl_sec.implementation = impl
        impl_sec.active = act
        impl_sec.secret = sec
        impl_sec.scrypt_params = par
        SES.query.return_value.filter_by.return_value.first.return_value = \
            impl_sec
        res_sec, res_act, res_par = MOD.get_secret_from_db(SES, impl)
        self.assertEqual(res_sec, sec)
        self.assertEqual(res_act, act)
        self.assertEqual(res_par, par)
        # missing case
        reset_mocks(vars())
        SES.query.return_value.filter_by.return_value.first.return_value = \
            None
        res_sec, res_act, res_par = MOD.get_secret_from_db(SES, impl)
        self.assertEqual(res_sec, None)
        self.assertEqual(res_act, None)
        self.assertEqual(res_par, None)

    def test_AccessToken(self):
        data = b'token'
        par = b'params'
        res = MOD.AccessToken(data=data, scrypt_params=par)
        self.assertEqual(
            str(res),
            ('<AccessToken(data="b\'token\'", scrypt_params="b\'params\'")>'))

    def test_ImplementationSecret(self):
        impl = 'implementation'
        sec = b'secret'
        act = 1
        par = b'params'
        res = MOD.ImplementationSecret(
            implementation=impl, active=act, secret=sec, scrypt_params=par)
        self.assertEqual(
            str(res),
            ('<ImplementationSecret(implementation="implementation", '
             'active="1", secret="b\'secret\'", '
             'scrypt_params="b\'params\'")>'))

    def test_MacRootKey(self):
        data = 'mac_params'
        par = b'params'
        res = MOD.MacRootKey(data=data, scrypt_params=par)
        self.assertEqual(
            str(res),
            ('<MacRootKey(data="mac_params", scrypt_params="b\'params\'")>'))


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
