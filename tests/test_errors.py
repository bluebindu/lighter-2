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

""" Tests for errors module """

from importlib import import_module
from re import sub
from unittest import TestCase
from unittest.mock import patch, Mock

from grpc import StatusCode

from lighter import errors, settings
from lighter.errors import ERRORS

MOD = import_module('lighter.errors')


class ErrorsTests(TestCase):
    """ Tests for errors module """

    def test_error(self):
        # Correct case
        for key, act in ERRORS.items():
            reset_mocks(vars())
            context = Mock()
            func = eval('errors.Err().{}'.format(key))
            res = func(context, 'param')
            sc = getattr(StatusCode, ERRORS[key]['code'])
            if 'msg' in ERRORS[key]:
                msg = sub('%PARAM%', 'param', ERRORS[key]['msg'])
            else:
                msg = 'param'
            context.abort.assert_called_once_with(sc, msg)
        # Error case
        reset_mocks(vars())
        context = Mock()
        res = MOD.Err().unexistent(context)
        assert not context.abort.called

    @patch('lighter.errors.getattr')
    def test_report_error(self, mocked_getattr):
        # Mapped errors
        implementations = ['clightning', 'eclair', 'lnd']
        for impl in implementations:
            settings.IMPLEMENTATION = impl
            module = import_module('lighter.light_{}'.format(impl))
            # Mapped errors
            mocked_getattr.side_effect = Exception()
            for msg, act in module.ERRORS.items():
                reset_mocks(vars())
                error = 'aaa {} zzz'.format(msg)
                context = Mock()
                err_self = MOD.Err()
                with self.assertRaises(Exception):
                    err_self.report_error(context, error)
                args = [context, act['params']] if 'params' in act \
                    else [context]
                mocked_getattr.assert_called_once_with(err_self, act['fun'])
            # Unmapped error
            reset_mocks(vars())
            context = Mock()
            err_self = MOD.Err()
            err_self.unexpected_error = Mock()
            err_self.unexpected_error.side_effect = Exception()
            with self.assertRaises(Exception):
                err_self.report_error(context, 'unmapped error')
            assert not mocked_getattr.called
            err_self.unexpected_error.assert_called_once_with(
                context, 'unmapped error')


def reset_mocks(params):
    for _key, value in params.items():
        try:
            if type(value.call_count) is int:
                value.reset_mock()
        except:
            pass
