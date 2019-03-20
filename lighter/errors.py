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

""" The errors module for Lighter """

from importlib import import_module
from logging import getLogger
from re import sub

from grpc import StatusCode

from lighter import settings

LOGGER = getLogger(__name__)

ERRORS = {
    'amount_required': {
        'code': 'INVALID_ARGUMENT',
        'msg': 'A positive amount is required for empty invoices'
    },
    'connect_failed': {
        'code': 'CANCELLED',
        'msg': 'Connection to peer failed'
    },
    'db_error': {
        'code': 'CANCELLED',
        'msg': 'Error accessing database'
    },
    'incorrect_description': {
        'code': 'INVALID_ARGUMENT',
        'msg': 'Provided description doesn\'t match the payment request one'
    },
    'insufficient_fee': {
        'code': 'OUT_OF_RANGE',
        'msg': 'Fees are insufficient'
    },
    'insufficient_funds': {
        'code': 'OUT_OF_RANGE',
        'msg': 'Funds are insufficient'
    },
    'invalid': {
        'code': 'INVALID_ARGUMENT',
        'msg': 'Invalid parameter "%PARAM%"'
    },
    'invoice_expired': {
        'code': 'OUT_OF_RANGE',
        'msg': 'Invoice expired'
    },
    'invoice_not_found': {
        'code': 'NOT_FOUND',
        'msg': 'Invoice not found'
    },
    'missing_parameter': {
        'code': 'INVALID_ARGUMENT',
        'msg': 'Parameter "%PARAM%" is necessary'
    },
    'node_error': {
        'code': 'UNAVAILABLE',
        'msg': '[node error] %PARAM%'
    },
    'openchannel_failed': {
        'code': 'CANCELLED',
        'msg': 'Failed to open channel'
    },
    'out_of_range': {
        'code': 'OUT_OF_RANGE',
        'msg': 'Parameter "%PARAM%" out of range'
    },
    'route_not_found': {
        'code': 'NOT_FOUND',
        'msg': 'Can\'t find route to node'
    },
    'unimplemented_method': {
        'code': 'UNIMPLEMENTED',
        'msg': 'This gRPC method is not supported for this implementation'
    },
    'unimplemented_parameter': {
        'code': 'UNIMPLEMENTED',
        'msg': 'This gRPC parameter is not supported for this implementation'
    },
    'unsettable': {
        'code': 'INVALID_ARGUMENT',
        'msg': 'Parameter "%PARAM%" unsettable'
    },
    'value_error': {
        'code': 'INVALID_ARGUMENT',
        'msg': 'Value is not a number or exceeds maximum precision'
    },
    'value_too_low': {
        'code': 'OUT_OF_RANGE',
        'msg': 'Value is under minimum value'
    },
    'value_too_high': {
        'code': 'OUT_OF_RANGE',
        'msg': 'Value exceeds maximum treshold'
    },
    'wrong_password': {
        'code': 'INVALID_ARGUMENT',
        'msg': 'Wrong password'
    },
    # Fallback
    'unexpected_error': {
        'code': 'UNKNOWN'
    }
}


class Err():  # pylint: disable=too-few-public-methods
    """ Class necessary to implement the __getattr__ method """
    def __getattr__(self, name):
        """ Dispatches the called error dynamically """
        def error_dispatcher(context, param=None):
            if name in ERRORS.keys():
                scode = getattr(StatusCode, ERRORS[name]['code'])
                msg = ''
                if 'msg' in ERRORS[name]:
                    msg = ERRORS[name]['msg']
                if param:
                    msg = sub('%PARAM%', str(param), msg)
                if name == 'unexpected_error':
                    msg = param
                    LOGGER.error('Unexpected error: %s', msg)
                context.abort(scode, msg)
            else:
                LOGGER.error('Unmapped error key')

        return error_dispatcher

    def report_error(self, context, error, always_abort=True):
        """
        Calls the proper function in dictionary or throws an unexpected_error
        """
        module = import_module('lighter.light_{}'.format(
            settings.IMPLEMENTATION))
        for msg, act in module.ERRORS.items():
            if msg in error:
                args = [context, act['params']] if 'params' in act \
                    else [context]
                if act['fun'] == 'node_error':
                    args = [context, error]
                getattr(self, act['fun'])(*args)
        if always_abort:
            self.unexpected_error(context, error)
