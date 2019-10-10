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

""" Handles alembic DB migration """

import sys

from functools import wraps
from logging import getLogger
from os import environ as env

from alembic import command

from lighter.db import get_alembic_cfg, init_db
from lighter.utils import get_start_options, update_logger

LOGGER = getLogger(__name__)


def _die(msg):
    """ Logs an error message and exits with status code 1 """
    if str(msg):
        LOGGER.error(msg)
    sys.exit(1)


def _handle_keyboardinterrupt(func):
    """ Handles KeyboardInterrupt """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            _die('\nKeyboard interrupt detected. Exiting...')

    return wrapper


@_handle_keyboardinterrupt
def migrate():
    """ Handles DB migration """
    try:
        update_logger()
        no_db = env.get('NO_DB')
        rm_db = env.get('RM_DB')
        if no_db or rm_db:
            return
        get_start_options()
        alembic_cfg = get_alembic_cfg(False)
        init_db()
        from lighter.db import ENGINE
        with ENGINE.begin() as connection:
            alembic_cfg.attributes['connection'] = connection
            command.upgrade(alembic_cfg, 'head')
    except RuntimeError as err:
        _die(str(err))
