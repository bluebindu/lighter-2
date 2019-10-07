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

""" The module which handles Lighter's database """

from contextlib import contextmanager
from logging import getLogger
from platform import system
from pathlib import Path

from sqlalchemy import create_engine, Column, Integer, LargeBinary, String
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from . import settings as sett
from .errors import Err

LOGGER = getLogger(__name__)


def _get_db_url(new_db):
    """
    Constructs the DB's URL for SQLAlchemy.
    It fails when DB is missing at runtime.
    """
    db_abspath = ''
    db_relpath = Path(sett.DB_DIR).joinpath(sett.DB_NAME)
    try:
        # from python3.6 'strict' in 'resolve' can be used to avoid exception
        db_abspath = db_relpath.resolve()
    except FileNotFoundError:
        if new_db:
            db_relpath.touch()
            db_abspath = db_relpath.resolve()
        else:
            raise RuntimeError('Your database is missing. Create it by '
                               'running make secure')
    running_sys = system()
    if running_sys in ('Linux', 'Darwin'):
        return 'sqlite:///{}'.format(db_abspath)
    if running_sys == 'Windows':
        return r'sqlite:///{}'.format(db_abspath)
    LOGGER.warning('Unrecognized OS, using in-memory database')
    return 'sqlite://'


Base = declarative_base()
ENGINE = None
Session = None


def init_db(new_db=False):
    """ Initialize DB connection, creating missing tables if requested """
    global ENGINE  # pylint: disable=global-statement
    global Session  # pylint: disable=global-statement
    ENGINE = create_engine(_get_db_url(new_db))
    Session = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False)
    if new_db:
        Base.metadata.create_all(ENGINE)


@contextmanager
def session_scope(context):
    """ Provides a transactional scope around a series of operations """
    session = Session()
    try:
        yield session
        session.commit()
    except SQLAlchemyError:
        session.rollback()
        Err().db_error(context)
    except Exception as exc:
        session.rollback()
        raise exc
    finally:
        session.close()


def is_db_ok(session):
    """
    It returns wheter the DB is ok (not containing old data nor missing
    essential data)
    """
    global ENGINE  # pylint: disable=global-statement
    # checking if old salt table exists
    if ENGINE.dialect.has_table(ENGINE, 'salt_table'):
        return False
    # checking if encrypted token exists
    if not ENGINE.dialect.has_table(ENGINE, AccessToken.__tablename__) or \
            not get_token_from_db(session):
        return False
    # checking if macaroon root key exists
    if not sett.DISABLE_MACAROONS:
        if not ENGINE.dialect.has_table(ENGINE, MacRootKey.__tablename__) or \
                not get_mac_params_from_db(session):
            LOGGER.error('Please make sure you have generated macaroon at '
                         'least one time')
            return False
    return True


def save_token_to_db(session, token, scrypt_params):
    """ Saves the encrypted token in database """
    session.merge(AccessToken(data=token, scrypt_params=scrypt_params))


def get_token_from_db(session):
    """ Gets the encrypted token from database """
    access_token = session.query(AccessToken).first()
    if not access_token:
        return None, None
    return access_token.data, access_token.scrypt_params


def save_mac_params_to_db(session, scrypt_params):
    """ Saves macaroon root key parameters in database """
    session.merge(MacRootKey(data='mac_params', scrypt_params=scrypt_params))


def get_mac_params_from_db(session):
    """ Gets macaroon root key parameters from database """
    mac_params = session.query(MacRootKey).first()
    if not mac_params:
        return None
    return mac_params.scrypt_params


def save_secret_to_db(session, implementation, active, data, scrypt_params):
    """ Saves implementation's secret in database """
    session.merge(ImplementationSecret(
        implementation=implementation, active=active, secret=data,
        scrypt_params=scrypt_params))


def get_secret_from_db(session, implementation):
    """ Gets implementation's secret from database """
    sec = session.query(ImplementationSecret).filter_by(
        implementation=implementation).first()
    if not sec:
        return None, None, None
    return sec.secret, sec.active, sec.scrypt_params


class AccessToken(Base):  # pylint: disable=too-few-public-methods
    """ Class that maps the table containing the access token """

    __tablename__ = 'access_token_table'

    data = Column(LargeBinary, primary_key=True)
    scrypt_params = Column(LargeBinary)

    def __repr__(self):
        return '<AccessToken(data="{}", scrypt_params="{}")>'.format(
            self.data, self.scrypt_params)


class ImplementationSecret(Base):  # pylint: disable=too-few-public-methods
    """ Class that maps the table containing the implementation secrets """

    __tablename__ = 'implementation_secrets'

    implementation = Column(String, primary_key=True)
    active = Column(Integer)
    secret = Column(LargeBinary)
    scrypt_params = Column(LargeBinary)

    def __repr__(self):
        return ('<ImplementationSecret(implementation="{}", active="{}", ' +
                'secret="{}", scrypt_params="{}")>').format(
                    self.implementation, self.active, self.secret,
                    self.scrypt_params)


class MacRootKey(Base):  # pylint: disable=too-few-public-methods
    """ Class that maps the table containing the macaroon root key """

    __tablename__ = 'mac_root_key_table'

    data = Column(String, primary_key=True)
    scrypt_params = Column(LargeBinary)

    def __repr__(self):
        return '<MacRootKey(data="{}", scrypt_params="{}")>'.format(
            self.data, self.scrypt_params)
