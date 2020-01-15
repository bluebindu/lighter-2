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
from os import path
from platform import system
from pathlib import Path

from alembic.command import stamp
from alembic.config import Config
from alembic.runtime import migration
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, Column, Integer, LargeBinary, String
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from . import settings as sett
from .errors import Err

LOGGER = getLogger(__name__)


def get_db_url(new_db):
    """
    Constructs the DB's URL for SQLAlchemy.
    It fails when DB is missing at runtime.
    """
    db_abspath = ''
    db_relpath = Path(sett.DB_DIR).joinpath(sett.DB_NAME)
    try:
        try:
            # from python3.6 strict is necessary to raise FileNotFoundError
            # pylint: disable=unexpected-keyword-arg
            db_abspath = db_relpath.resolve(strict=True)
            # pylint: enable=unexpected-keyword-arg
        except TypeError:
            db_abspath = db_relpath.resolve()
    except FileNotFoundError:
        if new_db:
            db_relpath.touch()
            db_abspath = db_relpath.resolve()
        else:
            raise RuntimeError('Your database is missing. Create it by '
                               'running lighter-secure')
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


def init_db(new_db=False, alembic_cfg=None):
    """ Initialize DB connection, creating missing tables if requested """
    if not alembic_cfg:
        alembic_cfg = get_alembic_cfg(new_db)
    sec = 'lighter_log'
    alembic_cfg.set_section_option(
        sec, 'lighter', path.join(sett.LOGS_DIR, sett.LOGS_LIGHTER))
    alembic_cfg.set_section_option(
        sec, 'migrations', path.join(sett.LOGS_DIR, sett.LOGS_MIGRATIONS))
    global ENGINE  # pylint: disable=global-statement
    global Session  # pylint: disable=global-statement
    ENGINE = create_engine(get_db_url(new_db))
    Session = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False)
    if new_db:
        LOGGER.info('Creating database')
        Base.metadata.create_all(ENGINE)
        stamp(alembic_cfg, 'head')


def get_alembic_cfg(new_db):
    """ Returns alembic Config object """
    alembic_cfg = Config(sett.ALEMBIC_CFG)
    alembic_cfg.set_main_option('sqlalchemy.url', get_db_url(new_db))
    alembic_cfg.set_main_option('script_location',
                                sett.PKG_NAME + ':migrations')
    return alembic_cfg


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
    It returns whether the DB is ok (not containing old data nor missing
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
    # checking if implementation_secrets table exists
    if not ENGINE.dialect.has_table(ENGINE, 'implementation_secrets'):
        return False
    if not is_db_at_head(get_alembic_cfg(False), ENGINE):
        LOGGER.error('Migrations may not have applied correctly')
        return False
    return True


def is_db_at_head(alembic_cfg, connectable):
    """ Returns whether the DB revision is at head """
    directory = ScriptDirectory.from_config(alembic_cfg)
    with connectable.begin() as connection:
        getLogger('alembic').propagate = False
        context = migration.MigrationContext.configure(connection)
        return set(context.get_current_heads()) == set(directory.get_heads())


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


# pylint: disable=too-many-arguments
def save_secret_to_db(session, implementation, sec_type, active, data,
                      scrypt_params):
    """ Saves implementation's secret in database """
    session.merge(ImplementationSecret(
        implementation=implementation, secret_type=sec_type, active=active,
        secret=data, scrypt_params=scrypt_params))
    # pylint: enable=too-many-arguments


def get_secret_from_db(session, implementation, sec_type):
    """ Gets implementation's secret from database """
    sec = session.query(ImplementationSecret).filter_by(
        implementation=implementation, secret_type=sec_type).first()
    return sec


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
    secret_type = Column(String, primary_key=True)
    active = Column(Integer)
    secret = Column(LargeBinary)
    scrypt_params = Column(LargeBinary)

    def __repr__(self):
        return ('<ImplementationSecret(implementation="{}", ' +
                'secret_type="{}", active="{}", secret="{}", ' +
                'scrypt_params="{}")>').format(
                    self.implementation, self.secret_type, self.active,
                    self.secret, self.scrypt_params)


class MacRootKey(Base):  # pylint: disable=too-few-public-methods
    """ Class that maps the table containing the macaroon root key """

    __tablename__ = 'mac_root_key_table'

    data = Column(String, primary_key=True)
    scrypt_params = Column(LargeBinary)

    def __repr__(self):
        return '<MacRootKey(data="{}", scrypt_params="{}")>'.format(
            self.data, self.scrypt_params)
