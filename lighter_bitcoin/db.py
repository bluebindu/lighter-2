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

""" Lighter's database schema definition module """

from logging import getLogger

from sqlalchemy import Column, Integer, LargeBinary, String
from sqlalchemy.ext.declarative import declarative_base

LOGGER = getLogger(__name__)

Base = declarative_base()


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
