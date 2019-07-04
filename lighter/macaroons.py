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

""" Macaroons management (creation and validation) class """

from codecs import decode
from logging import getLogger

from macaroonbakery.bakery import Bakery, canonical_ops, \
    DischargeRequiredError, LATEST_VERSION, MemoryKeyStore, \
    MemoryOpsStore, Op, PermissionDenied
from macaroonbakery.checkers import context_with_operations, AuthContext
from pymacaroons import Macaroon
from pymacaroons.exceptions import MacaroonDeserializationException

from . import settings

LOGGER = getLogger(__name__)

MAC_VERSION = LATEST_VERSION

ALL_OPS = canonical_ops(
    [Op(op['entity'], op['action']) for op in settings.ALL_PERMS.values()])

INVOICE_OPS = canonical_ops(
    [Op(op['entity'], op['action']) for op in settings.INVOICE_PERMS])

READONLY_OPS = canonical_ops(
    [Op(op['entity'], op['action']) for op in settings.READ_PERMS])

MACAROONS = {
    settings.MAC_ADMIN: ALL_OPS,
    settings.MAC_INVOICES: INVOICE_OPS,
    settings.MAC_READONLY: READONLY_OPS,
}


def check_macaroons(metadata, method):
    """ Checks if metadata contains valid macaroons """
    num_mac = 0
    for data in metadata:
        if data.key == 'macaroon':
            num_mac = num_mac + 1
            try:
                serialized_macaroon = decode(data.value, 'hex')
                macaroon = Macaroon.deserialize(serialized_macaroon)
            except (MacaroonDeserializationException, ValueError):
                LOGGER.error('- Cannot deserialize macaroon')
                return False
    if num_mac != 1:
        LOGGER.error(
            '- Wrong number of macaroons, 1 required, %s received', num_mac)
        return False
    return _validate_macaroon(macaroon, settings.ALL_PERMS[method])


def _validate_macaroon(macaroon, required_perm):
    """ Checks if a given macaroon is authorized to run required operation """
    baker = settings.LIGHTNING_BAKERY
    auth_checker = baker.checker.auth([[macaroon]])
    ctx_op = context_with_operations(AuthContext(), ALL_OPS)
    required_op = Op(required_perm['entity'], required_perm['action'])
    try:
        auth_info = auth_checker.allow(ctx_op, [required_op])
        if auth_info:
            return True
    except (DischargeRequiredError, PermissionDenied):
        LOGGER.error('- Authorization error')
    return False


def get_baker(root_key, put_ops=False):
    """ Gets a baker, optionally registering operations in MemoryOpsStore """
    baker = Bakery(
        location='lighter',
        ops_store=MemoryOpsStore(),
        root_key_store=MemoryKeyStore(key=root_key))
    if put_ops:
        for permitted_ops in MACAROONS.values():
            entity = baker.oven.ops_entity(permitted_ops)
            baker.oven.ops_store.put_ops(entity, None, permitted_ops)
    return baker
