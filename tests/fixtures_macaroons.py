import sys

from codecs import encode
from datetime import datetime, timedelta, timezone
from importlib import import_module

from . import proj_root

settings = import_module(proj_root + '.settings')
lighter_mac_mod = import_module(proj_root + '.macaroons')
get_baker = getattr(lighter_mac_mod, 'get_baker')
MACAROONS = getattr(lighter_mac_mod, 'MACAROONS')
MAC_VERSION = getattr(lighter_mac_mod, 'MAC_VERSION')

this = sys.modules[__name__]

MACAROONS_STORE = {
    settings.MAC_ADMIN: 'ADMIN_MAC',
    settings.MAC_READONLY: 'READ_MAC',
    settings.MAC_INVOICES: 'INVOICES_MAC'
}

ADMIN_MAC = ''
READ_MAC = ''
INVOICES_MAC = ''


def create_lightning_macaroons(root_key):
    baker = get_baker(root_key)
    for file_name, permitted_ops in MACAROONS.items():
        expiration_time = datetime.now(tz=timezone.utc) + timedelta(days=365)
        caveats = None
        mac = baker.oven.macaroon(
            MAC_VERSION, expiration_time, caveats, permitted_ops)
        serialized_macaroon = mac.macaroon.serialize()
        setattr(this, MACAROONS_STORE[file_name],
                encode(serialized_macaroon.encode(), 'hex'))
