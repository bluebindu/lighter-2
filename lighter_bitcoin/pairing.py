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

"""
Pairing: creates one lighterconnect URI and if macaroons are enabled also
a macaroon URI.
The user is prompt to choose to visualize a QR code or a text string.
"""

import sys

from configparser import Error as ConfigError
from os import access, path, R_OK
from signal import signal, SIGTERM

from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_L
from requests import get

from . import settings as sett
from .macaroons import MACAROONS
from .utils.exceptions import InterruptException
from .utils.misc import die, handle_keyboardinterrupt, handle_sigterm, \
    init_common

signal(SIGTERM, handle_sigterm)

QRCODE = 1
TEXT = 2


def _check_file(file_path, file_name):
    """ Checks if a file exists and is readable """
    if not path.exists(file_path):
        die('Could not find {} in specified path'.format(file_name))
    if not access(file_path, R_OK):
        die('Could not read {} in specified path (hint: check file '
            'permissions)'.format(file_name))


def _select_opts(opts, question):
    """ Creates options selector and returns choice as integer """
    while True:
        for num, desc in opts.items():
            print('{}) {}'.format(num, desc))
        choice = input(question)
        try:
            if int(choice) in opts.keys():
                return int(choice)
        except ValueError:
            pass
        print('Invalid option "{}", Ctrl-c to abort'.format(choice))


def _show_qrcode(data):
    """ Creates and shows a QR code from data """
    qrcode = QRCode(version=1, error_correction=ERROR_CORRECT_L, box_size=7)
    qrcode.add_data(data)
    qrcode.make()
    qrcode.print_ascii(tty=True)


def _show_data(pair_mode, data):
    """ Shows data according to pairing mode (QR code or text) """
    if pair_mode == QRCODE:
        _show_qrcode(data)
    else:
        print(data)


def _get_macaroon_uri():
    """ Constructs and returns macaroon URI """
    print('\nStep 3: authorization pairing')
    opts = {1: 'admin     (all ops)', 2: 'readonly  (read-only ops)',
            3: 'invoices  (create and check invoices only)'}
    question = 'Which set of permissions do you want to use? '
    choice = _select_opts(opts, question)
    if choice == 1:
        mac_name = sett.MAC_ADMIN
    elif choice == 2:
        mac_name = sett.MAC_READONLY
    else:
        mac_name = sett.MAC_INVOICES
    print('\nLighter authorization pairing (contains a macaroon).')
    print('Use this to authorize your client (e.g. Globular) to operate this '
          'Lighter instance:\n')
    mac_path = path.join(sett.MACAROONS_DIR, mac_name)
    mac = 'macaroon:'
    with open(mac_path, 'rb') as file:
        macaroon = file.read()
        mac = mac + macaroon.decode()
    return mac


def _get_connection_uri():
    """ Constructs and returns lighterconnect URI (connection data) """
    print('\nStep 2: connection pairing')
    public_ip = get('http://ipinfo.io/ip').text.strip()
    i_host = input('Insert your host (empty to use IP {}): '.format(public_ip))
    host = i_host if i_host else public_ip
    i_port = input('Insert your port (empty to use port {}): '.format(
        sett.PORT))
    if i_port:
        try:
            i_port = int(i_port)
        except ValueError:
            die('Invalid port')
        if i_port < 1 or i_port > 65535:
            die('Invalid port')
    port = i_port if i_port else int(sett.PORT)
    conn_uri = 'lighterconnect://{}:{}'.format(host, port)
    if not sett.INSECURE_CONNECTION:
        cert = ''
        cert_lines = []
        with open(sett.SERVER_CRT, 'r') as file:
            cert_lines = file.readlines()
        for cert_line in cert_lines:
            if 'CERTIFICATE' in cert_line:
                continue
            cert += cert_line.strip().replace('/', '_').replace('+', '-')
        conn_uri = conn_uri + '?cert={}'.format(cert)
    else:
        print('\nWARNING: connection security disabled')
    print('\nLighter connection pairing (contains host, port and TLS '
          'certificate).')
    print('Use this to connect your client (e.g. Globular) to this Lighter '
          'instance:\n')
    return conn_uri


def _get_pairing_mode():
    """ Gets pairing mode (QR code or text) selected by user """
    print('\nStep 1: paring mode selection')
    opts = {1: 'QR code image (recommended)', 2: 'Plain text'}
    choice = _select_opts(opts, 'Which one do you want to use? ')
    if choice == 1:
        return QRCODE
    return TEXT


def _pairing():
    """ Creates pairing images or texts """
    if not sett.INSECURE_CONNECTION:
        _check_file(sett.SERVER_CRT, 'certificate')
    if not sett.DISABLE_MACAROONS:
        for mac_name in MACAROONS:
            _check_file(path.join(sett.MACAROONS_DIR, mac_name), 'macaroon')
    pair_mode = _get_pairing_mode()
    conn_uri = _get_connection_uri()
    _show_data(pair_mode, conn_uri)
    if sett.DISABLE_MACAROONS:
        print('\nWARNING: macaroons are disabled')
        sys.exit(0)
    mac = _get_macaroon_uri()
    _show_data(pair_mode, mac)


def start():
    """ Pairing entrypoint """
    try:
        _start()
    except ImportError:
        die("Implementation '{}' is not supported".format(sett.IMPLEMENTATION))
    except RuntimeError as err:
        err_msg = ''
        if str(err):
            err_msg = str(err)
        die(err_msg)
    except ConfigError as err:
        die('Configuration error: ' + str(err))
    except InterruptException:
        die('Exiting...')


@handle_keyboardinterrupt
def _start():
    """ Initializes and starts pairing procedure """
    init_common("Start Lighter pairing procedure", core=False)
    _pairing()
