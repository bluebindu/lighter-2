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

""" Configuration settings module for Lighter """

from os import path


# Empty variables are set at runtime
# Some variables contain default values, cpuld be overwritten

IMPLEMENTATION = ''

L_DATA = './lighter-data'

HOST = '0.0.0.0'
PORT = '1708'
LIGHTER_ADDR = ''
INSECURE_CONNECTION = 0
SERVER_KEY = path.join(L_DATA, 'certs/server.key')
SERVER_CRT = path.join(L_DATA, 'certs/server.crt')
DB_DIR = path.join(L_DATA, 'db')
DB_NAME = 'lighter.db'
ENABLE_UNLOCKER = True
LOGS_DIR = path.join(L_DATA, 'logs')
CERTS_DIR = path.join(L_DATA, 'certs')

# Macaroons settings
UNLOCKER_STOP = False
LIGHTNING_BAKERY = None
DISABLE_MACAROONS = 0
MACAROONS_DIR = path.join(L_DATA, 'macaroons')
MAC_ADMIN = 'admin.macaroon'
MAC_READONLY = 'readonly.macaroon'
MAC_INVOICES = 'invoices.macaroon'

# Security settings
ACCESS_KEY_V1 = None
SALT_LEN = 32
ACCESS_TOKEN = b'lighter'
LATEST_VERSION = 1

ONE_DAY_IN_SECONDS = 60 * 60 * 24
GRPC_WORKERS = 10
GRPC_GRACE_TIME = 7
RESTART_THROTTLE = 3

# Lit-cli settings
CLI_HOST = '127.0.0.1'
CLI_ADDR = ''
CLI_TIMEOUT = 10

ENFORCE = True

TEST_HASH = '43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'
MAIN_HASH = '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000'

# Cli-based implementations settings
CMD_BASE = []

# c-lightning specific settings
CL_CLI = 'lightning-cli'
CL_RPC = 'lightning-rpc'

# eclair specific settings
ECL_HOST = 'localhost'
ECL_PORT = 8080
ECL_ENV = ''

# lnd specific settings
LND_HOST = 'localhost'
LND_PORT = 10009
LND_CERT = 'tls.cert'
LND_ADDR = ''
LND_CREDS = ''
LND_MAC = ''

# Common settings
IMPL_TIMEOUT = 7
MAX_INVOICES = 200
INVOICES_TIMES = 3
DEFAULT_DESCRIPTION = 'Lighter invoice'

LOG_TIMEFMT = '%Y-%m-%d %H:%M:%S %z'
LOG_TIMEFMT_SIMPLE = '%d %b %H:%M:%S'
LOG_LEVEL_CONSOLE = 'INFO'
LOG_LEVEL_FILE = 'DEBUG'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format':
            "[%(asctime)s] %(levelname).3s [%(name)s:%(lineno)s] %(message)s",
            'datefmt': LOG_TIMEFMT
        },
        'simple': {
            'format': '%(asctime)s %(levelname).3s: %(message)s',
            'datefmt': LOG_TIMEFMT_SIMPLE
        },
    },
    'handlers': {
        'console': {
            'level': LOG_LEVEL_CONSOLE,
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        }
    },
    'loggers': {
        '': {
            'handlers': ['console'],
            'level': 'DEBUG'
        }
    }
}

FILE_LOGGING = {
    'file': {
        'level': LOG_LEVEL_FILE,
        'class': 'logging.handlers.RotatingFileHandler',
        'filename': './lighter-data/logs/lighter.log',
        'maxBytes': 1048576,
        'backupCount': 7,
        'formatter': 'verbose'
    }
}

UNLOCK_PERMISSIONS = {
    '/lighter.Unlocker/UnlockLighter': {
        'entity': 'root',
        'action': 'unlock'
    }
}

READ_PERMS = {
    '/lighter.Lightning/ChannelBalance': {
        'entity': 'offchain',
        'action': 'read'
    },
    '/lighter.Lightning/CheckInvoice': {
        'entity': 'invoices',
        'action': 'read'
    },
    '/lighter.Lightning/DecodeInvoice': {
        'entity': 'offchain',
        'action': 'read'
    },
    '/lighter.Lightning/GetInfo': {
        'entity': 'info',
        'action': 'read'
    },
    '/lighter.Lightning/ListChannels': {
        'entity': 'offchain',
        'action': 'read'
    },
    '/lighter.Lightning/ListInvoices': {
        'entity': 'offchain',
        'action': 'read'
    },
    '/lighter.Lightning/ListPayments': {
        'entity': 'offchain',
        'action': 'read'
    },
    '/lighter.Lightning/ListPeers': {
        'entity': 'peers',
        'action': 'read'
    },
    '/lighter.Lightning/ListTransactions': {
        'entity': 'onchain',
        'action': 'read'
    },
    '/lighter.Lightning/WalletBalance': {
        'entity': 'onchain',
        'action': 'read'
    },
}

WRITE_PERMISSIONS = {
    '/lighter.Lightning/CreateInvoice': {
        'entity': 'invoices',
        'action': 'write'
    },
    '/lighter.Lightning/NewAddress': {
        'entity': 'address',
        'action': 'write'
    },
    '/lighter.Lightning/OpenChannel': {
        'entity': 'onchain',
        'action': 'write'
    },
    '/lighter.Lightning/PayInvoice': {
        'entity': 'offchain',
        'action': 'write'
    },
    '/lighter.Lightning/PayOnChain': {
        'entity': 'onchain',
        'action': 'write'
    },
}

INVOICE_PERMS = {
    '/lighter.Lightning/CheckInvoice': {
        'entity': 'invoices',
        'action': 'read'
    },
    '/lighter.Lightning/CreateInvoice': {
        'entity': 'invoices',
        'action': 'write'
    },
    '/lighter.Lightning/GetInfo': {
        'entity': 'info',
        'action': 'read'
    },
}

ALL_PERMS = {**READ_PERMS, **WRITE_PERMISSIONS}
