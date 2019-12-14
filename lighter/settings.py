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
# Some variables contain default values, could be overwritten

IMPLEMENTATION = ''

L_DATA = './lighter-data'

HOST = '0.0.0.0'
PORT = '1708'
LIGHTER_ADDR = ''
INSECURE_CONNECTION = 0
SERVER_KEY = path.join(L_DATA, 'certs/server.key')
SERVER_CRT = path.join(L_DATA, 'certs/server.crt')
CERTS_DIR = path.join(L_DATA, 'certs')
IMPLEMENTATION_SECRETS = False
IMPL_SEC_TYPE = ''

# Macaroons settings
RUNTIME_BAKER = None
DISABLE_MACAROONS = 0
MACAROONS_DIR = path.join(L_DATA, 'macaroons')
MAC_ADMIN = 'admin.macaroon'
MAC_READONLY = 'readonly.macaroon'
MAC_INVOICES = 'invoices.macaroon'

# Security settings
MAC_ROOT_KEY = None
SALT_LEN = 32
ACCESS_TOKEN = b'lighter'
PASSWORD_LEN = 12
ENTROPY_BLOCKING = 1
SCRYPT_PARAMS = {
    'cost_factor': 2**15,
    'block_size_factor': 8,
    'parallelization_factor': 1,
    'key_len': 32
}

# DB settings
DB_DIR = path.join(L_DATA, 'db')
DB_NAME = 'lighter.db'
ALEMBIC_CFG = 'migrations/alembic.ini'

# Server settings
ONE_DAY_IN_SECONDS = 60 * 60 * 24
GRPC_WORKERS = 10
GRPC_GRACE_TIME = 40
UNLOCKER_STOP = False
RUNTIME_SERVER = None
THREADS = []

# cliter settings
CLI_HOST = '127.0.0.1'
CLI_ADDR = ''
CLI_TIMEOUT = 10
CLI_INSECURE_CONNECTION = 0
CLI_DISABLE_MACAROONS = 0
CLI_CRT = ''
CLI_MAC = ''

ENFORCE = True

TEST_HASH = '43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'
MAIN_HASH = '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000'

# CLI-based implementations settings
CMD_BASE = []

# RPC-based implementations settings
RPC_URL = ''
RPC_TRIES = 5
RPC_SLEEP = .5
RPC_CONN_TIMEOUT = 3.1

# c-lightning specific settings
CL_CLI = 'lightning-cli'
CL_RPC = 'lightning-rpc'

# eclair specific settings
ECL_HOST = 'localhost'
ECL_PORT = 8080
ECL_PASS = ''

# electrum specific settings
ELE_HOST = 'localhost'
ELE_PORT = 7777
ELE_USER = 'user'
ELE_RELEASED_ADDRESSES = []

# lnd specific settings
LND_HOST = 'localhost'
LND_PORT = 10009
LND_CERT = 'tls.cert'
LND_ADDR = ''
LND_CREDS_SSL = ''
LND_CREDS_FULL = ''
LND_MAC = ''

# Common settings
IMPL_MIN_TIMEOUT = 2
IMPL_MAX_TIMEOUT = 180
RESPONSE_RESERVED_TIME = 0.3
THREAD_TIMEOUT = 3
CLOSE_TIMEOUT_NODE = 15
MAX_INVOICES = 200
INVOICES_TIMES = 3
EXPIRY_TIME = 420
DUST_LIMIT_SAT = 546

# Logging settings
LOGS_DIR = path.join(L_DATA, 'logs')
LOGS_LIGHTER = 'lighter.log'
LOGS_MIGRATIONS = 'migrations.log'
LOG_TIMEFMT = '%Y-%m-%d %H:%M:%S %z'
LOG_TIMEFMT_SIMPLE = '%d %b %H:%M:%S'
LOGS_LEVEL = 'INFO'
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
            'level': LOGS_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'level': LOG_LEVEL_FILE,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': path.join(LOGS_DIR, LOGS_LIGHTER),
            'maxBytes': 1048576,
            'backupCount': 7,
            'formatter': 'verbose'
        }
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG'
        },
    }
}

ALL_PERMS = {
    '/lighter.Lightning/ChannelBalance': {
        'entity': 'balance',
        'action': 'read'
    },
    '/lighter.Lightning/CheckInvoice': {
        'entity': 'invoice',
        'action': 'read'
    },
    '/lighter.Lightning/CloseChannel': {
        'entity': 'channel',
        'action': 'write'
    },
    '/lighter.Lightning/CreateInvoice': {
        'entity': 'invoice',
        'action': 'write'
    },
    '/lighter.Lightning/DecodeInvoice': {
        'entity': 'invoice',
        'action': 'read'
    },
    '/lighter.Lightning/GetInfo': {
        'entity': 'info',
        'action': 'read'
    },
    '/lighter.Lightning/ListChannels': {
        'entity': 'channel',
        'action': 'read'
    },
    '/lighter.Lightning/ListInvoices': {
        'entity': 'invoice',
        'action': 'read'
    },
    '/lighter.Lightning/ListPayments': {
        'entity': 'payment',
        'action': 'read'
    },
    '/lighter.Lightning/ListPeers': {
        'entity': 'peer',
        'action': 'read'
    },
    '/lighter.Lightning/ListTransactions': {
        'entity': 'transaction',
        'action': 'read'
    },
    '/lighter.Locker/LockLighter': {
        'entity': 'lock',
        'action': 'write'
    },
    '/lighter.Lightning/NewAddress': {
        'entity': 'address',
        'action': 'write'
    },
    '/lighter.Lightning/OpenChannel': {
        'entity': 'channel',
        'action': 'write'
    },
    '/lighter.Lightning/PayInvoice': {
        'entity': 'payment',
        'action': 'write'
    },
    '/lighter.Lightning/PayOnChain': {
        'entity': 'transaction',
        'action': 'write'
    },
    '/lighter.Lightning/UnlockNode': {
        'entity': 'unlock',
        'action': 'write'
    },
    '/lighter.Lightning/WalletBalance': {
        'entity': 'balance',
        'action': 'read'
    },
}

READ_PERMS = [
    {
        'entity': 'balance',
        'action': 'read'
    },
    {
        'entity': 'channel',
        'action': 'read'
    },
    {
        'entity': 'info',
        'action': 'read'
    },
    {
        'entity': 'invoice',
        'action': 'read'
    },
    {
        'entity': 'payment',
        'action': 'read'
    },
    {
        'entity': 'peer',
        'action': 'read'
    },
    {
        'entity': 'transaction',
        'action': 'read'
    },
]

INVOICE_PERMS = [
    {
        'entity': 'channel',
        'action': 'read'
    },
    {
        'entity': 'info',
        'action': 'read'
    },
    {
        'entity': 'invoice',
        'action': 'read'
    },
    {
        'entity': 'invoice',
        'action': 'write'
    },
    {
        'entity': 'peer',
        'action': 'read'
    },
]
