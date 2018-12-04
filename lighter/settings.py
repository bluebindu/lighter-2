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

# Empty variables are set at runtime

IMPLEMENTATION = ''

HOST = '0.0.0.0'
INSECURE_CONN = 0
INSECURE_PORT = '17080'
SECURE_CONN = 0
SECURE_PORT = '17443'
SERVER_KEY = ''
SERVER_CRT = ''

ONE_DAY_IN_SECONDS = 60 * 60 * 24
GRPC_WORKERS = 10
GRPC_GRACE_TIME = 7
RESTART_THROTTLE = 3

ENFORCE = True

TEST_HASH = '43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000'
MAIN_HASH = '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000'

DEFAULT_DESCRIPTION = 'Lighter invoice'

# Cli-based implementations settings
CMD_BASE = []
CMD_TIMEOUT = 30

# Lnd specific settings
LND_ADDR = ''
LND_CREDS = ''

LOG_TIMEFMT = '%Y-%m-%d %H:%M:%S %z'

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
            'format': '%(levelname)s: %(message)s'
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        }
    },
    'loggers': {
        '': {
            'handlers': ['console'],
            'level': 'INFO',
        }
    }
}

FILE_LOGGING = {
    'file': {
        'level': 'INFO',
        'class': 'logging.handlers.RotatingFileHandler',
        'filename': './lighter-data/logs/lighter.log',
        'maxBytes': 1048576,
        'backupCount': 7,
        'formatter': 'verbose'
    }
}
