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

""" Miscellaneous utils module """

import sys

from argparse import ArgumentParser
from configparser import ConfigParser
from contextlib import contextmanager
from distutils.util import strtobool
from functools import wraps
from glob import glob
from importlib import import_module
from logging import CRITICAL, disable, getLogger, NOTSET
from logging.config import dictConfig
from os import access, mkdir, path, R_OK, W_OK
from pathlib import Path
from shutil import copyfile
from site import USER_BASE
from threading import current_thread

from .. import __version__, settings as sett
from ..migrate import migrate
from .exceptions import InterruptException

LOGGER = getLogger(__name__)


def handle_keyboardinterrupt(func):
    """ Handles KeyboardInterrupt, raising an InterruptException """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            print('\nKeyboard interrupt detected.')
            raise InterruptException

    return wrapper


def handle_thread(func):
    """ Adds and removes async threads from global list """

    @wraps(func)
    def wrapper(*args, **kwargs):
        sett.THREADS.append(current_thread())
        try:
            res = func(*args, **kwargs)
            sett.THREADS.remove(current_thread())
            return res
        except Exception as exc:
            sett.THREADS.remove(current_thread())
            raise exc

    return wrapper


@contextmanager
def disable_logger():
    """
    Disables logging

    Warning: do not nest calls to this method
    """
    disable(CRITICAL)
    try:
        yield
    finally:
        disable(NOTSET)


def copy_config_sample(interactive):
    """ Copies (or asks to copy) config.sample and exits """
    if interactive:
        copy = str2bool(
            input('Missing configuration file, do you want a copy of '
                  'config.sample in the specified location '
                  '({})? [Y/n] '.format(sett.L_CONFIG)),
            force_true=True)
        if not copy:
            die("You'll need to manually create a configuration file")
    else:
        LOGGER.error('Missing config file, copying sample to "%s", '
                     'read doc/configuring.md for details', sett.L_CONFIG)
    sample = get_data_files_path(
        'share/doc/' + sett.PKG_NAME, 'examples/config.sample')
    try:
        copyfile(sample, sett.L_CONFIG)
    except OSError as err:
        die('Error copying sample file: ' + str(err))
    die('Please configure lighter')


def die(message=None):
    """ Prints message to stderr and exits with error code 1 """
    if message:
        sys.stderr.write(message + '\n')
    sys.exit(1)


def get_config_parser(interactive=False):
    """
    Reads config file, settings default values, and returns its parser.
    When config is missing, it copies config.sample in its expected location
    and terminates.
    """
    if not path.exists(sett.L_CONFIG):
        copy_config_sample(interactive)
    config = ConfigParser()
    config.read(sett.L_CONFIG)
    l_values = ['INSECURE_CONNECTION', 'PORT', 'SERVER_KEY', 'SERVER_CRT',
                'LOGS_DIR', 'LOGS_LEVEL', 'DB_DIR', 'MACAROONS_DIR',
                'DISABLE_MACAROONS']
    set_defaults(config, l_values)
    return config


def get_data_files_path(install_dir, relative_path):
    """
    Given a relative path to a data file, returns its absolute path.
    If it detects editable pip install / python setup.py develop, it uses a
    path relative to the source directory (following the .egg-link).
    """
    for base_path in (sys.prefix, USER_BASE, path.join(sys.prefix, 'local')):
        install_path = path.join(base_path, install_dir)
        if path.exists(path.join(install_path, relative_path)):
            return path.join(install_path, relative_path)
        egg_glob = path.join(base_path, 'lib*', 'python*', '*-packages',
                             '{}.egg-link'.format(sett.PIP_NAME))
        egg_link = glob(egg_glob)
        if egg_link:
            with open(egg_link[0], 'r') as f:
                realpath = f.readline().strip()
            if path.exists(path.join(realpath, relative_path)):
                return path.join(realpath, relative_path)
    raise RuntimeError('File "{}" not found'.format(relative_path))


def get_path(ipath, base_path=None):
    """
    Gets absolute posix path. By default relative paths are calculated from
    lighterdir
    """
    ipath = Path(ipath).expanduser()
    if ipath.is_absolute():
        return ipath.as_posix()
    if not base_path:
        base_path = sett.L_DATA
    return Path(base_path, ipath).as_posix()


def handle_importerror(err):
    """ Handles an ImportError """
    LOGGER.debug('Import error: %s', str(err))
    LOGGER.error(
        "Implementation '%s' is not supported", sett.IMPLEMENTATION)
    die()


def handle_sigterm(_signo, _stack_frame):
    """ Handles a SIGTERM, raising an InterruptException """
    raise InterruptException


def init_common(help_msg, core=True, write_perms=False, runtime=False):
    """ Initializes common entrypoints calls """
    _update_logger()
    _parse_args(help_msg, write_perms)
    if write_perms:
        if not access(sett.L_DATA, W_OK):
            raise RuntimeError('Permission denied on ' + sett.L_DATA)
    _init_tree()
    config = get_config_parser()
    _update_logger(config)
    _get_start_options(config, runtime)
    if core:
        migrate()
        # reupdating logger as migrate overrides configuration
        _update_logger(config)


def _update_logger(config=None):
    """
    Activates console logs by default and, when configuration is available,
    activates file logs and sets configured log level
    """
    if config:
        sec = 'lighter'
        logs_level = config.get(sec, 'LOGS_LEVEL').upper()
        sett.LOGGING['handlers']['console']['level'] = logs_level
        sett.LOGGING['loggers']['']['handlers'].append('file')
        sett.LOGGING['handlers'].update(sett.LOGGING_FILE)
        sett.LOGS_DIR = get_path(config.get(sec, 'LOGS_DIR'))
        log_path = path.join(sett.LOGS_DIR, sett.LOGS_LIGHTER)
        sett.LOGGING['handlers']['file']['filename'] = log_path
    try:
        dictConfig(sett.LOGGING)
    except (AttributeError, ImportError, TypeError, ValueError) as err:
        raise RuntimeError('Logging configuration error: ' + str(err))
    getLogger('urllib3').propagate = False


def _parse_args(help_msg, write_perms):
    """ Parses command line arguments """
    parser = ArgumentParser(description=help_msg)
    acc_mode = R_OK
    if write_perms:
        acc_mode = W_OK
    parser.add_argument(
        '--lighterdir', metavar='PATH',
        help="Path containing config file and other data")
    args = vars(parser.parse_args())
    if 'lighterdir' in args and args['lighterdir'] is not None:
        lighterdir = args['lighterdir']
        if not lighterdir:
            raise RuntimeError('Invalid lighterdir: empty path')
        if not path.isdir(lighterdir):
            raise RuntimeError('Invalid lighterdir: path is not a directory')
        if not access(lighterdir, acc_mode):
            raise RuntimeError('Invalid lighterdir: permission denied')
        sett.L_DATA = lighterdir
        sett.L_CONFIG = path.join(sett.L_DATA, 'config')


def _init_tree():
    """ Creates data directory tree if missing """
    _try_mkdir(sett.L_DATA)
    _try_mkdir(path.join(sett.L_DATA, 'certs'))
    _try_mkdir(path.join(sett.L_DATA, 'db'))
    _try_mkdir(path.join(sett.L_DATA, 'logs'))
    _try_mkdir(path.join(sett.L_DATA, 'macaroons'))


def _try_mkdir(dir_path):
    """ Creates a directory if it doesn't exist """
    if not path.exists(dir_path):
        LOGGER.info('Creating dir %s', dir_path)
        mkdir(dir_path)


def _get_start_options(config, runtime):
    """ Sets Lighter and implementation start options """
    sec = 'lighter'
    sett.IMPLEMENTATION = config.get(sec, 'IMPLEMENTATION').lower()
    sett.INSECURE_CONNECTION = str2bool(config.get(sec, 'INSECURE_CONNECTION'))
    sett.DISABLE_MACAROONS = str2bool(config.get(sec, 'DISABLE_MACAROONS'))
    sett.PORT = config.get(sec, 'PORT')
    sett.LIGHTER_ADDR = '{}:{}'.format(sett.HOST, sett.PORT)
    if sett.INSECURE_CONNECTION:
        sett.DISABLE_MACAROONS = True
    sett.SERVER_KEY = get_path(config.get(sec, 'SERVER_KEY'))
    sett.SERVER_CRT = get_path(config.get(sec, 'SERVER_CRT'))
    if sett.DISABLE_MACAROONS:
        LOGGER.warning('Disabling macaroons is not safe, '
                       'do not disable them in production')
    sett.MACAROONS_DIR = get_path(config.get(sec, 'MACAROONS_DIR'))
    sett.DB_DIR = get_path(config.get(sec, 'DB_DIR'))
    sett.DB_PATH = path.join(sett.DB_DIR, sett.DB_NAME)
    # Checks if implementation is supported, could throw an ImportError
    module = import_module('...light_{}'.format(sett.IMPLEMENTATION), __name__)
    if runtime:
        getattr(module, 'get_settings')(config, sett.IMPLEMENTATION)


def set_defaults(config, values):
    """ Sets configuration defaults """
    defaults = {}
    for var in values:
        defaults[var] = getattr(sett, var)
    config.read_dict({'DEFAULT': defaults})


def str2bool(string, force_true=False):
    """ Casts a string to boolean, forcing to a default value """
    try:
        return strtobool(str(string).lower())
    except ValueError:
        return force_true
