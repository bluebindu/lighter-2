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

""" Module to bundle Lighter with setuptools """

import sys

from distutils.command.build_py import build_py
from distutils.command.clean import clean
from importlib import import_module
from os import chdir, chmod, path, remove, stat, walk
from pathlib import Path
from shutil import move, rmtree, which
from stat import S_IXGRP, S_IXOTH, S_IXUSR
from subprocess import Popen, TimeoutExpired
from urllib.request import urlretrieve
from zipfile import ZipFile

from pkg_resources import resource_filename
from setuptools import setup
from setuptools.command.develop import develop
from setuptools.command.test import test as TestCommand

L_DIR = 'lighter_bitcoin'
E_DIR = 'examples'
__version__ = getattr(import_module(L_DIR), '__version__')
PKG_NAME = getattr(import_module(L_DIR + '.settings'), 'PKG_NAME')
PIP_NAME = getattr(import_module(L_DIR + '.settings'), 'PIP_NAME')
L_PROTO = 'lighter.proto'

CLI_NAME = 'cliter'
SHELLS = ['bash', 'zsh']

CL_VER = '0.8.0'

LND_REF = 'v0.8.2-beta'
LND_PROTO = 'rpc.proto'
GOOGLE = 'google'
GAPIS = 'googleapis'
GAPIS_MASTER = GAPIS + '-master'
GAPIS_ZIP = GAPIS + '.zip'

CLEANUP_SUFFIXES = [
    '_pb2.py',
    '_pb2_grpc.py',
    '.pyc',
    '.so',
    '.o',
]


def _die(message):
    """ Prints message to stderr with error code 1 """
    sys.stderr.write(message)
    sys.exit(1)


def _try_rm(tree):
    """ Tries to remove a directory or file, without failing if missing """
    try:
        rmtree(tree)
    except OSError:
        pass
    try:
        remove(tree)
    except OSError:
        pass


def _download_lnd_deps():
    """
    Downloads lnd's proto file for the supported version and googleapis
    """
    chdir(L_DIR)
    lnd_url = 'https://raw.githubusercontent.com/lightningnetwork/lnd'
    urlretrieve('{}/{}/lnrpc/{}'.format(lnd_url, LND_REF, LND_PROTO),
                LND_PROTO)
    googleapis_url = \
        'https://github.com/{}/{}/archive/master.zip'.format(GAPIS, GAPIS)
    urlretrieve(googleapis_url, GAPIS_ZIP)
    with ZipFile(GAPIS_ZIP, 'r') as zip_ref:
        start_member = GAPIS_MASTER + '/google/'
        files = [n for n in zip_ref.namelist() if n.startswith(start_member) and not n.endswith('/')]
        zip_ref.extractall('.', members=files)
    _try_rm(GAPIS_ZIP)
    if path.exists(GOOGLE):
        rmtree(GOOGLE)
    move(path.sep.join([GAPIS_MASTER, GOOGLE]), GOOGLE)
    _try_rm(GAPIS_MASTER)
    chdir('..')


def _gen_cli_completion(shell):
    """ Generates CLI completion files for bash and zsh """
    if not which(shell):
        Path(COMPLETION_SCRIPTS[shell]).touch()
        return
    source = 'source'
    if shell == 'zsh':
        source = 'source_zsh'
    cmd = [shell, '-c', '_{}_COMPLETE={} {} > {}'.format(
        CLI_NAME.upper(), source, CLI_NAME, COMPLETION_SCRIPTS[shell])]
    proc = Popen(cmd)
    try:
        _, _ = proc.communicate(timeout=10)
    except TimeoutExpired:
        proc.kill()
    status = stat(COMPLETION_SCRIPTS[shell])
    chmod(COMPLETION_SCRIPTS[shell],
          status.st_mode | S_IXUSR | S_IXGRP | S_IXOTH)


def _gen_proto(opts):
    """ Generates python code from given proto file """
    print('Generating proto files from', opts[-1])
    if not path.exists(opts[-1]):
        _die("Can't find required file: " + opts[-1])
    try:
        from grpc_tools.protoc import main as run_protoc
        if run_protoc(opts) != 0:
            _die('Failed generation of proto files')
    except ImportError:
        _die('Package grpcio-tools isn\'t installed')


def _build_lighter():
    """ Downloads and builds Lighter dependencies and shell completions """
    _download_lnd_deps()
    opts = ['--proto_path=.', '--python_out=.', '--grpc_python_out=.',
            path.sep.join([L_DIR, L_PROTO])]
    _gen_proto(opts)
    proto_include = resource_filename('grpc_tools', '_proto')
    opts = [__file__, '--proto_path=.', '--proto_path=' + L_DIR,
            '--proto_path=' + proto_include,
            '--python_out=.', '--grpc_python_out=.',
            path.sep.join([L_DIR, LND_PROTO])]
    _gen_proto(opts)
    _try_rm(path.sep.join([L_DIR, GOOGLE]))
    chdir(E_DIR)
    _gen_cli_completion('bash')
    _gen_cli_completion('zsh')
    chdir('..')


class Clean(clean):
    """ Cleans up generated and downloaded files """

    def run(self):
        """ Overrides default behavior """
        for (dirpath, _dirnames, filenames) in walk('.'):
            _try_rm(path.sep.join([dirpath, '__pycache__']))
            for filename in filenames:
                filepath = path.join(dirpath, filename)
                for suffix in CLEANUP_SUFFIXES:
                    if filepath.endswith(suffix):
                        print('Removing file: "{}"'.format(filepath))
                        remove(filepath)
        for shell in SHELLS:
            _try_rm(path.sep.join([E_DIR, COMPLETION_SCRIPTS[shell]]))
        for report in Path('reports').glob('*.report'):
            _try_rm(report.as_posix())
        _try_rm(path.sep.join([L_DIR, GAPIS_MASTER]))
        _try_rm(path.sep.join([L_DIR, GAPIS_ZIP]))
        _try_rm(path.sep.join([L_DIR, GOOGLE]))
        _try_rm(path.sep.join([L_DIR, LND_PROTO]))
        _try_rm('dist')
        _try_rm('.eggs')
        _try_rm('.coverage')
        _try_rm(L_DIR + '.egg-info')
        _try_rm('.pytest_cache')
        clean.run(self)


class BuildPy(build_py):
    """ Builds Python source """

    def run(self):
        """ Overrides default behavior """
        build_py.run(self)
        _build_lighter()


class Develop(develop):
    """ Defines installation in development mode """

    def run(self):
        """ Overrides default behavior """
        super().run()
        _build_lighter()


class PyTest(TestCommand):
    """ Runs unit tests (deprecated) """

    def initialize_options(self):
        """ Overrides default behavior """
        TestCommand.initialize_options(self)
        self.pytest_args = ['-v', '--cov=' + L_DIR,
                            '--cov-report=term-missing']

    def finalize_options(self):
        """ Overrides default behavior """
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        """ Overrides default behavior """
        _build_lighter()
        from pytest import main as run_pytest
        errno = run_pytest(self.pytest_args)
        sys.exit(errno)

LONG_DESC = ''
with open('README.md', encoding='utf-8') as f:
    LONG_DESC = f.read()

COMPLETION_SCRIPTS = {}
for SHELL in SHELLS:
    COMPLETION_SCRIPTS[SHELL] = 'complete-{}-{}.sh'.format(CLI_NAME, SHELL)

EXAMPLES = [path.as_posix() for path in Path(E_DIR).glob('*')] + \
    [path.sep.join([E_DIR, COMPLETION_SCRIPTS[shell]]) for shell in SHELLS]
DOC = [path.as_posix() for path in Path('.').glob('*.md')] + \
    [path.as_posix() for path in Path('doc').glob('*.md')]

MIGRATIONS_DIR = path.sep.join([L_DIR, 'migrations'])
MGR_VERSIONS_DIR = path.sep.join([MIGRATIONS_DIR, 'versions'])

setup(
    name=PIP_NAME,
    version=__version__,
    description='The Lightning Network node wrapper - enabling the 3rd '
                'layer with consensus on the 2nd',
    long_description=LONG_DESC,
    long_description_content_type='text/markdown',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Affero General Public License v3 '
        'or later (AGPLv3+)',
        'Natural Language :: English',
        'Operating System :: MacOS',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Other/Nonlisted Topic',
    ],
    keywords='lighter ln lightning network cliter wrapper',
    url='https://gitlab.com/inbitcoin/lighter',
    author='inbitcoin',
    author_email='lightning@inbitcoin.it',
    license='AGPLv3',
    packages=[L_DIR, MIGRATIONS_DIR, MGR_VERSIONS_DIR],
    include_package_data=True,
    package_data={
        L_DIR: ['migrations/alembic.ini', L_PROTO],
    },
    data_files=[
        ('share/doc/{}/{}'.format(PKG_NAME, E_DIR), EXAMPLES),
        ('share/doc/{}'.format(PKG_NAME), DOC),
    ],
    python_requires='>=3.5',
    install_requires=[
        'alembic~=1.2.1',
        'Click~=7.0',
        'googleapis-common-protos~=1.6.0',
        'grpcio~=1.26.0',
        'macaroonbakery~=1.2.3',
        'protobuf~=3.11.2',
        'pylibscrypt~=1.8.0',
        'pyln-client==' + CL_VER,
        'pymacaroons~=0.13.0',
        'pynacl~=1.3.0',
        'qrcode~=6.1',
        'requests~=2.22.0',
        'SQLAlchemy~=1.3.10',
    ],
    setup_requires=[
        'grpcio-tools~=1.26.0',
    ],
    tests_require=[
        'pytest', 'pytest-cov',
    ],
    entry_points={
        'console_scripts': [
            'cliter = {}.cliter:entrypoint'.format(L_DIR),
            'lighter = {}.lighter:start'.format(L_DIR),
            'lighter-pairing = {}.pairing:start'.format(L_DIR),
            'lighter-secure = {}.secure:secure'.format(L_DIR),
        ]
    },
    cmdclass={
        'build_py': BuildPy,
        'clean': Clean,
        'develop': Develop,
        'test': PyTest,
    }
)
