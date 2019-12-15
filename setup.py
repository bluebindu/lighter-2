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

""" Module to bundle cliter with setuptools """

import os
import sys

from distutils.command.build_py import build_py as _build_py
from distutils.command.clean import clean as _clean
from distutils.debug import DEBUG
from setuptools import setup
from setuptools.command.develop import develop as _develop

from lighter import __version__

PROTO_FILES = ['lighter/lighter.proto']

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


def generate_proto(source):
    """ Generate python from given source proto file """
    print('Generating proto files')
    if not os.path.exists(source):
        _die('Can\'t find required file: %s\n' % source)
    try:
        from grpc_tools import protoc
        opts = ['-I.', '--python_out=.', '--grpc_python_out=.', source]
        if protoc.main(opts) != 0:
            _die('Failed generation of proto files')
    except ImportError:
        _die('Package grpcio-tools isn\'t installed')


class build_py(_build_py):
    """ Builds Python source """

    def run(self):
        """ Overrides default behavior """
        for proto in PROTO_FILES:
            generate_proto(proto)
        _build_py.run(self)


class clean(_clean):
    """ Cleans up temporary files from build """

    def run(self):
        """ Overrides default behavior """
        for (dirpath, _dirnames, filenames) in os.walk('.'):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                for suffix in CLEANUP_SUFFIXES:
                    if filepath.endswith(suffix):
                        if DEBUG:
                            print('Removing file: "{}"'.format(filepath))
                        os.remove(filepath)
        _clean.run(self)


class develop(_develop):
    """ Defines installation in development mode """

    def run(self):
        """ Overrides default behavior """
        for proto in PROTO_FILES:
            generate_proto(proto)
        super().run()


if __name__ == '__main__':
    if DEBUG:
        print("Started!")

    setup(
        name='cliter',
        version=__version__,
        py_modules=['cliter'],
        packages=['lighter'],
        install_requires=[
            'Click~=7.0',
            'grpcio~=1.25.0',
            'protobuf~=3.9.2',
        ],
        setup_requires=[
            'grpcio-tools~=1.25.0',
        ],
        entry_points={
            'console_scripts': [
                'cliter = cliter:entrypoint'
            ]
        },
        cmdclass={
            'build_py': build_py,
            'clean': clean,
            'develop': develop
        }
    )

    if DEBUG:
        print("Finished!")
