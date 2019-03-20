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
""" Generator of Dockerfiles for building lighter """

import sys

from fileinput import FileInput
from os import environ as env
from re import sub
from shutil import copyfile


def _create_dockerfile(tag_arch):
    """ Creates a Dockerfile for a specific version and tag_arch """
    print('Creating Dockerfile for {}...'.format(tag_arch))
    new_file = 'Dockerfile.{}'.format(tag_arch)
    copyfile('Dockerfile.cross', new_file)
    envs = 'ENV APP_DIR="{}" ENV="{}" VERSION="{}"'.format(
        env['APP_DIR'], env['ENV_DIR'], env['version'])
    install_cmd = ("apt-get update && apt-get -y install g++ "
                   "libffi-dev python3-dev &&")
    clean_cmd = ("&& apt-get clean && "
                 "rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*")
    with FileInput(files=(new_file), inplace=True) as file:
        for line in file:
            line = sub('%%BASEIMAGE_ARCH%%', tag_arch, line.rstrip())
            line = sub('%%ENVS%%', envs, line.rstrip())
            if tag_arch == 'arm32v7':
                line = sub('%%BEFORE_SETUP%%', install_cmd, line.rstrip())
                line = sub('%%AFTER_SETUP%%', clean_cmd, line.rstrip())
            else:
                line = sub('%%BEFORE_SETUP%% ', '', line.rstrip())
                line = sub(' %%AFTER_SETUP%%', '', line.rstrip())
            print(line)
    print('{} created'.format(new_file))


def generate_dockerfiles():
    """ Generates a Dockerfile for each tag_arch """
    try:
        tags_archs = env['tags_archs'].split(' ')
        for tag_arch in tags_archs:
            _create_dockerfile(tag_arch)
    except KeyError as err:
        print('{} environment variable needs to be set'.format(err))
        sys.exit(1)


if __name__ == '__main__':
    generate_dockerfiles()
