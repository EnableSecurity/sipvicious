#!/usr/bin/env python
# vim: set fileencoding=utf-8 :
#
#       sipvicius/setup.py
#       Copyright 2010 - 2017 Sapian SAS <sebastian.rojo@sapian.com.co>,
#       Copyright 2010 - 2017 Sapian SAS <arpagon <arpagon@gmail.com.co>
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.

from sipvicius.libs.svhelper import __author__, __version__
from setuptools import setup, find_packages

setup(name='sipvicius',
    version=__version__,
    description='''SIPVicious suite is a set of tools that can be used to audit SIP based VoIP systems. 
    ''',
    author=__author__,
    author_email='sandro@enablesecurity.com',
    url='http://sipvicious.org',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'sipvicius_svmap = sipvicius.svmap:main',
            'sipvicius_svwar = sipvicius.svwar:main',
            'sipvicius_svcrack = sipvicius.svcrack:main',
            'sipvicius_svreport = sipvicius.svreport:main',
            'sipvicius_svcrash = sipvicius.svcrash:main',
            ]
    },
)
