#! /usr/bin/env python
import os
from distutils.core import setup
from distutils.extension import Extension
import distutils.command.clean
from Cython.Distutils import build_ext


class clean(distutils.command.clean.clean):
    def run(self):
        distutils.command.clean.clean.run(self)
        files = ["btdht/dht.c", "btdht/krcp.c", "btdht/utils.c"]
        for file in files:
            if os.path.exists(file):
                os.remove(file)
extensions = [
    Extension("btdht.dht", ["btdht/dht.pyx"],
        include_dirs = ["btdht/"],
    ),
    Extension("btdht.krcp", ["btdht/krcp.pyx"],
        include_dirs = ["btdht/"],
    ),
    Extension("btdht.utils", ["btdht/utils.pyx"],
        include_dirs = ["btdht/"],
    ),
]

setup(
    name="btdht",
    version="0.1",
    description="efficency full implementation of the bittorent mainline dht",
    url='https://github.com/nitmir/btdht/',
    packages = ['btdht'],
    cmdclass={'clean':clean, 'build_ext': build_ext},
    ext_modules = extensions,

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Cython',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
