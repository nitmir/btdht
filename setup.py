#! /usr/bin/env python
import os
from setuptools import setup
from setuptools import Extension
import distutils.command.clean
try:
    from Cython.Build import cythonize
    has_cython = True
except ImportError:
    has_cython = False

c_extensions = [
    Extension("btdht.dht", ["btdht/dht.c"]),
    Extension("btdht.krcp", ["btdht/krcp.c"]),
    Extension("btdht.utils", ["btdht/utils.c"]),
]

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

setup(
    name="btdht",
    version="0.1.1",
    packages = ['btdht'],
    ext_modules = cythonize("btdht/*.pyx") if has_cython else c_extensions,
    include_package_data=True,
    license='GPLv3',
    description="efficent full implementation of the bittorent mainline dht",
    long_description=README,
    author='Valentin Samir',
    author_email='valentin.samir@crans.org',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: C',
        'Programming Language :: Cython',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Communications :: File Sharing'
    ],
    install_requires=["datrie >= 0.7"],
    url='https://github.com/nitmir/btdht/',
    download_url="https://github.com/nitmir/btdht/releases/latest",
    zip_safe=False,
)
