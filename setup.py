#! /usr/bin/env python

from distutils.core import setup

from smspdu import __version__, __doc__

# perform the setup action
setup(
    name = "smspdu",
    version = __version__,
    description = "SMS PDU encoding and decoding, including GSM-0338 character set",
    long_description = __doc__,
    author = "Richard Jones",
    author_email = "rjones@ekit-inc.com",
    packages = ['smspdu'],
    url = 'http://pypi.python.org/pypi/smspdu',
    classifiers = [
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.11',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: BSD License',
    ],
)

# vim: set filetype=python ts=4 sw=4 et si
