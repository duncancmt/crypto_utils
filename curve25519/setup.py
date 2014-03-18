#! /usr/bin/python

from struct import calcsize
from subprocess import Popen, PIPE
from distutils.core import setup, Extension

version = Popen(["git", "describe", "--tags"], stdout=PIPE).communicate()[0]\
          .strip().decode("utf8")
if len(version) == 0 or version.startswith('fatal'):
    version = '0.0.0'

if calcsize("P") == 8: # 64-bit platform
    ext_modules = [Extension("curve25519._curve25519",
                             ["curve25519module.c",
                              "curve25519-donna-c64.c"],
                             )]
elif calcsize("P") == 4: # 32-bit platform
    ext_modules = [Extension("curve25519._curve25519",
                             ["curve25519module.c",
                              "curve25519-donna.c"],
                             )]
else:
    raise Exception("This module is only supported on 32-bit and 64-bit platforms")


short_description="Python wrapper for the Curve25519 cryptographic library"
long_description="""\
Curve25519 is a fast elliptic-curve key-agreement protocol, in which two
parties Alice and Bob each generate a (public,private) keypair, exchange
public keys, and can then compute the same shared key. Specifically, Alice
computes F(Aprivate, Bpublic), Bob computes F(Bprivate, Apublic), and both
get the same value (and nobody else can guess that shared value, even if they
know Apublic and Bpublic).

This is a Python wrapper for the portable 'curve25519-donna' implementation
of this algorithm, written by Adam Langley, hosted at
http://code.google.com/p/curve25519-donna/. Python wrapper originally by
Brian Warner, substantially modified by Duncan Townsend.
"""

setup(name="curve25519-donna",
      version=version,
      description=short_description,
      long_description=long_description,
      author="Duncan Townsend",
      author_email="duncant@mit.edu",
      license="BSD",
      packages=["curve25519"], # "curve25519.test"
      package_dir={"curve25519": "python-src"},
      ext_modules=ext_modules,
      )
