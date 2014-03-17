import random
import _curve25519
from constants import *
from intbytes import int2bytes, bytes2int
from immutable import ImmutableEnforcerMeta

try:
    from gmpy2 import mpz, invert
    mpz_type = type(mpz())
    has_gmpy = True
except ImportError:
    try:
        from gmpy import mpz, invert
        mpz_type = type(mpz())
        has_gmpy = True
    except ImportError:
        import warnings
        warnings.warn('Not having gmpy2 or gmpy makes this at least 10x slower')
        mpz_type = Integral
        has_gmpy = False

if not has_gmpy:
    def egcd(a, b):
        """The Extended Euclidean Algorithm
        In addition to finding the greatest common divisor (GCD) of the
        arguments, also find and return the coefficients of the linear
        combination that results in the GCD.
        """
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    def invert(a, m):
        """Return the multiplicative inverse of a, mod m"""
        g, x, y = egcd(a, m)
        if g != 1:
            raise ValueError('modular inverse does not exist')
        else:
            return x % m

def modproduct(a, b):
    return int2bytes(bytes2int(a, endian='little') * bytes2int(b, endian='little')\
                     % bytes2int(p, endian='little'),
                     length=32,
                     endian='little')
def modinvert(a):
    return int2bytes(invert(bytes2int(a, endian='little'), bytes2int(p, endian='little')),
                     length=32,
                     endian='little')

class Curve25519ElGamalKey(object):
    __metaclass__ = ImmutableEnforcerMeta
    def __init__(self, _pubkey=None, _seckey=None):
        if _pubkey is not None:
            self.pubkey = _pubkey
            return super(Curve25519ElGamalKey, self).__init__()
        if _seckey is not None:
            self.seckey = _seckey
            return super(Curve25519ElGamalKey, self).__init__()
        raise RuntimeError("Do not directly instantiate Curve25519ElGamalKey objects, use the alternate constructors")

    
    def encrypt(self, message, random=random):
        if (not isinstance(message, basestring)) \
               or len(message) != 32:
            raise ValueError("Message must be a string of length 32")
        # r is a random group element
        r = int2bytes(random.getrandbits(32*8), length=32, endian='little')
        # c1 = g^r
        c1 = _curve25519.curve(r, base)
        # c2 = pubkey^r = g^(seckey * r)
        c2 = _curve25519.curve(r, self.pubkey)
        # c3 = message*c2 = message * g^(seckey * r)
        c3 = modproduct(c2, message)
        return (c1, c3)

    
    def decrypt(self, message):
        c1, d = message
        # c = c1^seckey = g^(seckey * r)
        c = _curve25519.curve(self.seckey, c1)
        # c_prime = c^-1 = g^(seckey * r)^-1
        c_prime = modinvert(c)
        # m = d*c_prime = original * g^(seckey * r) * g^(seckey * r)^-1 = original
        m = modproduct(d, c_prime) 
        return m

    @classmethod
    def from_pubkey(cls, pubkey):
        # TODO: check for bad pubkeys
        return cls(_pubkey=pubkey)
    @classmethod
    def from_seckey(cls, seckey):
        return cls(_seckey=_curve25519.make_private(seckey))

    @property
    def pubkey(self):
        try:
            return self._pubkey
        except AttributeError:
            self.pubkey = _curve25519.make_private(self.seckey)
            return self._pubkey
    @pubkey.setter
    def pubkey(self, pubkey):
        self._pubkey = pubkey

    @property
    def seckey(self):
        return self._seckey
    @seckey.setter
    def seckey(self, seckey):
        self._seckey = seckey


__all__ = ['Curve25519ElGamalKey']
