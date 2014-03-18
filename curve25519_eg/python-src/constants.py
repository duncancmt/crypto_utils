# TODO: make use of the fast library functions for modular multiplication and inversion

import _curve25519
from intbytes import int2bytes, bytes2int
from numbers import Integral

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

class Curve25519Point(bytes):
    def __new__(cls, x):
        if isinstance(x, (Integral, mpz_type)):
            x = int2bytes(x, length=32, endian='little')
        if not isinstance(x, bytes):
            raise TypeError("Can only instantiate Curve25519Point instances from integers or bytes")
        return super(Curve25519Point, cls).__new__(cls, x)
    def __mul__(self, other):
        if isinstance(other, Curve25519Point):
            raise TypeError("Points can only be multiplied by elements")
        return Curve25519Point(_curve25519.curve(other, self))
    def __rmul__(self, other):
        return self * other

class Curve25519Element(bytes):
    def __new__(cls, x):
        if isinstance(x, (Integral, mpz_type)):
            x = int2bytes(x % bytes2int(p, endian='little'),
                          length=32,
                          endian='little')
        elif isinstance(x, bytes):
            x = int2bytes(bytes2int(x, endian='little') % bytes2int(p, endian='little'),
                          length=32,
                          endian='little')
        else:
            raise TypeError("Can only instantiate Curve25519Element instances from integers or bytes")
        return super(Curve25519Element, cls).__new__(cls, x)
    def __mul__(self, other):
        if not isinstance(other, Curve25519Element):
            raise TypeError("Multiplication is only defined on Curve25519Element's")
        return Curve25519Element(bytes2int(self, endian='little') * bytes2int(other, endian='little'))
    def __div__(self, other):
        if not isinstance(other, Curve25519Element):
            raise TypeError("Division is only defined on Curve25519Element's")
        return Curve25519Element(bytes2int(self, endian='little')
                                 * invert(bytes2int(other, endian='little'), bytes2int(p, endian='little')))

p = 2**255 - 19
base = 9
bad_public_keys = [0,
                   1,
                   325606250916557431795983626356110631294008115727848805560023387167927233504,
                   39382357235489614581723060781553021112529911719440698176882885853963445705823,
                   p - 1,
                   p,
                   p + 1,
                   p + 325606250916557431795983626356110631294008115727848805560023387167927233504,
                   p + 39382357235489614581723060781553021112529911719440698176882885853963445705823,
                   2*p - 1,
                   2*p,
                   2*p + 1]
p = int2bytes(p, length=32, endian='little')
base = Curve25519Point(base)
bad_public_keys = map(Curve25519Point,
                      bad_public_keys)
    
__all__ = ['p','base','bad_public_keys','Curve25519Point','Curve25519Element']
