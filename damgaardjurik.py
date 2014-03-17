import random
from math import ceil, floor, log
from fractions import gcd
from numbers import Integral
from copy import deepcopy
from primes import gen_prime
from intbytes import int2bytes, bytes2int
from noconflict import classmaker
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

def lcm(a,b):
    """Return the least common multiple (LCM) of the arguments"""
    return (a * b) // gcd(a,b)

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



class DamgaardJurik(object):
    """
    Class implementing the Damgaard-Jurik family of asymmetric cryptosystems

    The Paillier cryptosystem is a specific instance of this cryptosystem with s=1
    """
    __metaclass__ = ImmutableEnforcerMeta
    def __init__(self, keylen=None, random=random, _state=None):
        """Constructor:

        keylen: the length (in bits) of the key modulus
            (the key modulus may be 1 bit longer than specified, but keylen is the minimum)
        random: (optional) a source of entropy for key generation, the default is python's random
        _state: (do not use) a state tuple to initialize from instead of performing key generation
        """
        if _state is not None:
            # initialize self from given state
            (n, l) = _state
            if has_gmpy:
                n = mpz(n)
                if l is not None:
                    l = mpz(l)
            self.n = n
            self.l = l
        else:
            # generate key and initialize self
            if keylen is None:
                raise TypeError('You must specify the keylength when initializing a DamgaardJurik instance')
            self.generate(keylen, random=random)

    def generate(self, keylen, random=random):
        """Generate a keypair and initialize this instance with it

        random: (optional) a source of entropy for key generation, the default is python's random
        """
        p = gen_prime(int(floor(keylen / 2.0 + 1)), random=random)
        q = gen_prime(int(ceil(keylen / 2.0)), random=random)

        n = p * q
        l = lcm(p-1, q-1)
        if has_gmpy:
            n = mpz(n)
            l = mpz(l)
        self.n = n
        self.l = l

    def encrypt(self, message, s=None, random=random, ciphertext_args=dict()):
        """Encrypt a message with the public key

        message: the message to be encrypted, must be a DamgaardJurikPlaintext instance
        s: (optional) one less than the exponent of the modulus. Determines the maximum message length.
            If s is None (the default), automatically choose the minimum s that will fit the message.
            WARNING: setting s=None opens you up to some serious timing attacks
        random: (optional) a source of entropy for the generation of r, a parameter for the encryption
            the default is python's random
        ciphertext_args: (optional) keyword arguments to be supplied to the DamgaardJurikCiphertext
            instance that this method returns
        """

        if not isinstance(message, DamgaardJurikPlaintext):
            raise TypeError('Before encryption, convert messages to DamgaardJurikPlaintext instances')

        # format the message as an integer
        i = int(message)

        if s is None: # determine s from message length
            try:
                s = int(ceil(log(i, int(self.n))))
                s = max(s, 1) # i == 1
            except ValueError:
                # stupid edge cases
                assert i == 0
                s = 1
        if i >= self.n**s: # check that the message will fit with the given s
            raise ValueError('message value is too large for the given value of s')

        # utility constants
        ns = self.n**s
        ns1 = ns*self.n

        # generate the random parameter r
        r = random.randint(1, ns1-1)

        # perform the encryption
        c = pow((1+self.n), i, ns1)
        c *= pow(r, ns, ns1)
        c %= ns1

        # format the ciphertext as DamgaardJurikCiphertext
        return DamgaardJurikCiphertext(c, self, **ciphertext_args)

    def decrypt(self, message):
        """Decrypt and encrypted message. Only works if this instance has a private key available.

        message: the message to be decrypted, must be a DamgaardJurikCiphertext instance
        """
        # check that the private key is available
        if self.l is None:
            raise RuntimeError('This key has no private material for decryption')

        if not isinstance(message, DamgaardJurikCiphertext):
            raise TypeError('Data for decryption must be formatted as DamgaardJurikCiphertext instance')

        # format the ciphertext as an integer, regardless of the given type
        c = int(message)

        # determine s from the message length
        s = int(ceil(log(c, int(self.n)) - 1))
        assert s > 0

        # utility constants
        ns = self.n**s
        ns1 = ns*self.n
        assert c < ns1

        # calculate the decryption key for the given s
        d = invert(self.l, ns) * self.l
        assert d % ns == 1
        assert d % self.l == 0

        # perform the decryption
        c = pow(c, d, ns1)
        i = 0
        for j in xrange(1, s+1):
            nj = self.n**j
            nj1 = nj*self.n
            t1 = ((c % nj1) - 1) / self.n
            t2 = i
            kfac = 1
            for k in xrange(2, j+1):
                kfac *= k
                i -= 1

                t2 *= i
                t2 %= nj
                
                t1 -= (t2 * self.n ** (k - 1)) * invert(kfac, nj)
                t1 %= nj
            i = t1

        # format the plaintext to match the type of the ciphertext
        return DamgaardJurikPlaintext(i)

    @property
    def keylen(self):
        return self.n.bit_length()
    @property
    def pubkey(self):
        return int(self.n)
    @property
    def privkey(self):
        return (int(self.n), int(self.l))

    @property
    def n(self):
        return self._n
    @n.setter
    def n(self, value):
        self._n = value
    @property
    def l(self):
        return self._l
    @l.setter
    def l(self, value):
        self._l = value

    @classmethod
    def from_pubkey(cls, pubkey):
        return cls(_state=(pubkey, None))
    @classmethod
    def from_privkey(cls, privkey):
        return cls(_state=privkey)

    def __getstate__(self):
        return self.privkey
    def __setstate__(self, state):
        self.__init__(_state=state)

    def __hash__(self):
        return hash((int(self.n), int(self.l)))
    def __eq__(self, other):
        return self.n == other.n and self.l == other.l
    def __ne__(self, other):
        return self.n != other.n or self.l != other.l

class DamgaardJurikPlaintext(long):
    """Class representing the plaintext in Damgaard-Jurik"""
    def __new__(cls, n):
        if isinstance(n, bytes):
            n = bytes2int(n) | (1 << len(n)*8)
            return cls(n)
        else:
            return super(DamgaardJurikPlaintext, cls).__new__(cls, n)
    def __repr__(self):
        return 'DamgaardJurikPlaintext(%s)' % repr(int(self))
    def __str__(self):
        retval = int2bytes(self)
        if retval[-1] != '\x01':
            raise ValueError('Invalid padding for conversion to str')
        return retval[:-1]

class DamgaardJurikCiphertextBase(object):
    __metaclass__ = ImmutableEnforcerMeta
class DamgaardJurikCiphertext(DamgaardJurikCiphertextBase, Integral):
    """Class representing the ciphertext in Damgaard-Jurik. Also represents the homomorphisms of Damgaard-Jurik"""
    __metaclass__ = classmaker()
    def __init__(self, c, key, cache=True, bucket_size=5):
        """Constructor:

        c: the ciphertext, represented as an integer type
        ns1: the exponentiated modulus used in generating this ciphertext
        cache: (optional) if True, we cache the powers of the ciphertext
            this speeds up the square-and-multiply exponentiation used if
            lots of homomorphic manipulation takes place, the default is True
        bucket_size: (optional) only has an effect if cache=True, number of bits
            per bucket in the cache of powers, default 5
        """
        if isinstance(c, bytes):
            c = bytes2int(c)
        elif isinstance(c, (Integral, mpz_type)):
            pass
        else:
            raise TypeError('Expected argument c to be an integer')

        if not isinstance(key, DamgaardJurik):
            raise TypeError('Expected argument key to be a DamgaardJurik instance')
        self.key = key

        s = int(ceil(log(int(c), int(self.key.n)) - 1))
        ns1 = self.key.n ** (s + 1)
        if has_gmpy:
            c = mpz(c)
            ns1 = mpz(ns1)
        self.c = c
        self.s = s
        self.ns1 = ns1
        if bucket_size > 8:
            import warnings
            warnings.warn("Setting bucket_size > 8 allows timing attacks based on Python's handling of small integers")
        self.bucket_size = bucket_size
        if cache:
            self.cache = [ [ None
                             for _ in xrange((2**self.bucket_size)) ]
                           for __ in xrange(int(ceil(self.ns1.bit_length()/float(self.bucket_size)))) ]
        else:
            self.cache = None

    @property
    def c(self):
        return self._c
    @c.setter
    def c(self, value):
        self._c = value

    @property
    def key(self):
        return self._key
    @key.setter
    def key(self, value):
        self._key = value

    @property
    def s(self):
        return self._s
    @s.setter
    def s(self, value):
        self._s = value

    @property
    def ns1(self):
        return self._ns1
    @ns1.setter
    def ns1(self, value):
        self._ns1 = value

    @property
    def cache(self):
        return self._cache
    @cache.setter
    def cache(self, value):
        self._cache = value

    def populate_cache(self):
        """When caching of powers is enabled, populate the cache as appropriate.
        If the cache is not enabled, raises RuntimeError
        """
        if self.cache is None:
            raise RuntimeError("Tried to populate the cache of a DamgaardJurikCiphertext instance without a cache")
        elif self.cache[0][1] is None:
            self.cache[0][1] = self.c
            base = self.c
            for i, bucket in enumerate(self.cache):
                if i != 0:
                    bucket[1] = self.cache[i-1][-1]
                    bucket[1] *= base
                    bucket[1] %= self.ns1
                base = bucket[1]
                # assert base == pow(self.c, 2**(self.bucket_size*i), self.ns1)
                for j in xrange(2,len(bucket)):
                    bucket[j] = bucket[j-1]
                    bucket[j] *= base
                    bucket[j] %= self.ns1
                    # assert bucket[j] % self.ns1 == pow(self.c, 2**(self.bucket_size*i)*j, self.ns1)

    def wrap(self, other):
        """Convert an integer to a DamgaardJurikCiphertext instance with the
        same arguments as this instance.
        """
        return type(self)(other, self.key, self.cache is not None, self.bucket_size)
    def convert(self, i):
        """Encrypt an integer with the same key as this instance"""
        # it doesn't matter that r is chosen using a bad RNG because it will
        # be combined with our r that is chosen using a good RNG
        return self.key.encrypt(DamgaardJurikPlaintext(i), s=self.s)

    def __repr__(self):
        return 'DamgaardJurikCiphertext(%d, %s, cache=%s, bucket_size=%d)' \
               % (int(self.c), repr(self.key), self.cache is not None, self.bucket_size)
    def __str__(self):
        return int2bytes(self.c)

    def __add__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            if self.key is not other.key or self.s != other.s or self.ns1 != other.ns1:
                raise ValueError('Cannot add ciphertexts that belong to different keys')
            return self.wrap(self.c * other.c % self.ns1)
        else:
            # other is a int or long
            other = self.convert(other)
            return self + other
    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            if self.key is not other.key or self.s != other.s or self.ns1 != other.ns1:
                raise ValueError('Cannot subtract ciphertexts that belong to different keys')
            return self.wrap(self.c * invert(other.c, self.ns1) % self.ns1)
        else:
            # other is a int or long
            other = self.convert(other)
            return self - other
    def __rsub__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            if self.key is not other.key or self.s != other.s or self.ns1 != other.ns1:
                raise ValueError('Cannot subtract ciphertexts that belong to different keys')
            return self.wrap(other.c * invert(self.c, self.ns1) % self.ns1)
        else:
            # other is a int or long
            other = self.convert(other)
            return other - self
        
    def __mul__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            raise TypeError("It is nonsense to try to multiply ciphertexts. You can only multiply ciphertexts by normal integers")
        other %= self.ns1
        if self.cache is None:
            return self.wrap(pow(self.c, other, self.ns1))
        else:
            # perform the cache-accelerated exponentiation
            self.populate_cache()
            retval = 1
            garbage = 1
            for i, b in ( (i, (other >> (i * self.bucket_size)) & ((1 << self.bucket_size) - 1))
                          for i in xrange(int(ceil(other.bit_length() / float(self.bucket_size)))) ):
                j = random.randrange(1,len(self.cache[i])) # TODO: use a better random generator
                if b == 0:
                    garbage *= self.cache[i][j]
                    garbage %= self.ns1
                if b != 0:
                    retval *= self.cache[i][b]
                    retval %= self.ns1
                garbage = deepcopy(retval)
            return self.wrap(retval)
    def __rmul__(self, other):
        return self * other

    def __div__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            raise TypeError("It is nonsense to try to divide ciphertexts. You can only divide ciphertexts by normal integers")
        return self * invert(other, self.ns1)
    def __truediv__(self, other):
        return self.__div__(other)
    def __rdiv__(self, other):
        raise NotImplementedError
    def __rtruediv__(self, other):
        raise NotImplementedError

    def __mod__(self, other):
        raise NotImplementedError
    def __divmod__(self, other):
        raise NotImplementedError
    def __floordiv__(self, other):
        raise NotImplementedError
    def __rmod__(self, other):
        raise NotImplementedError
    def __rdivmod__(self, other):
        raise NotImplementedError
    def __rfloordiv__(self, other):
        raise NotImplementedError

    def __neg__(self):
        return self.wrap(invert(self.c, self.ns1))
    def __pos__(self):
        return self

    def __hash__(self):
        return hash((int(self.c), self.key, int(self.s), int(self.ns1)))
    def __lt__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            return self.c < other.c
        else:
            return self.c < other
    def __le__(self, other):
        return not self > other
    def __eq__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            return self.c == other.c
        else:
            return self.c == other
    def __ne__(self, other):
        return not self == other
    def __gt__(self, other):
        if isinstance(other, DamgaardJurikCiphertext):
            return self.c > other.c
        else:
            return self.c > other
    def __ge__(self, other):
        return not self < other

    def __int__(self):
        return int(self.c)
    def __trunc__(self):
        return int(self)
    def __long__(self):
        return long(int(self))
    def __float__(self):
        return float(int(self))
    def __complex__(self):
        return complex(int(self))

    def __and__(self, other):
        return NotImplemented
    def __xor__(self, other):
        return NotImplemented
    def __or__(self, other):
        return NotImplemented
    def __pow__(self, other):
        return NotImplemented
    def __lshift__(self, other):
        return NotImplemented
    def __rshift__(self, other):
        return NotImplemented
    def __rand__(self, other):
        return NotImplemented
    def __rxor__(self, other):
        return NotImplemented
    def __ror__(self, other):
        return NotImplemented
    def __rpow__(self, other):
        return NotImplemented
    def __rlshift__(self, other):
        return NotImplemented
    def __rrshift__(self, other):
        return NotImplemented

    def __iadd__(self, other):
        return NotImplemented
    def __isub__(self, other):
        return NotImplemented
    def __imul__(self, other):
        return NotImplemented
    def __idiv__(self, other):
        return NotImplemented
    def __itruediv__(self, other):
        return NotImplemented
    def __ifloordiv__(self, other):
        return NotImplemented
    def __imod__(self, other):
        return NotImplemented
    def __ipow__(self, other):
        return NotImplemented
    def __ilshift__(self, other):
        return NotImplemented
    def __irshift__(self, other):
        return NotImplemented
    def __iand__(self, other):
        return NotImplemented
    def __ixor__(self, other):
        return NotImplemented
    def __ior__(self, other):
        return NotImplemented
    def __abs__(self, other):
        return NotImplemented
    def __invert__(self, other):
        return NotImplemented

__all__ = [ 'DamgaardJurik', 'DamgaardJurikPlaintext', 'DamgaardJurikCiphertext' ]
