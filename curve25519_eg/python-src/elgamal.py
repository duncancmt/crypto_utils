import random
import _curve25519
from operator import or_
from itertools import imap
from constants import *
from intbytes import int2bytes, bytes2int
from immutable import ImmutableEnforcerMeta
from util import secure_compare


def curve(element, point):
    assert isinstance(element, Curve25519Element)
    assert isinstance(point, Curve25519Point)
    return Curve25519Point(_curve25519.curve(element, point))

def message_to_element(message):
    if isinstance(message, bytes):
        message = bytes2int(message, endian='little')
    if message >= 2**251:
        raise ValueError("Message too large to fit into an element")
    message <<= 3
    message = int2bytes(message, length=32, endian='little')
    message = _curve25519.make_element(message)
    message = Curve25519Element(message)
    return message

def element_to_message(element):
    if not isinstance(element, Curve25519Element):
        raise TypeError("Attempted to convert a non-element to a message")
    element = bytes2int(element, endian='little')
    element &= bytes2int('\xf8'+'\xff'*30+'\x3f', endian='little')
    element >>= 3
    return int2bytes(element, length=32, endian='little')

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
        r = Curve25519Element(random.getrandbits(32*8))
        # c1 = g^r
        c1 = curve(r, base)
        # c2 = pubkey^r = g^(seckey * r)
        c2 = curve(r, self.pubkey)
        # c3 = message*c2 = message * g^(seckey * r)
        c3 = message * Curve25519Element(c2)
        return (c1, c3)

    
    def decrypt(self, message):
        c1, d = message
        # c = c1^seckey = g^(seckey * r)
        c = curve(self.seckey, c1)
        # m = d/c = original * g^(seckey * r) * g^(seckey * r)^-1 = original
        m = d / Curve25519Element(c)
        return m

    @classmethod
    def from_pubkey(cls, pubkey):
        if reduce(or_, imap(lambda bad: secure_compare(pubkey, bad), bad_public_keys)):
            raise RuntimeError("Tried to instantiate Curve25519ElGamalKey with a bad public key")
        else:
            return cls(_pubkey=Curve25519Point(pubkey))
    @classmethod
    def from_seckey(cls, seckey):
        seckey = _curve25519.make_seckey(seckey)
        return cls(_seckey=Curve25519Element(seckey))
    @classmethod
    def from_privkey(cls, privkey):
        return cls.from_seckey(privkey)

    @property
    def pubkey(self):
        try:
            return self._pubkey
        except AttributeError:
            self.pubkey = curve(self.seckey, base)
            return self._pubkey
    @pubkey.setter
    def pubkey(self, pubkey):
        assert isinstance(pubkey, Curve25519Point)
        self._pubkey = pubkey

    @property
    def seckey(self):
        return self._seckey
    @seckey.setter
    def seckey(self, seckey):
        assert isinstance(seckey, Curve25519Element)
        self._seckey = seckey


__all__ = ['Curve25519ElGamalKey']
