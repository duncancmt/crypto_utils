import random
from operator import or_
from itertools import imap
from collections import namedtuple
from numbers import Integral
from curve import *
from intbytes import int2bytes, bytes2int, encode_varint, decode_varint
from immutable import ImmutableEnforcerMeta
from util import secure_compare


def string_to_element(s):
    if not isinstance(s, bytes):
        s = int2bytes(s, endian='little')
    if len(s) > 30:
        raise ValueError("Argument too large to fit into an element")

    encoded_length = encode_varint(len(s), endian='little')
    null_padding = '\x00'*(31 - len(encoded_length) - len(s))
    s += null_padding
    s += encoded_length
    s = bytes2int(s, endian='little')

    if s >= p:
        raise ValueError("Argument too large to fit into an element")
    s = Curve25519Element(s)
    return s

def element_to_string(element):
    if not isinstance(element, Curve25519Element):
        raise TypeError("Attempted to convert a non-element to a message")
    length, consumed = decode_varint(element, endian='little')
    element = element[:length]
    return element

class Curve25519PlainText(Curve25519Element):
    def __new__(cls, x):
        if (isinstance(x, Integral) and x > bytes2int(p, endian='little'))\
               or (isinstance(x, bytes) and bytes2int(x, endian='little') > bytes2int(p, endian='little')):
            raise ValueError("message too large/long to fit into a plaintext")
        elif not (isinstance(x, Integral) or isinstance(x, bytes)):
            raise TypeError("Can only instantiate Curve25519PlainText instances from integers or bytes")
        return super(Curve25519PlainText, cls).__new__(cls, x)
Curve25519CipherText = namedtuple("Curve25519CipherText", ["locks", "box"])

class Curve25519ElGamalKey(object):
    # TODO: allow hashing of the shared secret before multiplication
    """Implements encoding-free multiplicative ElGamal encryption as described in
    Encoding-Free ElGamal Encryption Without Random Oracles by Chevallier-Mames et.al.
    over Curve25519 as described in
    Curve25519: new Diffie-Hellman speed records by Bernstein"""
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
        if not (isinstance(message, Curve25519Element) or isinstance(message, Curve25519CipherText)):
            raise TypeError("Argument message must be a Curve25519Element, Curve25519PlainText, or Curve25519CipherText instance")
        # r is a random element of the subgroun Z_q
        r = Curve25519SubElement(random.getrandbits(32*8))
        # lock = g^r
        lock = curve(r, base)
        # c = pubkey^r = g^(seckey * r)
        c = curve(r, self.pubkey)
        # box = message*c = message * g^(seckey * r)
        if isinstance(message, Curve25519CipherText):
            if self.pubkey in message.locks:
                # below is approximately what ought to happen instead of throwing an error
                # lock *= message.locks[self.pubkey]
                raise ValueError("This ciphertext has already been encrypted with this key")
            box = message.box * Curve25519Element(c)
            locks = message.locks.copy()
            locks[self.pubkey] = lock
            return Curve25519CipherText(locks=locks, box=box)
        else:
            box = message * Curve25519Element(c)
            return Curve25519CipherText(locks={self.pubkey:lock}, box=box)

    def decrypt(self, message):
        if not isinstance(message, Curve25519CipherText):
            raise TypeError("Argument message must be a Curve25519CipherText instance")
        lock = message.locks[self.pubkey]
        box = message.box
        if not (isinstance(lock, Curve25519Point) and isinstance(box, Curve25519Element)):
            raise TypeError("Invalid ciphertext")

        # unlocked = lock^seckey = g^(seckey * r)
        unlocked = curve(self.seckey, lock)
        # m = box/lock = original * g^(seckey * r) * g^(seckey * r)^-1 = original
        m = box / Curve25519Element(unlocked)
        if len(message.locks) == 1:
            return Curve25519PlainText(m)
        else:
            locks = message.locks.copy()
            del locks[self.pubkey]
            return Curve25519CipherText(locks=locks, box=m)

    @classmethod
    def generate(cls, random=random):
        return cls.from_seckey(random.getrandbits(32*8))
    @classmethod
    def from_pubkey(cls, pubkey):
        if reduce(or_, imap(lambda bad: secure_compare(pubkey, bad), bad_public_keys)):
            raise RuntimeError("Tried to instantiate Curve25519ElGamalKey with a bad public key")
        else:
            return cls(_pubkey=Curve25519Point(pubkey))
    @classmethod
    def from_seckey(cls, seckey):
        return cls(_seckey=Curve25519SubElement(seckey))
    @classmethod
    def from_privkey(cls, privkey):
        return cls.from_seckey(privkey)

    ### Aliases for immutable state
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
        assert isinstance(seckey, Curve25519SubElement)
        self._seckey = seckey
    @property
    def privkey(self):
        return self.seckey
    @privkey.setter
    def privkey(self, privkey):
        self.seckey = privkey

__all__ = ['Curve25519ElGamalKey', 'Curve25519PlainText', 'Curve25519CipherText']
