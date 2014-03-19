import random
from operator import or_
from itertools import imap
from collections import namedtuple
from curve import *
from intbytes import int2bytes, bytes2int, encode_varint, decode_varint
from immutable import ImmutableEnforcerMeta
from util import secure_compare


def message_to_element(message):
    if not isinstance(message, bytes):
        message = int2bytes(message, endian='little')

    # TODO: this section assumes that message < p
    encoded_length = encode_varint(len(message), endian='little')
    null_padding = '\x00'*(31 - len(encoded_length) - len(message))
    message += null_padding
    message += encoded_length
    message = bytes2int(message, endian='little')

    if message >= p:
        raise ValueError("Message too large to fit into an element")
    message = Curve25519Element(message)
    return message

def element_to_message(element):
    if not isinstance(element, Curve25519Element):
        raise TypeError("Attempted to convert a non-element to a message")
    length, consumed = decode_varint(element, endian='little')
    element = element[:length]
    return element

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
        if not isinstance(message, Curve25519Element):
            message = message_to_element(message)
        # r is a random element of the subgroun Z_q
        r = Curve25519SubElement(random.getrandbits(32*8))
        # c1 = g^r
        c1 = curve(r, base)
        # c2 = pubkey^r = g^(seckey * r)
        c2 = curve(r, self.pubkey)
        # c3 = message*c2 = message * g^(seckey * r)
        c3 = message * Curve25519Element(c2)
        return Curve25519CipherText(locks={self.pubkey:c1}, box=c3)
    
    def decrypt(self, message):
        # TODO: add alternate second argument
        # TODO: type check
        c1 = message.locks[self.pubkey]
        d = message.box
        # c = c1^seckey = g^(seckey * r)
        c = curve(self.seckey, c1)
        # m = d/c = original * g^(seckey * r) * g^(seckey * r)^-1 = original
        m = d / Curve25519Element(c)
        return element_to_message(m)

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


__all__ = ['Curve25519ElGamalKey', 'Curve25519CipherText']
