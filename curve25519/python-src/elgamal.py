import random
from collections import namedtuple
from numbers import Integral
from curve import *
from key import Key
from intbytes import int2bytes, bytes2int, encode_varint, decode_varint

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
    s = Element(s)
    return s

def element_to_string(element):
    if not isinstance(element, Element):
        raise TypeError("Attempted to convert a non-element to a message")
    length, consumed = decode_varint(element, endian='little')
    element = element[:length]
    return element

class PlainText(Element):
    def __new__(cls, x):
        if (isinstance(x, Integral) and x > bytes2int(p, endian='little'))\
               or (isinstance(x, bytes) and bytes2int(x, endian='little') > bytes2int(p, endian='little')):
            raise ValueError("message too large/long to fit into a plaintext")
        elif not (isinstance(x, Integral) or isinstance(x, bytes)):
            raise TypeError("Can only instantiate PlainText instances from integers or bytes")
        return super(PlainText, cls).__new__(cls, x)
CipherText = namedtuple("CipherText", ["locks", "box"])

class ElGamalKey(Key):
    # TODO: allow hashing of the shared secret before multiplication
    """Implements encoding-free multiplicative ElGamal encryption as described in
    Encoding-Free ElGamal Encryption Without Random Oracles by Chevallier-Mames et.al.
    over Curve25519"""

    def encrypt(self, message, random=random):
        if not (isinstance(message, Element) or isinstance(message, CipherText)):
            raise TypeError("Argument message must be a Element, PlainText, or CipherText instance")
        # r is a random element of the subgroun Z_q
        r = SubElement(random.getrandbits(32*8))
        # lock = g^r
        lock = curve(r, base)
        # c = pubkey^r = g^(seckey * r)
        c = curve(r, self.pubkey)
        # box = message*c = message * g^(seckey * r)
        if isinstance(message, CipherText):
            if self.pubkey in message.locks:
                # below is approximately what ought to happen instead of throwing an error
                # lock *= message.locks[self.pubkey]
                raise ValueError("This ciphertext has already been encrypted with this key")
            box = message.box * Element(c)
            locks = message.locks.copy()
            locks[self.pubkey] = lock
            return CipherText(locks=locks, box=box)
        else:
            box = message * Element(c)
            return CipherText(locks={self.pubkey:lock}, box=box)

    def decrypt(self, message):
        if not isinstance(message, CipherText):
            raise TypeError("Argument message must be a CipherText instance")
        lock = message.locks[self.pubkey]
        box = message.box
        if not (isinstance(lock, Point) and isinstance(box, Element)):
            raise TypeError("Invalid ciphertext")

        # unlocked = lock^seckey = g^(seckey * r)
        unlocked = curve(self.seckey, lock)
        # m = box/lock = original * g^(seckey * r) * g^(seckey * r)^-1 = original
        m = box / Element(unlocked)
        if len(message.locks) == 1:
            return PlainText(m)
        else:
            locks = message.locks.copy()
            del locks[self.pubkey]
            return CipherText(locks=locks, box=m)


__all__ = ['ElGamalKey', 'PlainText', 'CipherText']
