import random
from operator import or_
from itertools import imap

from curve import *
from immutable import ImmutableEnforcerMeta
from util import secure_compare

def bad_pubkey(k):
    if not isinstance(k, Point):
        raise TypeError("Can only check Point instances")
    return reduce(or_, imap(lambda bad: secure_compare(k, bad), bad_public_keys))

class Key(object):
    """Base class for all Curve25519-related private/public keys as described in
    Curve25519: new Diffie-Hellman speed records by Bernstein"""
    __metaclass__ = ImmutableEnforcerMeta
    def __init__(self, _pubkey=None, _seckey=None):
        if _pubkey is not None:
            self.pubkey = _pubkey
            return super(ElGamalKey, self).__init__()
        if _seckey is not None:
            self.seckey = _seckey
            return super(ElGamalKey, self).__init__()
        raise RuntimeError("Do not directly instantiate Key objects, use the alternate constructors")

    @classmethod
    def generate(cls, random=random):
        return cls.from_seckey(random.getrandbits(32*8))
    @classmethod
    def from_pubkey(cls, pubkey):
        pubkey = Point(pubkey)
        if bad_pubkey(pubkey):
            raise RuntimeError("Tried to instantiate Key with a bad public key")
        else:
            return cls(_pubkey=pubkey)
    @classmethod
    def from_seckey(cls, seckey):
        return cls(_seckey=SubElement(seckey))
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
        assert isinstance(pubkey, Point)
        self._pubkey = pubkey

    @property
    def seckey(self):
        return self._seckey
    @seckey.setter
    def seckey(self, seckey):
        assert isinstance(seckey, SubElement)
        self._seckey = seckey
    @property
    def privkey(self):
        return self.seckey
    @privkey.setter
    def privkey(self, privkey):
        self.seckey = privkey

__all__ = ["bad_pubkey", "Key"]
