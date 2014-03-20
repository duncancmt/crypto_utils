import random
from curve import *

class Curve25519DHKey(object):
    __metaclass__ = ImmutableEnforcerMeta

    def shared_secret(self, other):
        if not isinstance(other, Curve25519DHKey):
            raise TypeError("Can only calculate the shared secret with another Curve25519DHKey instance")
        return curve(self.seckey, other.pubkey)

    @classmethod
    def generate(cls, random=random):
        return cls.from_seckey(random.getrandbits(32*8))
    @classmethod
    def from_pubkey(cls, pubkey):
        if reduce(or_, imap(lambda bad: secure_compare(pubkey, bad), bad_public_keys)):
            raise RuntimeError("Tried to instantiate Curve25519DHKey with a bad public key")
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
