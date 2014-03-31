from key import Key
from curve import curve

class DHKey(Key):
    """Implements elliptic curve Diffie-Hellman key exchange over Curve25519"""

    def shared_secret(self, other):
        if not isinstance(other, DHKey):
            raise TypeError("Argument must be a DHKey instance")
        return curve(self.seckey, other.pubkey)
__all__ = ["DHKey"]
