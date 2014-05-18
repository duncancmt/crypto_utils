# TODO: change all __init__ to __new__

########## THIS FILE IS JUST A TOY ##########

from operator import methodcaller
from abc import ABCMeta, abstractmethod, abstractproperty
from numbers import Integral
from itertools import imap, izip, izip_longest, chain
from math import ceil

import keccak
from intbytes import int2bytes, bytes2int, encode_varint, decode_varint
from fastslicer import FastSlicer




########## GLOBAL CONSTANTS AND HELPER FUNCTIONS ##########

# we use sha3-512
_keccak_args = {'r':576,
                'c':1024,
                'fixed_out':True,
                'duplex':False,
                'verbose':False}
attack_difficulty = 128 # we want to be secure against attacks with this time complexity
num_signatures = 64 # we won't make more than 2**num_signatures with one key
alpha = 2.0 # increase in key size required to account for 3-way birthday problem
tree_height = int(ceil(alpha*num_signatures))
assert tree_height % 8 == 0
num_subkey_pairs = 2*attack_difficulty+num_signatures
assert num_subkey_pairs % 8 == 0
key_size = int(ceil((attack_difficulty+alpha*num_signatures)/8.0)) # in bytes

def _grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return izip_longest(fillvalue=fillvalue, *args)

# Yeah, I know overriding builtins is a bad idea
def hash(m, out_len):
    if not isinstance(m, bytes):
        raise TypeError('argument must be a bytes')
    k = keccak.Keccak(**_keccak_args)
    k.update(m)
    return k.squeeze(out_len)

def deserialize(s):
    s = FastSlicer(s)
    tag = s[0]
    if tag not in deserialize_dict:
        raise ValueError('Malformed serialization')
    return deserialize_dict[tag].deserialize(s)




########## ABSTRACT BASE CLASSES ##########

class LamportBytesBase(bytes):
    __metaclass__ = ABCMeta
    @abstractproperty
    def tag_byte(self):
        raise NotImplementedError
    @abstractmethod
    def __init__(self, b):
        return super(LamportBytesBase, self).__init__(b)
    @abstractmethod
    def __repr__(self):
        return super(LamportBytesBase, self).__repr__()
    def serialize(self):
        return self.tag_byte+encode_varint(len(self),endian='big')+self
    @classmethod
    def deserialize(cls, s):
        if s[0] != cls.tag_byte:
            raise ValueError('Attempting to deserialize a stream with the wrong tag byte')
        s = s[1:]
        (length, consumed) = decode_varint(s,endian='big')
        s = s[consumed:]
        return (cls(s[:length]), 1+consumed+length)


class LamportTupleBase(tuple):
    __metaclass__ = ABCMeta
    @abstractproperty
    def tag_byte(self):
        raise NotImplementedError
    @abstractmethod
    def __init__(self, t):
        return super(LamportTupleBase, self).__init__(t)
    @abstractmethod
    def __repr__(self):
        return super(LamportTupleBase, self).__repr__()
    def serialize(self):
        retval = ''.join(imap(methodcaller('serialize'), self))
        return self.tag_byte+encode_varint(len(self),endian='big')+retval
    @classmethod
    def deserialize(cls, s):
        if s[0] != cls.tag_byte:
            raise ValueError('Attempting to deserialize a stream with the wrong tag byte')
        total_consumed = 1
        s = s[1:]

        length, consumed = decode_varint(s,endian='big')
        total_consumed += consumed
        s = s[consumed:]

        temp = [None]*length
        for i in xrange(length):
            (temp[i], consumed) = deserialize(s)
            total_consumed += consumed
            s = s[consumed:]

        return (cls(temp), total_consumed)


class LamportKeyBase(LamportTupleBase):
    @abstractproperty
    def subkey_type(self):
        raise NotImplementedError
    @abstractproperty
    def signature_type(self):
        raise NotImplementedError

    def __init__(self, subkey_tuple):
        subkey_tuple = tuple(subkey_tuple) # TODO: keep this iterator, somehow
        if len(subkey_tuple) != num_subkey_pairs*2:
            raise ValueError("Got the wrong number of subkeys")
        subkey_type = globals()[self.subkey_type]
        if not all(imap(lambda x: isinstance(x, subkey_type),
                        subkey_tuple)):
            raise TypeError('Attempted to initialize %s from tuple containing non %s object'\
                              % (type(self).__name__, subkey_type.__name__))
        super(LamportKeyBase, self).__init__(subkey_tuple)




########## SIGNATURE TYPES ##########

class LamportTreeSignature(LamportTupleBase):
    tag_byte = '\xC0'
    def __init__(self, t):
        t = tuple(t) # TODO: keep this iterator, somehow
        if len(t) != num_subkey_pairs + 1:
            raise ValueError("Got the wrong number of elements")
        if not isinstance(t[0], LamportTreePubKey):
            raise TypeError('First element of a LamportTreeSignature should be a LamportTreePubKey')
        # TODO: make timing attack resistant
        if not all(imap(lambda x: isinstance(x, LamportTreePrivSubkey),
                        t[1:])):
            raise TypeError('Attempted to initialize LamportTreeSignature from tuple containing non LamportTreePrivSubkey object')
        if not all(imap(lambda x: hash(x.serialize(), out_len=key_size) in t[0], t[1:])):
            raise ValueError('Private subkey has no corresponding element in public key')
        if (len(t)-1)*2 != len(t[0]):
            raise ValueError('Length mismatch between revealed secret keys and public key')
        super(LamportTreeSignature, self).__init__(t)
    def __repr__(self):
        return "LamportTreeSignature(%s)" % tuple.__repr__(self)
    def verify(self, message):
        pubkey, privkeys = self[0], self[1:]
        h_message = hash(message, out_len=num_subkey_pairs//8)
        assert len(self)-1 == len(h_message)*8
        i_message = bytes2int(h_message)
        selected_pubsubkeys = [ pubkey[(i<<1) | ((i_message >> i) % 2)]
                                for i in xrange(len(h_message)*8) ]
        # TODO: make timing attack resistant
        # TODO: perhaps move some of this functionality into a subkey method?
        for x,y in izip(imap(lambda x: hash(x, out_len=key_size),
                             imap(methodcaller('serialize'), privkeys)), selected_pubsubkeys):
            if x != y:
                raise ValueError('Bad signature')

class LamportSignature(LamportTupleBase):
    tag_byte = '\xC1'
    def __init__(self, t):
        t = tuple(t)
        if len(t) != tree_height:
            raise ValueError("Got the wrong number of sub-signatures")
        # TODO: make timing attack resistant
        if not all(imap(lambda x: isinstance(x, LamportTreeSignature), t)):
            raise TypeError('Attempted to initialize LamportSignature from tuple containing non LamportTreeSignature object')
        if not isinstance(t[-1][0], LamportRootPubKey):
            raise TypeError('The last subsignature of a LamportSignature must contain a LamportRootPubKey instead of a LamportTreePubKey')
        if not all(imap(lambda x: isinstance(x, LamportRootPrivSubkey), t[-1][1:])):
            raise TypeError('The last subsignature of a LamportSignature must contain a list of LamportRootPrivKey\'s instead of LamportTreePrivKey\'s')
        super(LamportSignature, self).__init__(t)
    def __repr__(self):
        return "LamportTreeSignature(%s)" % tuple.__repr__(self)
    def verify(self, message):
        # TODO: make timing attack resistant
        for signature in self:
            signature.verify(message)
            message = signature[0].serialize() # extract pubkey from subsignature
    def check_pubkey(self, pubkey):
        # TODO: make timing attack resistant
        # the last signature in self contains an instance of LamportPubKey as its first element
        return pubkey == self[-1][0]




########## SUBKEY TYPES ##########

class LamportTreePubSubkey(LamportBytesBase):
    tag_byte = '\x00'
    def __repr__(self):
        return "LamportTreePubSubkey(%s)" % bytes.__repr__(self)

class LamportTreePrivSubkey(LamportBytesBase):
    tag_byte = '\x01'
    def __repr__(self):
        return "LamportTreePrivSubkey(%s)" % bytes.__repr__(self)

class LamportRootPubSubkey(LamportTreePubSubkey):
    tag_byte = '\x02'
    def __repr__(self):
        return "LamportRootPubSubkey(%s)" % bytes.__repr__(self)

class LamportRootPrivSubkey(LamportTreePrivSubkey):
    tag_byte = '\x03'
    def __repr__(self):
        return "LamportRootPrivSubkey(%s)" % bytes.__repr__(self)




########## PUBLIC KEY TYPES ##########

class LamportPubKeyBase(LamportKeyBase):
    @abstractproperty
    def privkey_type(self):
        raise NotImplementedError

    @classmethod
    def from_privkey(cls, privkey):
        privkey_type = globals()[cls.privkey_type]
        if not isinstance(privkey, privkey_type):
            raise TypeError('argument must be a %s' % privkey_type.__name__)
        subkey_type = globals()[cls.subkey_type]
        temp = ( subkey_type(hash(subkey.serialize(), out_len=key_size))
                 for subkey in privkey )
        temp = tuple(temp)
        return cls(temp)


class LamportTreePubKey(LamportPubKeyBase):
    tag_byte = '\x40'
    privkey_type = 'LamportTreePrivKey'
    subkey_type = 'LamportTreePubSubkey'
    signature_type = 'LamportTreeSignature'
    def __repr__(self):
        return "LamportTreePubKey(%s)" % tuple.__repr__(self)

class LamportRootPubKey(LamportTreePubKey):
    tag_byte = '\x41'
    privkey_type = 'LamportRootPrivKey'
    subkey_type = 'LamportRootPubSubkey'
    signature_type = 'LamportTreeSignature'
    def __repr__(self):
        return "LamportRootPubKey(%s)" % tuple.__repr__(self)

class LamportPubKey(LamportRootPubKey):
    tag_byte = '\x42'
    # inherit privkey_type
    # inherit subkey_type
    signature_type = 'LamportSignature'
    def __repr__(self):
        return "LamportPubKey(%s)" % tuple.__repr__(self)

    @classmethod
    def from_privkey(cls, privkey):
        return super(LamportPubKey, cls).from_privkey(LamportRootPrivKey(tuple(iter(privkey))))




########## PRIVATE KEY TYPES ##########

class LamportPrivKeyBase(LamportKeyBase):
    @abstractproperty
    def pubkey_type(self):
        raise NotImplementedError

    @classmethod
    def from_seed_index(cls, seed, depth, index):
        if not isinstance(seed, bytes):
            raise TypeError('seed must be a bytes')
        if not isinstance(depth, Integral):
            raise TypeError('depth must be an Integral')
        if not isinstance(index, Integral):
            raise TypeError('index must be an Integral')

        k = keccak.Keccak(**_keccak_args)
        seed = k.pad10star1(seed, k.r)
        k.update(seed)
        depth = encode_varint(depth,endian='big')
        depth = k.pad10star1(depth, k.r)
        k.update(depth)
        index = encode_varint(index,endian='big')
        # k will automatically pad index upon squeezing
        k.update(index)
        raw_key_material = k.squeeze(key_size * num_subkey_pairs * 2)
        subkey_type = globals()[cls.subkey_type]
        temp = ( subkey_type(''.join(subkey))
                 for subkey in _grouper(raw_key_material,
                                        key_size) )
        temp = tuple(temp)
        return cls(temp)

    def to_pubkey(self):
        pubkey_type = globals()[self.pubkey_type]
        return pubkey_type.from_privkey(self)

    def sign(self, message):
        h_message = hash(message, out_len=num_subkey_pairs//8)
        assert len(self) == len(h_message)*16
        i_message = bytes2int(h_message)
        pubkey_type = globals()[self.pubkey_type]
        temp = chain([pubkey_type.from_privkey(self)],
                     ( self[(i<<1) | ((i_message >> i) % 2)]
                       for i in xrange(len(h_message)*8) ))
        signature_type = globals()[self.signature_type]
        return signature_type(tuple(temp))


class LamportTreePrivKey(LamportPrivKeyBase):
    tag_byte = '\x81'
    pubkey_type = 'LamportTreePubKey'
    subkey_type = 'LamportTreePrivSubkey'
    signature_type = 'LamportTreeSignature'
    def __repr__(self):
        return "LamportTreePrivKey(%s)" % tuple.__repr__(self)

class LamportRootPrivKey(LamportTreePrivKey):
    tag_byte = '\x82'
    pubkey_type = 'LamportRootPubKey'
    subkey_type = 'LamportRootPrivSubkey'
    signature_type = 'LamportTreeSignature'
    def __repr__(self):
        return "LamportRootPrivKey(%s)" % tuple.__repr__(self)

# This class is not like the others because it needs to hold the seed to the private key
# instead of the raw private key. As a result it extends bytes, not tuple
class LamportPrivKey(LamportBytesBase):
    tag_byte = '\x83'
    def __init__(self, seed):
        if not (isinstance(seed, bytes) or seed is None):
            import warnings
            warnings.warn("Argument to LamportPrivKey should be bytes. However, we will convert it with bytes()")
        super(LamportPrivKey, self).__init__(seed)

    def __repr__(self):
        return "LamportPrivKey(%s)" % bytes.__repr__(self)

    def __iter__(self):
        return iter(LamportRootPrivKey.from_seed_index(self, 1, 0))

    def to_pubkey(self):
        return LamportPubKey.from_privkey(self)

    def serialize(self):
        import warnings
        warnings.warn("You probably shouldn\'t be serializing LamportPrivKey instances")
        return super(LamportPrivKey, self).serialize()

    def _sign(self, message):
        s = LamportRootPrivKey(tuple(iter(self)))
        return s.sign(message)

    def sign(self, message):
        # calculate the tree path, a bit-string (represented as an integer)
        # declaring whether to go right or left at each node
        #
        # N.B. for our security guarantees to hold, the path must be
        # unpredictable by an attacker and deterministically produced from the
        # message. A path can be reused once before our security guarantees
        # are invalidated
        k = keccak.Keccak(**_keccak_args)
        k.update(k.pad10star1(hash(self, tree_height//8), k.r))
        k.update(hash(message, tree_height//8))
        tree_path = k.squeeze(tree_height//8)
        tree_path = bytes2int(tree_path)
        assert tree_path >> tree_height == 0
        
        keys = [None] * tree_height
        signatures = [None] * tree_height
    
        keys[0] = LamportTreePrivKey.from_seed_index(self, tree_height, tree_path)
        signatures[0] = keys[0].sign(message)
        for i in xrange(1, len(keys)-1):
            keys[i] = LamportTreePrivKey.from_seed_index(self, tree_height - i, tree_path >> i)
            signatures[i] = keys[i].sign(LamportTreePubKey.from_privkey(keys[i-1]).serialize())

        keys[-1] = self
        signatures[-1] = self._sign(LamportTreePubKey.from_privkey(keys[-2]).serialize())
        return LamportSignature(signatures)




########## SETUP ##########

deserialize_dict = dict()
name = None
cls = None
for name, cls in globals().iteritems():
    try:
        if name.startswith('Lamport') and isinstance(cls.tag_byte, bytes):
            if cls.tag_byte in deserialize_dict:
                if deserialize_dict[cls.tag_byte] is not cls:
                    raise TypeError('%s and %s have the same tag byte %s' % (repr(cls), repr(deserialize_dict[cls.tag_byte]), repr(cls.tag_byte)))
            deserialize_dict[cls.tag_byte] = cls
    except AttributeError:
        pass
del name
del cls

__all__ = [ 'deserialize', 'LamportPubKey', 'LamportPrivKey' ]


if __name__ == '__main__':
    seed = hash('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', out_len=key_size)
    privkey = LamportPrivKey(seed)
    s = privkey.serialize()
    # TODO: this is a bit disingenuous
    print 'Private keys are %d bytes long internally, %d bytes serialized' % (len(privkey), len(s))
    d,_ = deserialize(s)
    if d == privkey:
        print '\tDeserialization of private keys works!'
        privkey = d
    else:
        print '\tUH OH! Deserialization of private keys is broken!'

    pubkey = privkey.to_pubkey()
    s = pubkey.serialize()
    print 'Public keys are %d subkeys long internally, %d bytes serialized' % (len(pubkey), len(s))
    d,_ = deserialize(s)
    if d == pubkey:
        print '\tDeserialization of public keys works!'
        pubkey = d
    else:
        print '\tUH OH! Deserialization of public keys is broken!'

    sig = privkey.sign('Hello, World!')
    s = sig.serialize()
    print 'Signatures are %d subsignatures long internally, %d bytes serialized' % (len(sig), len(s))
    d,_ = deserialize(s)
    if d == sig:
        print '\tDeserialization of signatures works!'
        sig = d
    else:
        print '\tUH OH! Deserialization of signatures is broken!'

    try:
        sig.verify('Hello, World!')
        print 'Signature is valid for the original message'
    except ValueError:
        print 'UH OH! Signature is NOT valid for the original message'

    try:
        sig.verify('hello world')
        print 'UH OH! Signature is valid for a different message'
    except ValueError:
        print 'Signature is NOT valid for a different message'

    if sig.check_pubkey(pubkey):
        print 'Signature belongs to the original public key'
    else:
        print 'UH OH! Signature does not belong to the original public key'
