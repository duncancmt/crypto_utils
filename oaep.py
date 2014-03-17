import random
from operator import xor, or_
from itertools import *

from keccak import Keccak
from intbytes import int2bytes, bytes2int
from util import secure_compare

def oaep_keccak(m, label='', out_len=None, hash_len=32, random=random, keccak_args=dict()):
    """Perform OAEP (as specified by PKCS#1v2.1) with Keccak as the one-way function

    All lengths specified in *bytes*
    m: message to be padded
    label: (optional) to be associated with the message, the default is the empty string
    out_len: (optional) the length of the message after padding, the default is len(m) + 2*hash_len + 2
    hash_len: (optional) the length of the output of the hash algorithm, the default is 32
    random: (optional) source of entropy for the random seed generation, the default is python's random module
    keccak_args: (optional) parameters for the Keccak sponge function, the defaults are the Keccak defaults
    """
    if out_len is not None and len(m) > out_len - 2*hash_len - 2:
        raise ValueError("Message too long to specified output and hash lengths")
    
    # hash the label
    k = Keccak(**keccak_args)
    k.absorb(label)
    lhash = k.squeeze(hash_len)

    if out_len is not None:
        pad_string = '\x00' * (out_len - len(m) - 2*hash_len - 2)
    else:
        pad_string = ''
    
    # pad m
    padded = lhash + pad_string + '\x01' + m

    # generate rand_seed, a hash_len-byte random string
    rand_seed = random.getrandbits(hash_len*8)
    rand_seed = int2bytes(rand_seed)

    # expand rand_seed to the length of padded
    k = Keccak(**keccak_args)
    k.absorb(rand_seed)
    mask = k.squeeze(len(padded))

    # XOR the message with the expanded r
    masked = ''.join(imap(chr, imap(xor, imap(ord, padded),
                                         imap(ord, mask))))

    # hash masked to generate the seed mask
    k = Keccak(**keccak_args)
    k.absorb(masked)
    seed_mask = k.squeeze(len(rand_seed))

    # mask the seed
    masked_seed = ''.join(imap(chr, imap(xor, imap(ord, rand_seed),
                                              imap(ord, seed_mask))))

    # concatenate the two together
    return '\x00' + masked_seed + masked

def unoaep_keccak(m, label='', hash_len=32, keccak_args=dict()):
    """Recover a message padded with OAEP (as specified by PKCS#1v2.1) with Keccak as the one-way function

    All lengths specified in *bytes*
    m: message to be decoded
    label: (optional) the label expected on the message, the default is the empty string
    hash_len: (optional) the length of the output of the hash algorithm, the default is 32
    keccak_args: (optional) parameters for the Keccak sponge function, the defaults are the Keccak defaults
    """
    # hash the label
    k = Keccak(**keccak_args)
    k.absorb(label)
    lhash = k.squeeze(hash_len)

    # split the three parts of the OAEP'd message
    Y, masked_seed, masked = m[0], m[1:hash_len+1], m[hash_len+1:]

    # recover rand_seed
    k = Keccak(**keccak_args)
    k.absorb(masked)
    seed_mask = k.squeeze(len(masked_seed))

    rand_seed = ''.join(imap(chr, imap(xor, imap(ord, masked_seed),
                                            imap(ord, seed_mask))))

    # recover the original message
    k = Keccak(**keccak_args)
    k.absorb(rand_seed)
    mask = k.squeeze(len(masked))

    padded = ''.join(imap(chr, imap(xor, imap(ord, masked),
                                         imap(ord, mask))))

    # find the index of the '\x01' separator byte without leaking timing info
    found_separator = False
    separator_index = hash_len
    tru = True
    for i in xrange(hash_len,len(padded)):
        condition = (not found_separator) + (padded[i] != '\x00') == 2 # use + to avoid short-circuiting
        if condition: 
            separator_index = i
            found_separator = tru
        if not condition:
            separator_index = separator_index
            found_separator = found_separator
            
    lhash_, pad_string, separator, retval = padded[:hash_len], padded[hash_len:separator_index], \
                                            padded[separator_index], padded[separator_index+1:]

    # check that lhash matches, the separator is correct, and the leading NUL is preserved
    # without leaking which one failed
    if sum([ secure_compare(lhash, lhash_),
             separator == '\x01',
             Y == '\x00' ]) != 3:
        raise ValueError("Decryption failed")
    else:
        return retval
