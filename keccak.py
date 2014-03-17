#### ORIGINAL LICENSE ####
# The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
# Michael Peeters and Gilles Van Assche. For more information, feedback or
# questions, please refer to our website: http://keccak.noekeon.org/
# 
# Implementation by Renaud Bauvin,
# hereby denoted as "the implementer".
#
# To the extent possible under law, the implementer has waived all copyright
# and related or neighboring rights to the source code in this file.
# http://creativecommons.org/publicdomain/zero/1.0/

#### MODIFICATION TO ORIGINAL LICENSE ####
# Heavy modifications to make this more idiomatic by Duncan Townsend.
# KeccakRandom and KeccakCipher written by Duncan Townsend.
#
# These modifications are available under the same license as the rest of this
# project

import operator
import warnings
from math import ceil
from binascii import hexlify
from copy import copy, deepcopy
from itertools import imap
from intbytes import int2bytes, bytes2int
from util import secure_compare

class KeccakError(RuntimeError):
    """Class of error used in the Keccak implementation

    Use: raise KeccakError("Text to be displayed")"""

try:
    import _sha3
    if _sha3._varout_state_patched:
        has_fast = True
    else:
        raise KeccakError
except (ImportError, AttributeError, KeccakError):
    try:
        del _sha3
    except NameError:
        pass
    warnings.warn('Having the _sha3 module from pysha3 makes this module much faster')
    has_fast = False

class Keccak(object):
    """
    Class implementing the Keccak sponge function
    """
    def __init__(self, r=1024,c=576,fixed_out=False,duplex=False,verbose=False):
        """Constructor:

        r: bitrate (default 1024)
        c: capacity (default 576)
        verbose: print the details of computations(default:False)
        r + c must be 25, 50, 100, 200, 400, 800 or 1600 (recommended 1600)
        see http://keccak.noekeon.org/NoteOnKeccakParametersAndUsage.pdf
        """

        if fixed_out and duplex:
            raise ValueError('It is nonsense to try to instantiate a fixed output, duplex Keccak')
        self.fixed_out = fixed_out
        self.duplex = duplex
        self.verbose = verbose
        if (r<0) or (r%8!=0):
            raise ValueError('r must be a multiple of 8 in this implementation')
        self.r = r
        self.c = c
        self.b = b = r+c
        if b not in [25, 50, 100, 200, 400, 800, 1600]:
            raise ValueError('b value not supported - use 25, 50, 100, 200, 400, 800 or 1600')
        self.w = b//25
        self.l=(self.w-1).bit_length()
        self.nr=12+2*self.l
        self.done_absorbing = False

        if has_fast and not duplex:
            if fixed_out and b == 1600 and c == 448:
                self.fast = True
                self.fast_impl = _sha3.sha3_224()
                return
            elif fixed_out and b == 1600 and c == 512:
                self.fast = True
                self.fast_impl = _sha3.sha3_256()
                return
            elif fixed_out and b == 1600 and c == 768:
                self.fast = True
                self.fast_impl = _sha3.sha3_384()
                return
            elif fixed_out and b == 1600 and c == 1024:
                self.fast = True
                self.fast_impl = _sha3.sha3_512()
                return
            elif not fixed_out and b == 1600 and c == 576:
                self.fast = True
                self.fast_impl = _sha3.sha3_0()
                return

        self.fast = False
        if verbose:
            print "Create a Keccak function with (r=%d, c=%d (i.e. w=%d))" % (r,c,(r+c)//25)

        # Initialisation of state
        self.S = ((0,0,0,0,0),
                  (0,0,0,0,0),
                  (0,0,0,0,0),
                  (0,0,0,0,0),
                  (0,0,0,0,0))
        self.P = ''
        self.output_cache = ''

    # Constants

    ## Round constants
    RC=(0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008)

    ## Rotation offsets
    rot_off=((0,    36,     3,    41,    18)    ,
             (1,    44,    10,    45,     2)    ,
             (62,    6,    43,    15,    61)    ,
             (28,   55,    25,    21,    56)    ,
             (27,   20,    39,     8,    14)    )

    ## Generic utility functions

    @staticmethod
    def rot(x,n,w):
        """Bitwise rotation (to the left) of n bits considering the \
        string of bits is w bits long"""

        n = n%w
        return ((x>>(w-n))+(x<<n))%(1<<w)

    @staticmethod
    def fromStringToLane(string):
        """Convert a string of bytes to a lane value"""
        return bytes2int(string)

    @staticmethod
    def fromLaneToString(lane, w):
        """Convert a lane value to a string of bytes"""
        return int2bytes(lane, w//8)

    @staticmethod
    def printState(state, info):
        """Print on screen the state of the sponge function preceded by \
        string info

        state: state of the sponge function
        info: a string of characters used as identifier"""

        print "Current value of state: %s" % (info)
        for y in range(5):
            line=[]
            for x in range(5):
                 line.append(hex(state[x][y]))
            print '\t%s' % line

    ### Conversion functions String <-> Table (and vice-versa)

    @classmethod
    def convertStrToTable(cls,string,w,b):
        """Convert a string of bytes to its 5x5 matrix representation

        string: string of bytes"""

        #Check that input paramaters
        if w%8!= 0:
            raise ValueError("w is not a multiple of 8")
        if len(string)!=b//8:
            raise ValueError("string can't be divided in 25 blocks of w bits\
            i.e. string must have exactly b bits")

        #Convert
        output=[[0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0]]
        for x in xrange(5):
            for y in xrange(5):
                offset=((5*y+x)*w)//8
                output[x][y]=cls.fromStringToLane(string[offset:offset+(w//8)])
        return tuple(map(tuple,output))

    @classmethod
    def convertTableToStr(cls, table, w):
        """Convert a 5x5 matrix representation to its string representation"""

        #Check input format
        if w%8!= 0:
            raise ValueError("w is not a multiple of 8")
        if (len(table)!=5) or (False in [len(row)==5 for row in table]):
            raise ValueError("table must be 5x5")

        #Convert
        output=[None]*25
        for x in range(5):
            for y in range(5):
                output[5*y+x]=cls.fromLaneToString(table[x][y], w)
        output = ''.join(output)
        return output

    @classmethod
    def Round(cls,A,RCfixed,w):
        """Perform one round of computation as defined in the Keccak-f permutation

        A: current state (5x5 matrix)
        RCfixed: value of round constant to use (integer)
        """

        #Initialisation of temporary variables
        A = map(list, A)
        B=[[0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0]]
        C= [0,0,0,0,0]
        D= [0,0,0,0,0]

        #Theta step
        for x in range(5):
            C[x] = A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4]

        for x in range(5):
            D[x] = C[(x-1)%5]^cls.rot(C[(x+1)%5],1,w)

        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y]^D[x]

        #Rho and Pi steps
        for x in range(5):
          for y in range(5):
                B[y][(2*x+3*y)%5] = cls.rot(A[x][y], cls.rot_off[x][y], w)

        #Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y]^((~B[(x+1)%5][y]) & B[(x+2)%5][y])

        #Iota step
        A[0][0] = A[0][0]^RCfixed

        return tuple(map(tuple,A))

    @classmethod
    def KeccakF(cls, A, nr, w, verbose):
        """Perform Keccak-f function on the state A

        A: 5x5 matrix containing the state
        nr: number of rounds to perform
        w: lane width
        verbose: a boolean flag activating the printing of intermediate computations
        """

        if verbose:
            cls.printState(A,"Before first round")

        for i in range(nr):
            #NB: result is truncated to lane size
            A = cls.Round(A,cls.RC[i]%(1<<w),w)

            if verbose:
                cls.printState(A,"Satus end of round #%d/%d" % (i+1,nr))

        return A

    ### Padding rule

    @staticmethod
    def pad10star1(M, n, M_bit_len=None):
        """Pad M with the pad10*1 padding rule to reach a length multiple of r bits

        M: string to be padded
        n: block length in bits (must be a multiple of 8)
        M_bit_len: length of M (in bits) only supply this argument if M is not an octet stream
        (M_bit_len functionality is unused in this implementation)
        """

        # Check the parameter n
        if n%8!=0:
            raise ValueError("n must be a multiple of 8")

        M = deepcopy(M)
        if M_bit_len is None:
            M_bit_len = len(M)*8
        elif M_bit_len > len(M)*8:
            raise ValueError("the string is too short to contain the number of bits announced")

        nr_bytes_filled=M_bit_len//8
        nbr_bits_filled=M_bit_len%8
        l = M_bit_len % n
        if ((n-8) <= l <= (n-2)):
            # We need only a single pad byte
            if (nbr_bits_filled == 0):
                pad_byte = 0
            else:
                pad_byte = ord(M[nr_bytes_filled])
            pad_byte >>= 8 - nbr_bits_filled
            pad_byte += 2**nbr_bits_filled + 2**7
            M = M[0:nr_bytes_filled]
            M += chr(pad_byte)
        else:
            # We need multiple pad bytes
            if (nbr_bits_filled == 0):
                pad_byte = 0
            else:
                pad_byte=ord(M[nr_bytes_filled])
            pad_byte >>= 8 - nbr_bits_filled
            pad_byte += 2**nbr_bits_filled
            M = M[0:nr_bytes_filled]
            M += chr(pad_byte)
            M += '\x00'*(n//8-1-len(M)%(n//8))+'\x80'

        assert len(M) % (n//8) == 0
        return M

    @staticmethod
    def unpad10star1(M):
        if M[-1] == '\x80':
            # multibyte padding
            for pad_end in xrange(len(M)-2,-1,-1):
                if M[pad_end] != '\x00':
                    break
            last_byte = M[pad_end]
            if last_byte == '\x01':
                return M[:pad_end]
            else:
                last_byte = ord(last_byte)
                last_byte <<= 8-last_byte.bit_length() # left-align padding string
                last_byte &= 127 # strip leading 1
                last_byte <<= 1 # left-align
                return M[:pad_end]+chr(last_byte)
        else:
            # single byte padding
            last_byte = M[-1]
            if last_byte == '\x81':
                return M[:-1]
            else:
                last_byte = ord(last_byte)
                last_byte <<= 8-last_byte.bit_length() # left-align padding string
                last_byte &= 127 # strip first padding 1
                last_byte <<= 8-last_byte.bit_length() # left-align second padding 1
                last_byte &= 127 # strip second padding 1
                last_byte <<= 1 # left-align
                return M[:-1]+chr(last_byte)

    def __call__(self, M):
        """If this instance is duplex, permforms the duplex Keccak operations,
        otherwise does the same as absorb
        """
        if not self.duplex:
            return self.absorb(M)
        
        r, c, b, w, nr, verbose = self.r, self.c, self.b, self.w, self.nr, self.verbose

        M = self.pad10star1(M, r)
        if len(M) > r//8:
            raise ValueError('Argument too long for duplex Keccak with r=%d' % r)

        self.absorb(M, _ignore_duplex=True)
        assert len(self.P) == 0
        return self.squeeze(r//8, _ignore_duplex=True)

    def update(self, M):
        """Does the same as absorb"""
        return self.absorb(M)

    def absorb(self, M, _ignore_duplex=False):
        """Perform the absorbing phase of Keccak: data is mixed into the internal state
        
        M: the string to be absorbed
        """
        if self.duplex and not _ignore_duplex:
            raise KeccakError('Duplex Keccak cannot absorb or squeeze, call this object instead')
        if self.done_absorbing and not _ignore_duplex:
            raise KeccakError('Cannot continue absorbing once squeezing has begun')
        if self.fast:
            return self.fast_impl.update(M)

        r, c, b, w, nr, verbose = self.r, self.c, self.b, self.w, self.nr, self.verbose

        self.P += M

        while len(self.P) >= r//8:
            chunk, self.P = self.P[:r//8], self.P[r//8:]
            if verbose:
                print("String ready to be absorbed: %s (will be completed by %d x NUL)" % (hexlify(chunk), c//8))

            chunk += '\x00'*(c//8)
            Pi=self.convertStrToTable(chunk,w,b)
            self.S = ( ( x ^ y
                         for x, y in zip(srow, prow) )
                       for srow, prow in zip(self.S, Pi) )
            self.S = tuple(map(tuple, self.S))
            self.S = self.KeccakF(self.S, nr, w, verbose)

            if verbose:
                print("Value after absorption : %s" % (hexlify(self.convertTableToStr(self.S, w))))
        assert len(self.P) < r // 8

    def digest(self):
        """Does the same as squeeze"""
        return self.squeeze(self.c//16)

    def hexdigest(self):
        """Convenience function that returns the hexadecimal version of the digest"""
        return hexlify(self.digest())

    def squeeze(self, n, _ignore_duplex=False):
        """Perform the squeezing phase of Keccak: arbitrary-length digest output is produced from the internal state

        n: the length (in bytes) of the output to produce
        (this method can be called many times to produce as much output as needed)
        """
        w, r, nr, verbose = self.w, self.r, self.nr, self.verbose

        if self.duplex and not _ignore_duplex:
            raise KeccakError('Duplex Keccak cannot absorb or squeeze, call this object instead')

        if self.fast:
            self.done_absorbing = True
            if self.fixed_out:
                tmp = self.fast_impl.copy() # TODO use copy.deepcopy
                retval = self.fast_impl.squeeze(n)
                self.fast_impl = tmp
                return retval
            else:
                return self.fast_impl.squeeze(n)

        # pad the remaining input and add it to the internal state
        if not self.done_absorbing:
            assert self.output_cache == ''
            self.P = self.pad10star1(self.P, r)
            assert len(self.P) == r // 8
            self.absorb('', _ignore_duplex=_ignore_duplex)
            self.done_absorbing = True

        assert self.P == ''

        if self.fixed_out:
            old_S = self.S

        # if there is any leftover output from a previous squeezing, return it
        assert len(self.output_cache) < r//8
        retval = ''
        outputLength = n
        if outputLength <= len(self.output_cache):
            retval, self.output_cache = self.output_cache[:outputLength], self.output_cache[outputLength:]
            return retval
        retval += self.output_cache
        outputLength -= len(self.output_cache)
        self.output_cache = ''
        
        # perform the squeezing operation up to within a block boundary of the output
        while outputLength>=r//8:
            retval += self.convertTableToStr(self.S, w)[:r//8]
            self.S = self.KeccakF(self.S, nr, w, verbose)
            outputLength -= r//8

        # fill the rest of the output and save the leftovers, if any
        if outputLength > 0:
            string = self.convertTableToStr(self.S, w)[:r//8]
            self.S = self.KeccakF(self.S, nr, w, verbose)
            temp, self.output_cache = string[:outputLength], string[outputLength:]
            retval += temp
        assert len(self.output_cache) < r//8
            
        if verbose:
            print("Value after squeezing : %s" % (hexlify(self.convertTableToStr(self.S, w))))

        if self.fixed_out:
            self.S = old_S
            self.output_cache = ''

        return retval

    def getstate(self):
        retval = copy(self.__dict__)
        if retval['fast']:
            retval['fast_impl'] = retval['fast_impl'].state
        return deepcopy(retval)
    def setstate(self, state):
        state = deepcopy(state)
        if state['fast']:
            fast_state = state['fast_impl']
            del state['fast_impl']
            c = state['c']
            if c == 448:
                state['fast_impl'] = _sha3.sha3_224()
            elif c == 512:
                state['fast_impl'] = _sha3.sha3_256()
            elif c == 768:
                state['fast_impl'] = _sha3.sha3_384()
            elif c == 1024:
                state['fast_impl'] = _sha3.sha3_512()
            elif c == 576:
                state['fast_impl'] = _sha3.sha3_0()
            else:
                raise TypeError('Malformed state')
            state['fast_impl'].state = fast_state

        for k, v in state.iteritems():
            setattr(self, k, v)


try:
    from correct_random import CorrectRandom as random_base
except ImportError:
    warnings.warn("Not having correct_random.CorrectRandom makes some of KeccakRandom's methods produce biased output")
    from random import Random as random_base
class KeccakRandom(random_base):
    """A random implementation based on the Keccak sponge function"""
    def __init__(self, seed=None, keccak_args=dict(), _state=None):
        """Constructor:

        seed: a bytes from which to deterministically initialize the state of this instance
        keccak_args (optional): keyword arguments to supply to the underlying Keccak instance
        _state (do not use): a state tuple to initialize from instead of using the seed
        """
        if _state is not None:
            self.setstate(_state)
        else:
            if 'duplex' in keccak_args and keccak_args['duplex']:
                raise ValueError('KeccakRandom does not work with duplex Keccak')
            if 'fixed_out' in keccak_args and keccak_args['fixed_out']:
                raise ValueError('KeccakRandom does not work with fixed output Keccak')
            keccak_args['fixed_out'] = False
            self.keccak_args = deepcopy(keccak_args)
            self.seed(seed)

    @classmethod
    def from_state(cls, state):
        """Alternate constructor:

        Return a KeccakRandom instance directly initialized from a state tuple
        """
        return cls(seed=None, keccak_args=None, _state=state)

    def getrandbits(self, n):
        """Generate a long integer with n random bits"""
        bytes_needed = max(int(ceil((n-self._cache_len) / 8.0)), 0)

        self._cache |= bytes2int(self.k.squeeze(bytes_needed)) << self._cache_len
        self._cache_len += bytes_needed * 8

        result = self._cache & ((1<<n) - 1)
        self._cache >>= n
        self._cache_len -= n
        return result

    def seed(self, seed):
        """Deterministically reinitialize this instance from the given seed"""
        self.k = Keccak(**self.keccak_args)

        if seed is None:
            seed = ''
            with open('/dev/random','rb') as randfile:
                print 'reading %d bytes from /dev/random' % int(ceil(self.k.c / 8.0))
                for _ in xrange(int(ceil(self.k.c / 8.0))):
                    seed += randfile.read(1)
        self.k.absorb(seed)

        self._cache = 0L
        self._cache_len = 0L

    def getstate(self):
        """Return a state tuple that can be used to create identical copies of this instance"""
        return deepcopy((self.keccak_args, self.k.getstate(),
                         self._cache, self._cache_len))

    def setstate(self, state):
        """Directly reinitialize this instance from a state tuple, making it identical
        to the instance that provided the state.
        """
        (self.keccak_args, keccak_state, self._cache, self._cache_len) = deepcopy(state)
        self.k = Keccak(**self.keccak_args)
        self.k.setstate(keccak_state)

    def jumpahead(self, n):
        """Jump the underlying Keccak instance ahead the given number of states and
        continue producing randomness from there.
        """
        # iterate Keccak n times
        for _ in xrange(n):
            self.k.squeeze(self.k.r//8)

        # clear our cache
        self._cache = 0L
        self._cache_len = 0L



class ShortKeyWarning(RuntimeWarning):
    pass
class KeccakCipher(object):
    """Implements an authenticated symmetric encryption mode based on duplex Keccak"""
    def __init__(self, key, nonce, encrypt_not_decrypt=True, keccak_args=dict()):
        """Constructor:

        key: the key to encrypt under, must be kept secret, must be a bytes
        nonce: the nonce to be used for this block of encryption, must not be reused, must be a bytes
        encrypt_not_decrypt: (optional) whether to perform encryption, default True
        keccak_args: a dict of additional keyword arguments to Keccak (experts only)
        """
        if 'duplex' in keccak_args and not keccak_args['duplex']:
            raise ValueError('KeccakCipher does not work with simplex Keccak')
        keccak_args['duplex'] = True
        if 'fixed_out' in keccak_args and keccak_args['fixed_out']:
            raise ValueError('KeccakCipher does not work with fixed output Keccak')
        keccak_args['fixed_out'] = False
        self.k = Keccak(**keccak_args)

        if not isinstance(key, bytes):
            raise TypeError("key must be a bytes")
        if not isinstance(nonce, bytes):
            raise TypeError("nonce must be a bytes")
        if len(key) < self.k.c // 8:
            warnings.warn(ShortKeyWarning('Key is shorter than the capacity of the cipher. The use of a short key weakens the cipher.'))
        if len(nonce) < self.k.c // 8:
            warnings.warn(ShortKeyWarning('Nonce is shorter than the capacity of the cipher. The use of a short nonce weakens the cipher.'))

        self.input_cache = ''
        self.mac_size = self.k.r//8
        self.block_size = self.mac_size - 3 # one byte for encoding the length,
                                            # one byte for the domain,
                                            # one byte for the padding
        self.cipher_round_byte = '\x00'
        self.mac_round_byte = '\x01'
        assert self.cipher_round_byte != self.mac_round_byte

        # get the underlying Keccak instance to the correct state to begin encryption/decryption
        self.encrypt_not_decrypt = True
        self.last_block = '\x00'*self.mac_size
        self.encrypt(key)
        self.last_block = self.emit_mac()[-self.mac_size:]
        self.encrypt(nonce)
        self.last_block = self.emit_mac()[-self.mac_size:]
        self.encrypt_not_decrypt=encrypt_not_decrypt

    def encrypt(self, m):
        """Encrypt the bytes m and return as much ciphertext as is available.
        There may not be ciphertext available every time this method is called.
        There is no guarantee about the length of the ciphertext compared to the length of the plaintext.
        Ciphertext chunks must be fed to the decrypt method in the same order that they are produced
            by the encrypt method.
        """
        if not self.encrypt_not_decrypt:
            raise KeccakError('This instance is intended for decryption, not encryption')
        if self.last_block is None:
            raise KeccakError('MAC has already been emitted, no further encryption may be performed')
        if not isinstance(m, bytes):
            raise TypeError("argument must be a bytes")

        self.input_cache += m
        retval = ''

        while len(self.input_cache) >= self.block_size:
            chunk, self.input_cache = self.input_cache[:self.block_size], \
                                      self.input_cache[self.block_size:]
            assert len(self.last_block) == self.mac_size
            assert len(chunk) == self.block_size
            retval += ''.join(imap(chr, imap(operator.xor, imap(ord, chunk),
                                                           imap(ord, self.last_block[:self.block_size]))))
            self.last_block = self.k(chr(len(chunk)) + chunk + self.cipher_round_byte)
            assert len(self.last_block) == self.mac_size
        assert len(retval) % self.block_size == 0
        return retval

    def emit_mac(self):
        """Call this method when all the plaintext has been supplied.
        This method will return any remaining ciphertext chunks and the MAC, concatenated.
        """
        if not self.encrypt_not_decrypt:
            raise KeccakError('This instance is intended for decryption, not encryption')
        if self.last_block is None:
            raise KeccakError('MAC has already been emitted, no further encryption may be performed')
        
        retval = ''
        assert len(self.input_cache) < self.block_size
        encoded_input_cache_len = chr(len(self.input_cache))
        self.input_cache = self.k.pad10star1(self.input_cache, self.block_size*8)
        assert len(self.input_cache) == self.block_size
        assert len(self.last_block) == self.mac_size
        final_ciphertext_block = ''.join(imap(chr, imap(operator.xor, imap(ord, self.input_cache),
                                                                      imap(ord, self.last_block[:self.block_size]))))
        assert len(final_ciphertext_block) == self.block_size
        retval += final_ciphertext_block

        self.last_block = self.k(encoded_input_cache_len + self.input_cache + self.mac_round_byte)
        assert len(self.last_block) == self.mac_size
        retval += self.last_block

        self.last_block = None
        self.input_cache = ''
        assert len(retval) == self.block_size + self.mac_size
        return retval

    def decrypt(self, m):
        """Decrypt the bytes m and return as much plaintext as is available.
        There may not be plaintext available every time this method is called.
        There is no guarantee about the length of the plaintext compared to the length of the ciphertext.
        Ciphertext chunks must be fed to the decrypt method in the same order that they were produced
            by the encrypt method
        """
        if self.encrypt_not_decrypt:
            raise KeccakError('This instance is intended for encryption, not decryption')
        if self.last_block is None:
            raise KeccakError('MAC has already been verified, no further decryption may be performed')
        if not isinstance(m, bytes):
            raise TypeError("argument must be a bytes")

        self.input_cache += m
        retval = ''

        while len(self.input_cache) > self.block_size+self.mac_size:
            chunk, self.input_cache = self.input_cache[:self.block_size], \
                                      self.input_cache[self.block_size:]
            assert len(self.last_block) == self.mac_size
            plain = ''.join(imap(chr, imap(operator.xor, imap(ord, chunk),
                                                         imap(ord, self.last_block[:self.block_size]))))

            self.last_block = self.k(chr(len(plain))+plain+self.cipher_round_byte)
            retval += plain
            assert len(self.last_block) == self.mac_size
        return retval

    def verify_mac(self, mac=None):
        """Call this method with the last chunk of ciphertext, or with the empty
        string or no argument if all ciphertext has already been supplied to
        decrypt.

        This method returns remaining plaintext if the MAC matched and the
        message is authentic. Otherwise, this method raises KeccakError if it
        has already been called or ValueError if the MAC did not match and the
        mesage has been tampered with.
        """
        if self.encrypt_not_decrypt:
            raise KeccakError('This instance is intended for encryption, not decryption')
        if self.last_block is None:
            raise KeccakError('MAC has already been verified')

        retval = ''
        if mac:
            retval += self.decrypt(mac)

        assert len(self.input_cache) > self.block_size
        chunk, mac = self.input_cache[:self.block_size], \
                     self.input_cache[self.block_size:]
        assert len(mac) == self.mac_size
        self.input_cache = ''
        assert len(self.last_block) == self.mac_size
        assert len(chunk) == self.block_size
        padded = ''.join(imap(chr, imap(operator.xor, imap(ord, chunk),
                                                      imap(ord, self.last_block[:self.block_size]))))
        plain = self.k.unpad10star1(padded)
        self.last_block = self.k(chr(len(plain))+padded+self.mac_round_byte)
        retval += plain

        if secure_compare(mac, self.last_block):
            self.last_block = None
            return retval
        else:
            self.last_block = None
            raise ValueError('MAC did not match')

__all__ = ['Keccak', 'KeccakError', 'KeccakRandom', 'KeccakCipher']
