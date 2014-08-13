import cPickle
import string
import sys
import os.path
from itertools import imap, izip, count, chain
from intbytes import int2bytes, bytes2int, encode_varint, decode_varint
from math import log, floor, ceil
from keccak import Keccak

for path in sys.path + [None]:
    if path is None:
        raise IOError("Could not find words.pkl")
    words_path = os.path.join(path, 'words.pkl')
    if os.path.isfile(words_path):
        break
    words_path = os.path.join(path, 'bigfiles', 'words.pkl')
    if os.path.isfile(words_path):
        break
words = cPickle.Unpickler(open(words_path,'rb')).load()
rwords = dict(izip(words,count()))

def dldist(s, n):
    def flatten(lol):
        return chain.from_iterable(lol)

    def onedldist(s):
        num_deletions = len(s)
        num_insertion_positions = len(s)+1
        num_insertion_values = len(string.ascii_lowercase)
        num_insertions = num_insertion_positions*num_insertion_values
        num_transpositions = len(s)-1
        num_substitution_positions = len(s)
        num_substitution_values = len(string.ascii_lowercase)
        num_substitutions = num_substitution_positions*num_substitution_values

        # deletions
        for j in xrange(num_deletions):
            yield s[:j]+s[j+1:]
        # insertions
        for j in xrange(num_insertion_positions):
            for k in xrange(num_insertion_values):
                yield s[:j]+string.ascii_lowercase[k]+s[j:]
        # transpositions
        for j in xrange(num_transpositions):
            yield s[:j]+s[j+1]+s[j]+s[j+2:]
        # substitutions
        for j in xrange(num_substitution_positions):
            for k in xrange(num_substitution_values):
                yield s[:j]+string.ascii_lowercase[k]+s[j+1:]
        raise StopIteration

    if n == 1:
        return set(onedldist(s))
    else:
        return set(flatten(imap(onedldist, dldist(s, n-1))))


def pad_and_checksum(s, compact, checksum):
    """Apply length padding and checksum to a string"""
    assert isinstance(s, bytes)
    if checksum:
        k = Keccak()
        k.absorb(s)
        checksum_length = max(1, (len(s)-1).bit_length())
        checksum = k.squeeze(checksum_length)

        length = chr(checksum_length) if compact else encode_varint(len(s), endian='little')
        return s + checksum + length
    else:
        length = '\x01' if compact else encode_varint(len(s), endian='little')
        return s + length

def unpad_and_checksum(s, compact, checksum):
    """Check length padding and checksum for a string
    return the string without length padding or checksum
    raise ValueError if either are wrong"""
    assert isinstance(s, bytes)
    if checksum:
        if compact:
            checksum_length = ord(s[-1])
            consumed = 1
            length = len(s) - checksum_length - consumed
        else:
            (length, consumed) = decode_varint(s, endian='little')
            checksum_length = max(1, (length-1).bit_length())

        s = s[:-consumed]
        s, checksum = s[:-checksum_length], s[-checksum_length:]
        if len(s) != length:
            raise ValueError("Invalid length")

        k = Keccak()
        k.absorb(s)
        if k.squeeze(checksum_length) != checksum:
            raise ValueError("Invalid checksum")

        return s
    else:
        if compact:
            return s[:-1]
        else:
            (length, consumed) = decode_varint(s, endian='little')
            s = s[:-consumed]
            if len(s) != length:
                raise ValueError("Invalid length")
            return s


def encode(s, compact=False, checksum=True):
    """From a byte string, produce a list of words that durably encodes the string.

    s: the byte string to be encoded
    compact: instead of using the length encoding scheme, pad by appending a single byte
    checksum: append a checksum to the byte string before encoding

    The words in the encoding dictionary were chosen to be common and unambiguous.
    The encoding is constructed so that common errors are extremely unlikely to
    produce a valid encoding.
    """
    if not isinstance(s, bytes):
        raise TypeError("mnemonic.encode can only encode byte strings")

    s = pad_and_checksum(s, compact, checksum)

    word_index = 0
    i = bytes2int(s, endian='little')
    retval = [None] * int(floor(log(i, len(words)) + 1))
    for j in xrange(len(retval)):
        assert i > 0
        word_index += i % len(words)
        word_index %= len(words)
        retval[j] = words[word_index]
        i //= len(words)
    assert i == 0
    return tuple(retval)

def decode(w, compact=False, checksum=True, permissive=False):
    """From a list of words, or a whitespace-separated string of words, produce
    the original byte string that was encoded.

    w: the list of words, or whitespace delimited words to be decoded
    compact: compact encoding was used instead of length encoding
    checksum: encoded string had a checksum appended before encoding
    permissive: if there are spelling errors, correct them instead of throwing
        an error (will still throw ValueError if spelling can't be corrected)

    Raises ValueError if the encoding is invalid.
    """
    if isinstance(w, bytes):
        w = w.split()

    indexes = [None]*len(w)
    for i,word in enumerate(w):
        if word in rwords:
            indexes[i] = rwords[word]
        elif permissive:
            for nearby in dldist(word, 1):
                if nearby in rwords:
                    indexes[i] = rwords[nearby]
                    break
        if indexes[i] is None:
            raise ValueError('Unrecognized word %s' % repr(word))

    # because we don't directly encode the mantissas, we have to extract them
    values = reduce(lambda (last_index, accum), index: (index,
                                                        accum + [(index - last_index) % len(words)]),
                    indexes,
                    (0, []))[1]
    i = sum(mantissa * len(words)**radix for radix, mantissa in enumerate(values))
    # we don't need to worry about truncating null bytes because of the encoded length on the end
    s = unpad_and_checksum(int2bytes(i, endian='little'), compact, checksum)

    return s

def randomart(s, height=9, width=17, length=64, border=True, tag=''):
    """Produce a easy to compare visual representation of a string.
    Follows the algorithm laid out here http://www.dirk-loss.de/sshvis/drunken_bishop.pdf
    with the substitution of Keccak for MD5.

    s: the string to create a representation of
    height: (optional) the height of the representation to generate, default 9
    width: (optional) the width of the representation to generate, default 17
    length: (optional) the length of the random walk, essentially how many
        points are plotted in the representation, default 64
    border: (optional) whether to put a border around the representation,
        default True
    tag: (optional) a short string to be incorporated into the border,
        does nothing if border is False, defaults to the empty string
    """
    k = Keccak()
    k.absorb(s)
    # we reverse the endianness so that increasing length produces a radically
    # different randomart
    i = bytes2int(reversed(k.squeeze(int(ceil(length / 4.0)))),
                  endian='little')

    field = [ [0 for _ in xrange(width)]
              for __ in xrange(height) ]
    start = (height // 2,
             width // 2)
    position = start
    directions = ((-1, -1),
                  (-1, 1),
                  (1, -1),
                  (1, 1))
    for j in xrange(length):
        row_off, col_off = directions[(i>>(j*2)) % 4]
        position = (min(max(position[0] + row_off, 0),
                        height - 1),
                    min(max(position[1] + col_off, 0),
                        width - 1))
        field[position[0]][position[1]] += 1

    field[start[0]][start[1]] = 15
    field[position[0]][position[1]] = 16
    chars = ' .o+=*BOX@%&#/^SE'

    if border:
        if len(tag) > width - 2:
            tag = tag[:width-2]
        if tag:
            tag_pad_len = (width - len(tag) - 2) / 2.0
            first_row = '+' + ('-'*int(floor(tag_pad_len))) \
                        + '['+tag+']' \
                        + ('-'*int(ceil(tag_pad_len))) + '+\n'
        else:
            first_row = '+' + ('-'*width) + '+\n'
        last_row = '\n+' + ('-'*width) + '+'
        return first_row \
               + '\n'.join('|'+''.join(chars[cell] for cell in row)+'|'
                           for row in field) \
               + last_row
    else:
        return '\n'.join(''.join(chars[cell] for cell in row)
                         for row in field)


def nCk(n, k):
    """Binomial coefficient function"""
    if n < k or k < 0:
        return 0
    else:
        ntok = 1
        ktok = 1
        for t in xrange(1, min(k, n-k) + 1):
            ntok *= n
            ktok *= t
            n -= 1
        return ntok // ktok

rank_length_offsets = [None]*len(words)
rank_length_offsets[0] = 0
rank_length_offsets[1] = 0
def get_rank_length_offset(length):
    """Given the length of a unordered encoding,
    return the highest number that can be represented by an encoding 1 shorter."""
    if rank_length_offsets[length] is None:
        for i in xrange(length-1, -1, -1):
            if rank_length_offsets[i] is not None:
                break
        for j in xrange(i, length):
            rank_length_offsets[j+1] = rank_length_offsets[j] + nCk(len(words), j)
        return get_rank_length_offset(length)
    else:
        return rank_length_offsets[length]

def encode_unordered(s, compact=False, checksum=True):
    """From a byte string, produce an unordered set of words that durably encodes the string.

    s: the byte string to be encoded
    compact: instead of using the length encoding scheme, pad by appending a single byte
    checksum: append a checksum to the byte string before encoding

    The words in the encoding dictionary were chosen to be common and unambiguous.
    The encoding is constructed so that common errors are extremely unlikely to
    produce a valid encoding.
    """
    n = bytes2int(pad_and_checksum(s, compact, checksum), endian='little')
    upper = len(words)+1
    lower = 0
    minn = n+1
    maxn = n
    while minn > n or n >= maxn:
        length = (upper + lower) // 2
        minn = get_rank_length_offset(length)
        maxn = get_rank_length_offset(length+1)
        if n >= maxn:
            lower = length
        else: # n < minn
            upper = length


    n -= get_rank_length_offset(length)
    retval = [None] * length
    for i in xrange(length, 0, -1):
        upper = len(words)
        lower = 0
        minn = n+1
        maxn = n
        while minn > n or n >= maxn:
            c = (upper + lower) // 2
            minn = nCk(c, i)
            maxn = nCk(c+1, i)
            if n >= maxn:
                lower = c
            else: # n < minn
                upper = c
        retval[i-1] = words[c]
        n -= minn
    return frozenset(retval)


def decode_unordered(w, compact=False, checksum=True, permissive=False):
    """From an unordered set of words, or a whitespace-separated string of words, produce
    the original byte string that was encoded.

    w: the list of words, or whitespace delimited words to be decoded
    compact: compact encoding was used instead of length encoding
    checksum: encoded string had a checksum appended before encoding
    permissive: if there are spelling errors, correct them instead of throwing
        an error (will still throw ValueError if spelling can't be corrected)

    Raises ValueError if the encoding is invalid.
    """
    if isinstance(w, bytes):
        w = w.split()

    digits = [None]*len(w)
    for i,word in enumerate(w):
        if word in rwords:
            digits[i] = rwords[word]
        elif permissive:
            for nearby in dldist(word, 1):
                if nearby in rwords:
                    digits[i] = rwords[nearby]
                    break
        if digits[i] is None:
            raise ValueError('Unrecognized word %s' % repr(word))

    digits.sort()
    n = get_rank_length_offset(len(digits))
    for i, d in enumerate(digits):
        n += nCk(d, i+1)
    s = int2bytes(n, endian='little')
    return unpad_and_checksum(s, compact, checksum)

__all__ = ['encode', 'decode', 'randomart', 'encode_unordered', 'decode_unordered']

if __name__ == '__main__':
    import random
    try:
        iterations = int(sys.argv[1])
    except:
        iterations = 1000

    print >>sys.stderr, "\nTesting encode/decode ordered, not compact, with checksum"
    for _ in xrange(iterations):
        n = random.getrandbits(1024)
        s = int2bytes(n, endian='little')
        r = encode(s, compact=False, checksum=True)
        s = decode(r, compact=False, checksum=True)
        m = bytes2int(s, endian='little')
        assert n == m, (n, r, m)
        print >>sys.stderr, '.',
        sys.stderr.flush()

    print >>sys.stderr, "\nTesting encode/decode ordered, compact, with checksum"
    for _ in xrange(iterations):
        n = random.getrandbits(1024)
        s = int2bytes(n, endian='little')
        r = encode(s, compact=True, checksum=True)
        s = decode(r, compact=True, checksum=True)
        m = bytes2int(s, endian='little')
        assert n == m, (n, r, m)
        print >>sys.stderr, '.',
        sys.stderr.flush()

    print >>sys.stderr, "\nTesting encode/decode ordered, not compact, without checksum"
    for _ in xrange(iterations):
        n = random.getrandbits(1024)
        s = int2bytes(n, endian='little')
        r = encode(s, compact=False, checksum=False)
        s = decode(r, compact=False, checksum=False)
        m = bytes2int(s, endian='little')
        assert n == m, (n, r, m)
        print >>sys.stderr, '.',
        sys.stderr.flush()

    print >>sys.stderr, "\nTesting encode/decode ordered, compact, without checksum"
    for _ in xrange(iterations):
        n = random.getrandbits(1024)
        s = int2bytes(n, endian='little')
        r = encode(s, compact=True, checksum=False)
        s = decode(r, compact=True, checksum=False)
        m = bytes2int(s, endian='little')
        assert n == m, (n, r, m)
        print >>sys.stderr, '.',
        sys.stderr.flush()

    print >>sys.stderr, "\nTesting encode/decode unordered, not compact, with checksum"
    for _ in xrange(iterations):
        n = random.getrandbits(1024)
        s = int2bytes(n, endian='little')
        r = list(encode_unordered(s, compact=False, checksum=True))
        random.shuffle(r)
        s = decode_unordered(r,compact=False, checksum=True)
        m = bytes2int(s,endian='little')
        assert n == m, (n, r, m)
        print >>sys.stderr, '.',
        sys.stderr.flush()

    print >>sys.stderr, "\nTesting encode/decode unordered, compact, with checksum"
    for _ in xrange(iterations):
        n = random.getrandbits(1024)
        s = int2bytes(n, endian='little')
        r = list(encode_unordered(s, compact=True, checksum=True))
        random.shuffle(r)
        s = decode_unordered(r,compact=True, checksum=True)
        m = bytes2int(s,endian='little')
        assert n == m, (n, r, m)
        print >>sys.stderr, '.',
        sys.stderr.flush()

    print >>sys.stderr, "\nTesting encode/decode unordered, not compact, without checksum"
    for _ in xrange(iterations):
        n = random.getrandbits(1024)
        s = int2bytes(n, endian='little')
        r = list(encode_unordered(s, compact=False, checksum=False))
        random.shuffle(r)
        s = decode_unordered(r,compact=False, checksum=False)
        m = bytes2int(s,endian='little')
        assert n == m, (n, r, m)
        print >>sys.stderr, '.',
        sys.stderr.flush()

    print >>sys.stderr, "\nTesting encode/decode unordered, compact, without checksum"
    for _ in xrange(iterations):
        n = random.getrandbits(1024)
        s = int2bytes(n, endian='little')
        r = list(encode_unordered(s, compact=True, checksum=False))
        random.shuffle(r)
        s = decode_unordered(r,compact=True, checksum=False)
        m = bytes2int(s,endian='little')
        assert n == m, (n, r, m)
        print >>sys.stderr, '.',
        sys.stderr.flush()

    print >>sys.stderr, "\nDone self testing"
