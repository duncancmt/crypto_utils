import cPickle
import string
import sys
import os.path
from itertools import imap, izip, count, chain
from intbytes import int2bytes, bytes2int, encode_varint, decode_varint
from math import log, floor, ceil
from keccak import Keccak

for path in sys.path:
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


def encode(s, compact=False):
    """From a byte string, produce a list of words that durably encodes the string.

    s: the byte string to be encoded
    compact: instead of using the length encoding scheme, pad by prepending a 1 bit

    The words in the encoding dictionary were chosen to be common and unambiguous.
    The encoding also includes a checksum. The encoding is constructed so that
    common errors are extremely unlikely to produce a valid encoding.
    """
    if not isinstance(s, bytes):
        raise TypeError("mnemonic.encode can only encode byte strings")

    k = Keccak()
    k.absorb(s)
    checksum_length = max(1, (len(s)-1).bit_length())
    checksum = k.squeeze(checksum_length)

    length = chr(checksum_length) if compact else encode_varint(len(s), endian='little')

    s += checksum
    s += length

    word_index = 0
    i = bytes2int(s)
    retval = [None] * int(floor(log(i, len(words)) + 1))
    for j in xrange(len(retval)):
        assert i > 0
        word_index += i % len(words)
        word_index %= len(words)
        retval[j] = words[word_index]
        i //= len(words)
    assert i == 0
    return tuple(retval)

def decode(w, compact=False, permissive=False):
    """From a list of words, or a whitespace-separated string of words, produce
    the original string that was encoded.

    w: the list of words, or whitespace delimited words to be decoded
    compact: compact encoding was used instead of length encoding
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
    s = int2bytes(i)

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
    i = bytes2int(reversed(k.squeeze(int(ceil(length / 4.0)))))

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

__all__ = ['encode', 'decode', 'randomart']
