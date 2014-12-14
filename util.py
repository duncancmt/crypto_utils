from itertools import imap
from operator import or_, xor

def ord(c, old_ord=ord):
    return long(old_ord(c))

def secure_compare(a,b):
    """Return 'a == b', but try not to leak timing information about the
    arguments. In the event that the length of the two strings are not
    equal, we leak the length of the right argument, b.
    """
    retval = True

    if not (isinstance(a, bytes) & isinstance(b, bytes) \
            & (a is not b) \
            & (len(a) != 0) & (len(b) != 0)):
        raise TypeError('Arguments must be distinct bytes objects with nonzero length')

    # copy b to a if the lengths of a and b are unequal
    retval &= len(a) == len(b)
    # some gymnastics we have to do because of small integer caching
    new_a = [None] * len(b)
    a_mask = -long(retval)
    b_mask = ~a_mask
    for i in xrange(len(new_a)):
        # It's conceivable that the pattern of memory accesses here may leak
        # information about the length of a. However, I belive that this is
        # unlikely
        new_a[i] = ord(a[i & a_mask]) & a_mask \
                   | ord(b[i & b_mask]) & b_mask
    a = ''.join(imap(chr, new_a))
    del new_a, b_mask, a_mask, i

    retval &= (reduce(or_, imap(xor, imap(ord, a),
                                     imap(ord, b)), 0L) == 0L)
    return retval

__all__ = ['secure_compare']
