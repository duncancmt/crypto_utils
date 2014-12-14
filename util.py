from itertools import imap
from operator import or_, xor
def secure_compare(a,b):
    """Return 'a == b', but try not to leak timing information about the
    arguments. In the event that the length of the two strings are not
    equal, we leak the length of the right argument, b.
    """
    retval = True

    if not (isinstance(a, bytes) & isinstance(b, bytes)):
        raise TypeError('Arguments must be bytes')

    # copy b to a if the lengths of a and b are unequal
    retval &= len(a) == len(b)
    # some gymnastics we have to do because of small integer caching
    new_a = [None] * ( len(a) & -retval\
                       | len(b) & ~-retval )
    for i in xrange(len(new_a)):
        # doing `% len(a)' here suppresses errors, but may leak information about
        # the length of a through cache timing
        new_a[i] = long(ord(a[i % len(a)])) & -retval \
                   | long(ord(b[i])) & ~-retval
    a = ''.join(imap(chr, new_a))
    del new_a
    del i

    retval &= (reduce(or_, imap(xor, imap(ord, a),
                                     imap(ord, b)), 0) == 0)
    return retval

__all__ = ['secure_compare']
