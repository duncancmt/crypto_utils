try:
    from hmac import compare_digest as secure_compare
except ImportError:
    from operator import or_, xor
    from itertools import imap
    
    def secure_compare(a,b):
        """Return 'a == b', but try not to leak timing information about the
        arguments. In the event that the length of the two strings are not
        equal, we leak the length of the right argument, b.
        """
        error = TypeError('Arguments must be bytes with the same length')
        retval = True
        
        if not isinstance(a, bytes):
            retval = error
        if not isinstance(b, bytes):
            retval = error
        if isinstance(retval, TypeError):
            raise retval
    
        if len(a) == len(b):
            a,b = a[::],b[::]
            retval &= True
        if len(a) != len(b):
            a,b = b[::],b[::]
            retval &= False

        retval &= (reduce(or_, imap(xor, imap(ord, a),
                                         imap(ord, b)), 0) == 0)
        return retval

__all__ = ['secure_compare']
