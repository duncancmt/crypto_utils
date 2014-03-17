import random
import math

try:
    from gmpy2 import mpz as _mpz, is_prime as _is_prime
    has_gmpy = True
except ImportError:
    try:
        from gmpy import mpz as _mpz, is_prime as _is_prime
        has_gmpy = True
    except ImportError:
        import warnings
        warnings.warn("Not having gmpy2 or gmpy makes this at least 10x slower")
        has_gmpy = False

def gen_prime(bits=256, certainty=128, random=random):
    """
    Randomly generate a probable prime with a given number of binary digits
    With probability 2^-certainty, this function returns a non-prime
    """

    certainty += int(math.ceil(math.log(bits*math.log(2),2)))
    while True:
        candidate = random.getrandbits(bits - 1) | (1 << (bits - 1))

        if candidate & 1 == 0:
            candidate += 1

        if mr_test(candidate, certainty=certainty):
            return candidate

def mr_test(n, certainty=128, rounds=None, slow=False):
    """
    returns True if n is possibly prime, False if n is definitely composite
    2^-certainty of numbers for which this returns True will mistakenly be composite
    certainty defaults to 128
    If rounds is supplied, that many rounds will be run, ignoring certainty
    If slow is True, we will only use the pure python implementation
    """
    if rounds is None:
        rounds = int(math.ceil(math.log(1 - 2**certainty - math.log(n) + (2**certainty)*math.log(n), 2)/2))

    if (not isinstance(n, (int, long))) or n < 2 or n % 2 == 0:
        return False

    if has_gmpy and not slow:
        n = _mpz(n)
        return _is_prime(n, rounds)

    # turn (n-1) into (2**s) * m
    s = 0
    m = n-1
    while not m&1:  # while m is even
        m >>= 1
        s += 1
    assert 2**s * m == n - 1

    def mr_round(m,s,a,n):
        y = pow(a,m,n)
        if y == 1:
            return True
        for _ in xrange(s):
           if y == n-1:
               return True
           y = pow(y,2,n)       
        return False

    for a in ( random.randrange(2,n) for _ in xrange(rounds) ):
        if not mr_round(m,s,a,n):
            return False
    return True

__all__ = ['gen_prime', 'mr_test']
