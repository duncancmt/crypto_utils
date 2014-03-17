from __future__ import division
from random import Random, BPF
from math import ceil as _ceil, log as _log
from types import MethodType as _MethodType, BuiltinMethodType as _BuiltinMethodType
from warnings import warn as _warn

class CorrectRandom(Random):
    def random(self):
        return float(self.getrandbits(BPF)) / 2**BPF

    def _randbelow(self, n, int=int, _maxwidth=1L<<BPF,
                   _Method=_MethodType, _BuiltinMethod=_BuiltinMethodType):
        """Return a random int in the range [0,n)

        Handles the case where n has more bits than returned
        by a single call to the underlying generator.
        """

        try:
            getrandbits = self.getrandbits
        except AttributeError:
            pass
        else:
            # Only call self.getrandbits if the original random() builtin method
            # has not been overridden or if a new getrandbits() was supplied.
            # This assures that the two methods correspond.
            if type(self.random) is _BuiltinMethod or type(getrandbits) is _Method:
                k = (n-1).bit_length()   # 2**k > n-1 > 2**(k-2)
                r = getrandbits(k)
                while r >= n:
                    r = getrandbits(k)
                return r
        if n >= _maxwidth:
            _warn("Underlying random() generator does not supply \n"
                "enough bits to choose from a population range this large")
        return int(self.random() * n)

    def choice(self, seq):
        """Choose a random element from a non-empty sequence."""
        if len(seq) <= 1:
            return seq[0] # raises IndexError if seq is empty
        return seq[self._randbelow(len(seq))]

    def shuffle(self, x, random=None):
        """x -> shuffle list x in place; return None."""

        _randbelow = self._randbelow
        for i in reversed(xrange(1, len(x))):
            # pick an element in x[:i+1] with which to exchange x[i]
            j = _randbelow(i+1)
            x[i], x[j] = x[j], x[i]

    def sample(self, population, k):
        """Chooses k unique random elements from a population sequence.

        Returns a new list containing elements from the population while
        leaving the original population unchanged.  The resulting list is
        in selection order so that all sub-slices will also be valid random
        samples.  This allows raffle winners (the sample) to be partitioned
        into grand prize and second place winners (the subslices).

        Members of the population need not be hashable or unique.  If the
        population contains repeats, then each occurrence is a possible
        selection in the sample.

        To choose a sample in a range of integers, use xrange as an argument.
        This is especially fast and space efficient for sampling from a
        large population:   sample(xrange(10000000), 60)
        """

        # Sampling without replacement entails tracking either potential
        # selections (the pool) in a list or previous selections in a set.

        # When the number of selections is small compared to the
        # population, then tracking selections is efficient, requiring
        # only a small set and an occasional reselection.  For
        # a larger number of selections, the pool tracking method is
        # preferred since the list takes less space than the
        # set and it doesn't suffer from frequent reselections.

        n = len(population)
        if not 0 <= k <= n:
            raise ValueError("sample larger than population")
        _randbelow = self._randbelow
        result = [None] * k
        setsize = 21        # size of a small set minus size of an empty list
        if k > 5:
            setsize += 4 ** _ceil(_log(k * 3, 4)) # table size for big sets
        if n <= setsize or hasattr(population, "keys"):
            # An n-length list is smaller than a k-length set, or this is a
            # mapping type so the other algorithm wouldn't work.
            pool = list(population)
            for i in xrange(k):         # invariant:  non-selected at [0,n-i)
                j = _randbelow(n-i)
                result[i] = pool[j]
                pool[j] = pool[n-i-1]   # move non-selected item into vacancy
        else:
            try:
                selected = set()
                selected_add = selected.add
                for i in xrange(k):
                    j = _randbelow(n)
                    while j in selected:
                        j = _randbelow(n)
                    selected_add(j)
                    result[i] = population[j]
            except (TypeError, KeyError):   # handle (at least) sets
                if isinstance(population, list):
                    raise
                return self.sample(tuple(population), k)
        return result

__all__ = ["CorrectRandom"]

try:
    from proxy import BetterProxy, getattr_static
    class CorrectRandomWrapper(BetterProxy):
        for name in CorrectRandom.__dict__.iterkeys():
            locals()[name] = getattr_static(CorrectRandom, name)
        del name
    __all__.append("CorrectRandomWrapper")
except ImportError:
    pass
