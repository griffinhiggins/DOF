import lib


class BloomFilter(object):
    def __init__(self, B):
        self.B = B
        self.arr = [0] * B

    def add(self, e, B, q, uni_hash):
        for i in lib.hash(e, B, q, uni_hash):
            self.arr[i] = 1

    def __repr__(self):
        return "".join(str(i) if i == 0 else lib.strc('b', str(i)) for i in self.arr)
