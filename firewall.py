import lib
import SSS
import BF
import random

verbose = False


class Firewall(object):
    def __init__(self, B, q, k, m, t, N):
        # BF params
        self.B = B
        self.q = q
        self.k = k
        self.uni_hash = [
            (random.randrange(1, self.q-1),
             random.randrange(1, self.q-1))
            for _ in range(self.k)
        ]
        # SSS params
        self.m = m
        self.t = t
        self.N = N

    def firewall_init(self, nodes, blacklist):
        # Create temp BF
        bf = BF.BloomFilter(self.B)
        # Add blacklisted IPs
        for ip in blacklist:
            bf.add(ip, self.B, self.q, self.uni_hash)
        # Create and distribute shares to nodes
        # and set node values to align with firewall
        for bit in bf.arr:
            bit_shares = SSS.gen_shares(self.N, self.m, self.t, bit)
            for node, share in zip(nodes, bit_shares):
                node.shares.append(share)
                node.B = self.B
                node.q = self.q
                node.k = self.k
                node.uni_hash = self.uni_hash

    def firewall_eval(self, nodes, ip):
        # Initalize the evaluation
        # For all the nodes send them the
        # IP and recover the shares
        lib.printv(verbose, f"RECOVERING SHARES FROM EACH NODE")
        shares = [node.recover_share(ip) for node in nodes]
        # Sample t shares and sum the
        # shared bits
        lib.printv(verbose, f"SAMPLING RANDOM SHARES")
        sample = random.sample(shares, self.t)
        lib.printv(verbose, f"\tSAMPLE: {sample}")
        result = SSS.recover_secret(sample, self.N)
        lib.printv(verbose, f"\tRESULT: {result}")
        ret = result == self.k
        # Return wheather or not to block the IP
        lib.printv(verbose, "sum(RESULTS) == k" if ret else "sum(RESULTS) != k")
        return ret


class Node(object):
    def __init__(self, id):
        self.id = id
        self.shares = []
        self.B = None
        self.q = None
        self.uni_hash = None

    def recover_share(self, ip):
        lib.printv(verbose, f"\t{ip} RECIEVED AT NODE_{self.id}")
        shares = [self.shares[i]
                  for i in lib.hash(ip,  self.B, self.q, self.uni_hash)]
        lib.printv(
            verbose, f"\tNODE_{self.id} SENDING SHARES {shares} TO FIREWALL")
        return (self.id, sum([i for _, i in shares]))
