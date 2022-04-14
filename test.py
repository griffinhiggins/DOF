from lib import strc
import random
import firewall as FW
import firewall_mod as FW_mod


def gen_ip():
    return f"192.{random.randrange(0,255)}.{random.randrange(0,255)}.{random.randrange(0,255)}"


def gen_rule():
    return f"{'TCP' if random.randrange(0,1) == 1 else 'UDP'} {gen_ip()}:{random.randrange(0,65535)} -> {gen_ip()}:{random.randrange(0,65535)}"


def test(blacklist, firewall, nodes, mode="ip"):
    firewall.firewall_init(nodes, blacklist)
    print(strc("g", "testing"))
    blocklist = set()
    for i in range(1000000):
        if i % 100000 == 0:
            print(f"{(i/1000000)*100}%")
        if mode == "ip":
            ip = gen_ip() if i % 10000 != 0 else random.choice(blacklist)
        else:
            ip = gen_rule() if i % 10000 != 0 else random.choice(blacklist)
        if firewall.firewall_eval(nodes, ip):
            blocklist.add(ip)
    print(strc("r", "blacklist"))
    print(len(set(blacklist)))
    print(strc("b", "blocklist"))
    print(len(blocklist))
    print(strc("y", "difference"))
    diff = blocklist - set(blacklist)
    print(len(diff))
    return diff


# ====================================
B = 4_000_000  # Number of bit locations in the Bloom filter
q = 4_000_037  # Smallest prime bigger than B
k = 20     # Number of hash functions used in checking
# set membership via the Bloom filter
m = 7      # Number of parties involved in the secret sharing scheme
t = 5      # Reconstruction threashold
# Modulus for the secret sharing scheme, (Smallest prime bigger than k)
N = 23
n = 10     # Number of blacklisted IPs
# ====================================

# Test IPs without proposed changes
blacklist = [gen_ip() for _ in range(n)]
firewall = FW.Firewall(B, q, k, m, t, N)
nodes = [FW.Node(i) for i in range(1, m+1)]
test(blacklist, firewall, nodes, "ip")

# Test rules without proposed changes
# blacklist = [gen_ip() for _ in range(n) ]
# firewall = FW_mod.Firewall(B, q, k, m, t, N, "tevssvauvttvaf")
# nodes = [FW_mod.Node(i) for i in range(1,m+1)]
# test(blacklist,firewall,nodes,"ip")

# Test IPs with proposed changes
# blacklist = [gen_rule() for _ in range(n) ]
# firewall = FW.Firewall(B, q, k, m, t, N)
# nodes = [FW.Node(i) for i in range(1,m+1)]
# test(blacklist,firewall,nodes,"rule")

# Test rules with proposed changes
# blacklist = [gen_rule() for _ in range(n) ]
# firewall = FW_mod.Firewall(B, q, k, m, t, N, "tevssvauvttvaf")
# nodes = [FW_mod.Node(i) for i in range(1,m+1)]
# test(blacklist,firewall,nodes,"rule")
