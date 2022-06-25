
# Excerpts from CS6415: <em>Firewall Attacks and Mitigation Techniques<em> (Higgins, G. & Vaishnavi, M. 2022)

## Distributed Oblivious Firewall Model

As  part of  our work,  we model  the Distributed  Oblivious Firewall  scheme as
outlined in [4]. Here, the reader is  expected to be familiar with Bloom Filters
and Shamir  Secret Sharing  since it is  not practical to  explain them  here in
detail.  However, the  reader is  encouraged  to refer  to [4],  [10], [11]  for
further reading  in these areas.  In the remainder  of this section,  we briefly
outline the most important functions  developed from equations and algorithms in
[4, Alg. 2  and 3] used in  our model. Additionally, we also  cover our proposed
improvements  to the  model and  future directions  of our  work. Our  model was
developed  entirely using  Python 3.  Our  codebase implements  a Shamir  Secret
Sharing scheme in SSS.py, Bloom  filter in BF.py, Distributed Oblivious Firewall
scheme in firewall.py, helper functions in lib.py, a test script in test.py, and
a Distributed  Oblivious Firewall scheme  with our proposed changes  in firewall
mod.py [12].

### A. Firewall Functions
In the  firewall initialization  function, shown  in Listing 1,  a list  of node
objects and a blacklist of IPs are received as arguments to the function in line 1. 
In line 2 a Bloom filter is  instantiated using B bits and k independent hash
functions. Next, the  IPs in the blacklist  are hashed into the  Bloom filter in
lines 3  and 4. Afterward in  lines 5-8 each bit  in the Bloom filter  is secret
shared using Shamir Secret Sharing, bounded  by a predefined minimum and maximum
share reconstruction threshold, namely t and m respectively.
```python
def firewall_init(self, nodes, blacklist):
    bf = BF.BloomFilter(self.B)
    for ip in blacklist:
        bf.add(ip, self.B, self.q, self.uni_hash)
    for bit in bf.arr:
        bit_shares = SSS.gen_shares(self.N, self.m, self.t, bit)
        for node, share in zip(nodes, bit_shares):
            node.shares.append(share)
            node.B = self.B
            node.q = self.q
            node.k = self.k
            node.uni_hash = self.uni_hash
```
Listing 1: Firewall Initialization

Additional pieces  of data are  copied from the firewall  to each node  in lines
9-11. Lastly,  it is important to  note that the  Bloom filter is not  stored or
used after  the function completes.  Next, in the firewall  evaluation function,
shown in  Listing 2,  a list of  node objects  and a single  IP are  received as
arguments to the function  in line 1. In line 2, the IP  is passed to each node,
and a list of m shares is recovered.
```python
def firewall_eval(self, nodes, ip):
    shares = [node.recover_share(ip) for node in nodes]
    sample = random.sample(shares, self.t)
    result = SSS.recover_secret(sample, self.N)
    return result == self.k
```
Listing 2: Firewall Evaluation

On  line 3,  a minimum  threshold of  t shares  is randomly  sampled from  the m
recovered shares. Next, the secret is reconstructed and the equality between the
secret and number  of hash functions k is  returned in lines 4 and  5. Our model
differs slightly in  this regard from [4,  Alg. 3], as only one  sample is taken
instead  of multiple.  The reason  for taking  multiple samples  has to  do with
detecting and identifying attackers rather than determining outright correctness
of the  reconstructed secret.  Regardless, the  basic functionality  remains the
same.

In the recover share function, shown in Listing 3, the nodes return their shares
for a given input IP,  in line 1. In line 2 and 3 the IP  is hashed using k hash
functions. All the  values at the indices  of the k digests in  the shared Bloom
filter  are returned  into  a list.  In  line  4, a  tuple  containing the  node
identifier  and the  sum  of its  shares  are returned.  The  values are  summed
since  Shamir Secret  Sharing  has an  additive property  that  helps limit  the
communication complexity (i.e., one tuple is sent rather than k tuples).
```python
def recover_share(self, ip):
    shares = [self.shares[i] for i in lib.hash_all(ip, self.B)]
    return (self.id, sum([i for _, i in shares]))
```
Listing 3: Firewall Recover Share

### B. Shamir Secret Sharing Functions

In the  Shamir Secret  Sharing share  generation function,  shown in  Listing 4,
several parameters are used representing the modulus N, maximum number of shares
m, minimum number  of shares t, and secret value  S in line 1. In line  2, t - 1
random coefficients are chosen to construct  the secret polynomial. In lines 3-8
shares of the secret  polynomial are constructed and appended to  a list that is
then returned in line 9.
```python
def gen_shares(N, m, t, S):
    C = [random.randrange(0, N) for _ in range(t - 1)]
    s = []
    for x in range(1, m + 1):
        p = 0
        for t, c in enumerate(C):
            p += c * x ** (t + 1)
        s.append((x, (p + S) % N))
    return s
```
Listing 4: Share Generation

In the  Shamir Secret Sharing  secret recovery function,  shown in Listing  5, a
list of  shares and a  modulus N  are passed as  parameters in line  1. Lagrange
Polynomial Interpolation is  used in lines 2-9, to reconstruct  the secret value
from a minimal threshold of t or  more shares. One notable part of the algorithm
occurs in line 8  where the modular inverse is needed  since the calculations in
our model are computed over a finite field.
```python
def recover_secret(shares, N):
    s = 0
    for j, sj in enumerate(shares):
        xj, yj = sj
        for k, sk in enumerate(shares):
            xk, _ = sk
            if k != j:
                yj *= -xk * pow(xj - xk, -1, N)
        s += yj
    return s % N
```
Listing 5: Secret Recovery

### C. Proposed Changes

A small theoretic issue with the current implementation is that it unnecessarily
leaks information  about the IPs being  queried to the distributed  nodes during
firewall evaluation.  While this is  needed in the  case of a  truly distributed
topology, where  any node can  act as a  gateway, it is  not needed in  the case
where a constrained topology is employed (i.e.: a master node overseeing several
distributed nodes). We  propose two minor changes to the  model to alleviate the
information  leakage  and improve  query  privacy  in the  constrained  topology
setting. We  propose that during  the initialization phase, rather  than hashing
plaintext IPs into  the Bloom filter, a  keyed hash of the IP  is instead hashed
into the Bloom filter.  In this case, the master node keeps  the key used during
the firewall initialization and  thus is the only node that  can request a valid
query to  evaluate an IP.  Correspondingly, during the firewall  evaluation when
the master node wishes to evaluate an IP it must hash the IP in conjunction with
its key before sending the digest to the distributed nodes for evaluation. These
changes  are shown  in lines  5  and 18  of  Listing 6  within their  respective
functions.
```python
def firewall_init(self, nodes, blacklist):
    bf = BF.BloomFilter(self.B)
    for ip in blacklist:
        # ===MODIFIED===
        bf.add(lib.sha256(ip + self.key))
        # ==============
    for bit in bf.arr:
        bit_shares = SSS.gen_shares(self.N, self.m, self.t, bit)
        for node, share in zip(nodes, bit_shares):
            node.shares.append(share)

def firewall_eval(self, nodes, ip):
    # ===MODIFIED===
    shares = [node.recover_share(lib.sha256(ip + self.key)) for node in nodes]
    # ==============
    sample = random.sample(shares, self.t)
    result = SSS.recover_secret(sample, self.N)
    return result == self.k
```
Listing 6: Firewall Proposed Changes

Under this  modified scheme  the distributed  nodes can no  longer learn  the IP
being sent  to them since they  only receive a  keyed hash from the  master node
that  they  cannot  feasibly  reverse.  Therefore, the  privacy  of  queries  is
substantially improved.  However, a limitation of  this proposal is that  a node
could theoretically match two received digests  and discern that they are of the
same plaintext  or IP  even if  they don’t  know what  the IP  is or  what its
evaluation outcome is (i.e., blocked or forwarded).

### D. Remarks
One  of the  most  difficult parts  of  implementing this  scheme,  as noted  by
the  authors, is  selecting  the  appropriate parameters  for  the Bloom  filter
construction such that false positives  are not excessively generated. We tested
our model  against 1,000,000  randomly selected  IPs in  the range  192.0.0.0 to
192.255.255.255. Additionally, we randomly selected ten random IPs in the stated
range  that we  placed on  our blacklist.  Furthermore, at  every 10,000th  test
iteration, we randomly selected a blacklisted IP for testing to ensure our model
could  correctly  block it.  However,  we  were  primarily interested  in  false
positives (i.e., falsely  blocked IPs). We ran the experiment  several times and
found that by increasing  the number of hash functions k and the  size B of bits
in the Bloom filter we could generate  smaller and smaller error rates. With a k
value  of ten  and a  B value  of 1,000,000,  our model  generated eleven  false
positives. With  a k value of  20 and a B  value of 4,000,000 our  model instead
generated  three  false positives.  Depending  on  the application  these  false
positives may  or may not  be acceptable. However,  it is important  to consider
that this  limitation is somewhat offset  by the protection the  scheme provides
against  inside attackers.  Additionally, since  the  IPs on  the blacklist  are
merely strings, we were able to  extend our blacklist to include filtering rules
with source  and destination  IP and port  as well as  IP protocol.  We observed
identical findings in  this case and when testing our  proposed changes. 

As part of our future work, we  are considering adding our to proposal where the
master node  sends both real  and fake queries to  different groups such  that a
node  could only  guess with  some probability  that it  received a  real query.
Additionally, now that  we have successfully developed and tested  our model for
correctness we  are looking to  fine-tune our codebase  and test our  model with
larger blacklists,  Bloom filters, and  hash functions. Afterward our  next step
would  be to  implement the  scheme in  a real-world  firewall under  controlled
conditions.

# References

[1] K. Nagendran, S.  Balaji, B. A. Raj, P. Chanthrika,  and R. Amirthaa, “Web
application firewall evasion techniques,” in 2020 6th International Conference
on Advanced Computing and Communication Systems (ICACCS), 2020, pp. 194–199.

[2]  A.  X.  Liu,  A.  R.  Khakpour,  J.  W.  Hulst,  Z.  Ge,  D.  Pei,  and  J.
Wang,  “Firewall fingerprinting  and  denial of  firewalling attacks,”  IEEE
Transactions on Information Forensics and Security,  vol. 12, no. 7, pp. 1699–
1712, 2017.

[3] K. Salah, K. Elbadawi, and  R. Boutaba, “Performance modeling and analysis
of network  firewalls,” IEEE Transactions  on Network and  Service Management,
vol. 9, no. 1, pp. 12–21, 2012.

[4]  K.  Goss  and  W.  Jiang, “Distributing  and  obfuscating  firewalls  via
oblivious bloom filter evaluation,” CoRR, vol. abs/1810.01571, 2018. [Online].
Available: http://arxiv.org/abs/1810.01571

[5] D. K. Banwal, S. Kumar, and  I. S. Rawat, “Firewall: Software and hardware
implementations,” 2013.

[6] Z.  Trabelsi, S.  Zeidan, and  K. Hayawi,  “Denial of  firewalling attacks
(dof): The case study of the emerging blacknurse attack,” IEEE Access, vol. 7,
pp. 61 596–61 609, 2019.

[7]  K. Hayawi,  Z. Trabelsi,  S.  Zeidan, and  M. M.  Masud, “Thwarting  icmp
low-rate attacks against firewalls  while minimizing legitimate traffic loss,”
IEEE Access, vol. 8, pp. 78 029–78 043, 2020.

[8] D. Appelt,  C. D. Nguyen, and L. Briand,  “Behind an application firewall,
are  we safe  from  sql injection  attacks?” in  2015  IEEE 8th  International
Conference on  Software Testing, Verification  and Validation (ICST),  2015, pp.
1–10.

[9] B. I. Mukhtar and M.  A. Azer, “Evaluating the modsecurity web application
firewall against sql injection attacks,” in 2020 15th International Conference
on Computer Engineering and Systems (ICCES), 2020, pp. 1–6.

[10] A. Shamir, “How to share a secret,” Commun. ACM, vol. 22, no. 11,
p. 612–613, nov 1979. [Online]. Available: https://doi.org/10.1145/
359168.359176

[11] B. H. Bloom, “Space/time trade-offs in hash coding with allowable
errors,” Commun. ACM, vol. 13, no. 7, p. 422–426, jul 1970. [Online].
Available: https://doi.org/10.1145/362686.362692

[12] G. Higgins and V. Modi, “Distributed oblivious firewall model,” 4
2022. [Online]. Available: https://github.com/griffinhiggins/DOF
