import random


def gen_shares(N, m, t, S):
    # Pick t - 1 random coefficients mod N
    C = [random.randrange(0, N) for _ in range(t - 1)]
    # Generate shares for each node at x in the form:
    #   (c_t-1*x^t-1 + ... + c_2*x^2 + c_1*x + s) mod N
    s = []
    for x in range(1, m+1):
        p = 0
        for t, c in enumerate(C):
            p += c * x ** (t+1)
        s.append((x, (p + S) % N))
    return s


def recover_secret(s, N):
    # Lagrange Polynomial Interpolation mod N
    sum = 0
    for j, sj in enumerate(s):
        xj, yj = sj
        for k, sk in enumerate(s):
            xk, _ = sk
            if k != j:
                yj *= -xk * pow(xj-xk, -1, N)
        sum += yj
    return sum % N
