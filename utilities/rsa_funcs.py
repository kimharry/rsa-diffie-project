import random
from utility import *

def rsa_keygen():
    p = 0
    q = 0
    while not is_prime(p):
        p = random.randint(100, 1000)
    while not is_prime(q):
        q = random.randint(100, 1000)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 0
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = 0
    while (d * e) % phi != 1:
        d += 1
    return (n, e, d)

def rsa_encrypt(n, e, m):
    c = []
    for i in m:
        c.append((ord(i) ** e) % n)
    return c

def rsa_decrypt(n, d, c):
    m = ""
    for i in c:
        m += chr((i ** d) % n)
    return m

def verify_rsa_keypair(p, q, e, d):
    n = p * q
    phi = (p - 1) * (q - 1)
    if (p * q) % n == 0 and (p - 1) * (q - 1) % phi == 0:
        if (e * d) % phi == 1:
            return True
    return False

if __name__ == '__main__':
    n, e, d = rsa_keygen()
    print(n, e, d)
    m = "Hello world!"
    c = rsa_encrypt(n, e, m)
    print(c)
    m = rsa_decrypt(n, d, c)
    print(m)