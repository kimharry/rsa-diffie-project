import random
from utilities.utility import *

def rsa_keygen():
    p = gen_prime(400, 500)
    q = gen_prime(400, 500)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 0
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = 0
    while (d * e) % phi != 1:
        d += 1
    return (n, p, q, e, d)

def rsa_encrypt(n, e, m):
    c = []
    for i in m:
        c.append((i ** e) % n)
    return c

def rsa_decrypt(n, d, c):
    m = []
    for i in c:
        m.append((i ** d) % n)
    return bytes(m)

def verify_rsa_keypair(p, q, e, d):
    n = p * q
    phi = (p - 1) * (q - 1)
    if (p * q) % n == 0 and (p - 1) * (q - 1) % phi == 0:
        if (e * d) % phi == 1:
            return True
    return False

if __name__ == '__main__':
    _, p, q, e, d = rsa_keygen()
    print(p, q, e, d)
    m = "Hello world!"
    c = rsa_encrypt(p*q, e, m)
    print(c)
    m = rsa_decrypt(p*q, d, c)
    print(m)