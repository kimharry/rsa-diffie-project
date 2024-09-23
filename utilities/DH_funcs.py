import random
from utility import *

def dh_keygen():
    p = 0
    g = 0
    while not is_prime(p):
        p = random.randint(100, 1000)
    while not is_prime(g):
        g = random.randint(2, p - 1)
    x = random.randint(2, p - 1)
    y = (g ** x) % p
    return (p, g, y, x)

def dh_shared_key(p, g, y, x):
    return (y ** x) % p

def verify_dh_keypair(p, g, y, x):
    if (g ** x) % p == y:
        return True
    return False

if __name__ == '__main__':
    p, g, y, x = dh_keygen()
    print(p, g, y, x)
    k = dh_shared_key(p, g, y, x)
    print(k)
    print(verify_dh_keypair(p, g, y, x))