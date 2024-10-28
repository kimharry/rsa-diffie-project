import random
from utilities.utility import *

def dh_keygen(p=0, g=0):
    if p == 0:
        p = gen_prime(0, 65536)
    if g == 0:
        g = gen_prime(2, p - 1)
    a = random.randint(2, p - 1)
    return (p, g, a, (g ** a) % p)

def dh_shared_key(p, g, public, private):
    return (public ** private) % p

def is_correct_generator(p, g):
    if g > 1 and g < p:
        if (g ** (p - 1)) % p == 1:
            return True
    return False

if __name__ == '__main__':
    p, g, y, x = dh_keygen()
    print(p, g, y, x)
    k = dh_shared_key(p, g, y, x)
    print(k)