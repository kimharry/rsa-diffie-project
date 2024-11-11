import random
from sympy import factorint
from utilities.utility import *

def dh_keygen(p=0, g=0):
    if p == 0:
        p = gen_prime(400, 500)
    if g == 0:
        phi = p - 1
        factors = []
        
        for i in range(2, phi + 1):
            if phi % i == 0:
                factors.append(i)
                while phi % i == 0:
                    phi //= i

        while True:
            g = random.randint(2, p - 1)
            if all(pow(g, (p - 1) // factor, p) != 1 for factor in factors):
                break
            
    a = random.randint(2, p - 1)
    return (p, g, a, (g ** a) % p)

def dh_shared_key(p, public, private):
    return (public ** private) % p

def is_correct_generator(p, g):
    if g <= 1 or g >= p:
        return False

    prime_factors = factorint(p-1)

    for q in prime_factors.keys():
        if pow(g, (p-1) // q, p) == 1:
            return False

    return True


if __name__ == '__main__':
    p, g, y, x = dh_keygen()
    print(p, g, y, x)

    print(is_correct_generator(p, g))
    
