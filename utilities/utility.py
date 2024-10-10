import math
import base64

def is_prime(n):
    if n == 1:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def bytes_to_base64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def base64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def int_to_base64(i: int) -> str:
    return base64.b64encode(str(i).encode("ascii")).decode("ascii")

def base64_to_int(b: str) -> int:
    return int(base64.b64decode(b.encode("ascii") + b"==").decode("ascii"))

def str_to_base64(s: str) -> str:
    return base64.b64encode(s.encode("ascii")).decode("ascii")

def base64_to_str(b: str) -> str:
    return base64.b64decode(b.encode("ascii") + b"==").decode("ascii")

def list_to_base64(l: list) -> str:
    return base64.b64encode(str(l).encode("ascii")).decode("ascii")

def base64_to_list(b: str) -> list:
    return eval(base64.b64decode(b.encode("ascii") + b"==").decode("ascii"))