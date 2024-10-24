import math
import base64
import json
import random

def modular(base, exponent, mod):
    result = 1
    base = base % mod 
    
    while exponent > 0:
        if (exponent % 2) == 1:
            result = (result * base) % mod
        
        exponent = exponent // 2
        base = (base * base) % mod
    
    return result

#fermat
def is_prime(n, k=5):
    if n == 1:
        return False
    
    if n == 2 or n == 3:
        return True
    
    if n % 2 == 0:
        return False
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        if modular(a, n - 1, n) != 1:
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

def recv_packet(conn) -> dict:
    b_bytes = conn.recv(1024)
    return json.loads(b_bytes.decode("ascii"))

def send_packet(conn, packet: dict):
    b_bytes = json.dumps(packet).encode("ascii")
    conn.send(b_bytes)
