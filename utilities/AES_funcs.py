from Crypto.Cipher import AES
import random

BLOCK_SIZE = 16

def AES_keygen():
    return random.randbytes(32)

def AES_encrypt(key, msg):
    pad = BLOCK_SIZE - len(msg) % BLOCK_SIZE
    msg = msg + pad * chr(pad)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())

def AES_decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    dec = aes.decrypt(encrypted)
    pad = dec[-1]
    return dec[:-pad].decode("ascii")

if __name__ == '__main__':
    key = AES_keygen()
    print(key)
    msg = "Hello, world!"
    c = AES_encrypt(key, msg)
    print(c)
    m = AES_decrypt(key, c)
    print(m)