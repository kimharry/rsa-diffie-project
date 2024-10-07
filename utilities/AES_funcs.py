from Crypto.Cipher import AES
import random

BLOCK_SIZE = 16

def AES_keygen():
    return random.randbytes(32)

def AES_encrypt(key, msg):
    pad = BLOCK_SIZE - len(msg)
    msg = msg + pad * chr(pad)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())

def AES_decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    dec = aes.decrypt(encrypted)
    pad = dec[-1]
    return dec[:-pad]