import json
import base64
from Crypto.Cipher import AES
import argparse


def dh_shared_key(public, private, p):
    return pow(public, private, p)


def aes_decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted)
    dec = aes.decrypt(encrypted_bytes)
    pad = dec[-1]
    return dec[:-pad].decode("ascii")


def find_private_key(g, public_key, p):
    for private_key in range(1, p):
        if pow(g, private_key, p) == public_key:
            return private_key
    return None


def attack(file_name):
    with open(file_name, "r") as f:
        logs = [json.loads(line.strip()) for line in f]

    p, g = None, None
    public_bob = None
    public_alice = None
    encryption_1 = None
    encryption_2 = None

    for log in logs:
        print(f"Log entry: {log}")

        if log.get("opcode") == 1 and "parameter" in log:
            p = log["parameter"].get("p")
            g = log["parameter"].get("g")
            print(f"Found p: {p}, g: {g}")

        if log.get("opcode") == 1 and "public" in log:
            if public_alice is None:
                public_alice = log["public"]
                print(f"Found Alice's public key: {public_alice}")
            else:
                public_bob = log["public"]
                print(f"Found Bob's public key: {public_bob}")

        if log.get("opcode") == 2 and "encryption" in log:
            if encryption_1 is None:
                encryption_1 = log["encryption"]
                print(f"Found first encrypted message: {encryption_1}")
            else:
                encryption_2 = log["encryption"]
                print(f"Found second encrypted message: {encryption_2}")

    if not p or not g or not public_bob or not public_alice:
        print("The log file lacks a required parameter.")
        return

    private_alice = find_private_key(g, public_alice, p)
    if private_alice is None:
        print("Alice's private key was not found.")
        return

    print(f"Alice's private key: {private_alice}")

    shared_key = dh_shared_key(public_bob, private_alice, p)
    symm_key = shared_key.to_bytes(2, byteorder="big") * 16

    print("Decrypted message 1: ", aes_decrypt(symm_key, encryption_1))
    print("Decrypted message 2: ", aes_decrypt(symm_key, encryption_2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attack on DH protocol messages")
    parser.add_argument("-l", "--log", help="Log file path")
    args = parser.parse_args()

    attack(args.log)
