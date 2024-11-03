import socket
import argparse
import logging
import json
from utilities.RSA_funcs import *
from utilities.DH_funcs import *
from utilities.AES_funcs import *
from utilities.utility import *


def RSAKey_protocol(conn):
    logging.info("[*] Alice RSAKey protocol starts")

    a_msg = {}
    a_msg["opcode"] = 0
    a_msg["type"] = "RSAKey"

    send_packet(conn, a_msg)
    logging.info("[*] Sent: {}".format(a_msg))

    b_msg = recv_packet(conn)
    logging.info("[*] Received: {}".format(b_msg))

    private = b_msg["private"]
    public = b_msg["public"]
    p = b_msg["parameter"]["p"]
    q = b_msg["parameter"]["q"]

    if not is_prime(p):
        logging.error(" - p is not prime")
        return
    if not is_prime(q):
        logging.error(" - q is not prime")
        return
    if not verify_rsa_keypair(p, q, public, private):
        logging.error(" - invalid key pair")
        return
    
    logging.info(" - private key: {}".format(private))
    logging.info(" - public key: {}".format(public))
    logging.info(" - key pair verified")

    logging.info("[*] Alice RSAKey protocol ends")

    conn.close()

def RSA_protocol(conn, msg):
    logging.info("[*] Alice RSA protocol starts")

    a_msg1 = {}
    a_msg1["opcode"] = 0
    a_msg1["type"] = "RSA"

    send_packet(conn, a_msg1)
    logging.info("[*] Sent: {}".format(a_msg1))

    b_msg1 = recv_packet(conn)
    logging.info("[*] Received: {}".format(b_msg1))

    public = b_msg1["public"]
    n = b_msg1["parameter"]["n"]

    symm_key = AES_keygen()
    encrypted_key = rsa_encrypt(n, public, symm_key)

    a_msg2 = {}
    a_msg2["opcode"] = 2
    a_msg2["type"] = "RSA"
    a_msg2["encrypted_key"] = encrypted_key

    send_packet(conn, a_msg2)
    logging.info("[*] Sent: {}".format(a_msg2))

    b_msg2 = recv_packet(conn)
    logging.info("[*] Received: {}".format(b_msg2))

    c_bob = base64_to_bytes(b_msg2["encryption"])
    msg_bob = AES_decrypt(symm_key, c_bob)
    logging.info(" - decrypted Bob's message: {}".format(msg_bob))

    c_alice = AES_encrypt(symm_key, msg)
    logging.info(" - encrypted Alice's message: {}".format(c_alice))

    a_msg3 = {}
    a_msg3["opcode"] = 2
    a_msg3["type"] = "AES"
    a_msg3["encryption"] = bytes_to_base64(c_alice)

    send_packet(conn, a_msg3)
    logging.info("[*] Sent: {}".format(a_msg3))

    logging.info("[*] Alice RSA protocol ends")

    conn.close()
    
def DH_protocol(conn, msg):
    logging.info("[*] Alice DH protocol starts")

    a_msg = {}
    a_msg["opcode"] = 0
    a_msg["type"] = "DH"
    logging.debug("a_msg: {}".format(a_msg))

    send_packet(conn, a_msg)
    logging.info("[*] Sent: {}".format(a_msg))

    b_msg = recv_packet(conn)
    logging.debug("b_msg: {}".format(b_msg))

    bob_public = base64_to_int(b_msg["public"])
    p = b_msg["parameter"]["p"]
    g = b_msg["parameter"]["g"]

    logging.info("[*] Received: {}".format(b_msg))
    logging.info(" - public key: {}".format(bob_public))
    logging.info(" - p: {}".format(p))
    logging.info(" - g: {}".format(g))

    if is_prime(p):
        logging.info(" - prime modulus")
    else:
        logging.error(" - not prime modulus")
        a_msg = {}
        a_msg["opcode"] = 3
        a_msg["error"] = "incorrect prime number"
        return

    if is_correct_generator(p, g):
        logging.info(" - correct generator")
    else:
        logging.error(" - incorrect generator")
        a_msg = {}
        a_msg["opcode"] = 3
        a_msg["error"] = "incorrect generator"
        return

    _, _, b, alice_public = dh_keygen(p, g)

    a_msg = {}
    a_msg["opcode"] = 1
    a_msg["type"] = "DH"
    a_msg["public"] = int_to_base64(alice_public)
    logging.debug("a_msg: {}".format(a_msg))

    send_packet(conn, a_msg)
    logging.info("[*] Sent: {}".format(a_msg))

    shared_key = dh_shared_key(p, bob_public, b)
    logging.info(" - shared key: {}".format(shared_key))

    logging.info("[*] Alice DH protocol ends")

    conn.close()

def run(addr, port, option):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    if option == 1:
        RSAKey_protocol(conn)
    elif option == 2:
        msg = input("Enter message to send: ")
        RSA_protocol(conn, msg)
    elif option == 3:
        msg = input("Enter message to send: ")
        DH_protocol(conn, msg)

    conn.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-o", "--option", metavar="<option (1/2/3)>", help="Which protocol to run (1/2/3)", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if args.option < 1 or args.option > 3:
        logging.error("Invalid option")
        return

    run(args.addr, args.port, args.option)
    
if __name__ == "__main__":
    main()
