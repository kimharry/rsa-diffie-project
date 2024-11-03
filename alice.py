import socket
import argparse
import logging
import json
from utilities.rsa_funcs import *
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

    a_msg1 = {}
    a_msg1["opcode"] = 0
    a_msg1["type"] = "DH"

    send_packet(conn, a_msg1)
    logging.info("[*] Sent: {}".format(a_msg1))

    b_msg1 = recv_packet(conn)
    logging.info("[*] Received: {}".format(b_msg1))

    p = b_msg1["parameter"]["p"]
    g = b_msg1["parameter"]["g"]
    public_bob = b_msg1["public"]

    if not is_prime(p):
        logging.error("incorrect prime number")

        a_err = {}
        a_err["opcode"] = 3
        a_err["error"] = "incorrect prime number"
        send_packet(conn, a_err)
        logging.info("[*] Sent: {}".format(a_err))

        logging.info("[*] Alice DH protocol ends")
        conn.close()
        return
    
    if not is_correct_generator(p, g):
        logging.error("incorrect generator")

        a_err = {}
        a_err["opcode"] = 3
        a_err["error"] = "incorrect generator"
        send_packet(conn, a_err)
        logging.info("[*] Sent: {}".format(a_err))

        logging.info("[*] Alice DH protocol ends")
        conn.close()
        return

    _, _, private_alice, public_alice = dh_keygen(p, g)

    shared_key = dh_shared_key(p, public_bob, private_alice)
    symm_key = shared_key.to_bytes(2, byteorder="big") * 16
    logging.info(" - shared symmetric key: {}".format(symm_key))

    a_msg2 = {}
    a_msg2["opcode"] = 1
    a_msg2["type"] = "DH"
    a_msg2["public"] = public_alice

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

    logging.info("[*] Alice DH protocol ends")

    conn.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-o", "--option", metavar="<option (1/2/3/4)>", help="Which protocol to run (1/2/3/4)", type=int, required=True)
    parser.add_argument("-m", "--msg", metavar="<message>", help="Message to send", type=str, default="world")
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((args.addr, args.port))
    logging.info("Alice is connected to {}:{}".format(args.addr, args.port))

    if args.option == 1:
        RSAKey_protocol(conn)
    elif args.option == 2:
        RSA_protocol(conn, args.msg)
    elif args.option == 3 or args.option == 4:
        DH_protocol(conn, args.msg)
    else:
        logging.error("Invalid option")

    conn.close()
    
if __name__ == "__main__":
    main()
