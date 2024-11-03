import socket
import threading
import argparse
import logging
import json
from utilities.RSA_funcs import *
from utilities.DH_funcs import * 
from utilities.AES_funcs import *
from utilities.utility import *

def handler(sock):
    sock.close()

def general_protocol(conn, msg):
    logging.info("[*] Bob General protocol starts")

    a_msg = recv_packet(conn)
    logging.debug("a_msg: {}".format(a_msg))

    logging.info("[*] Received: {}".format(a_msg))

    if a_msg["type"] == "RSAKey":
        RSAKey_protocol(conn)
    elif a_msg["type"] == "RSA":
        RSA_protocol(conn, msg)
    elif a_msg["type"] == "DH":
        DH_protocol(conn, msg)
    else:
        logging.error(" - Unknown protocol")
        return

def RSAKey_protocol(conn):
    logging.info("[*] Bob RSAKey protocol starts")

    _, p, q, e, d = rsa_keygen()

    b_msg = {}
    b_msg["opcode"] = 0
    b_msg["type"] = "RSAKey"
    b_msg["private"] = d
    b_msg["public"] = e
    b_msg["parameter"] = {}
    b_msg["parameter"]["p"] = p
    b_msg["parameter"]["q"] = q

    send_packet(conn, b_msg)
    logging.info("[*] Sent: {}".format(b_msg))

    logging.info("[*] Bob RSAKey protocol ends")

    conn.close()

def RSA_protocol(conn, msg):
    logging.info("[*] Bob RSA protocol starts")

    n, _, _, e, d = rsa_keygen()

    b_msg1 = {}
    b_msg1["opcode"] = 1
    b_msg1["type"] = "RSA"
    b_msg1["public"] = e
    b_msg1["parameter"] = {}
    b_msg1["parameter"]["n"] = n

    send_packet(conn, b_msg1)
    logging.info("[*] Sent: {}".format(b_msg1))

    a_msg2 = recv_packet(conn)
    logging.info("[*] Received: {}".format(a_msg2))

    encrypted_key = a_msg2["encrypted_key"]
    logging.debug(" - encrypted key: {}".format(encrypted_key))
    symm_key =rsa_decrypt(n, d, encrypted_key)
    logging.info(" - symmetric key: {}".format(symm_key))

    c_bob = AES_encrypt(symm_key, msg)
    logging.info(" - encrypted Bob's message: {}".format(c_bob))

    b_msg2 = {}
    b_msg2["opcode"] = 2
    b_msg2["type"] = "AES"
    b_msg2["encryption"] = bytes_to_base64(c_bob)

    send_packet(conn, b_msg2)
    logging.info("[*] Sent: {}".format(b_msg2))

    a_msg3 = recv_packet(conn)
    logging.info("[*] Received: {}".format(a_msg3))

    c_alice = base64_to_bytes(a_msg3["encryption"])
    msg_alice = AES_decrypt(symm_key, c_alice)
    logging.info(" - decrypted Alice's message: {}".format(msg_alice))

    logging.info("[*] Bob RSA protocol ends")

    conn.close()

def DH_protocol(conn, msg):
    logging.info("[*] Bob DH protocol starts")

    p, g, a, bob_public = dh_keygen()

    b_msg = {}
    b_msg["opcode"] = 1
    b_msg["type"] = "DH"
    b_msg["public"] = int_to_base64(bob_public)
    b_msg["parameter"] = {}
    b_msg["parameter"]["p"] = p
    b_msg["parameter"]["g"] = g
    logging.debug("b_msg: {}".format(b_msg))

    send_packet(conn, b_msg)
    logging.info("[*] Sent: {}".format(b_msg))

    a_msg = recv_packet(conn)
    logging.debug("a_msg: {}".format(a_msg))

    alice_public = base64_to_int(a_msg["public"])
    shared_key = dh_shared_key(p, g, alice_public, a)
    logging.info(" - shared key: {}".format(shared_key))

def run(addr, port, msg):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()

        logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))

        conn_handle = threading.Thread(target=general_protocol, args=(conn,msg,))
        conn_handle.start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    msg = input("Enter message to send: ")

    run(args.addr, args.port, msg)

if __name__ == "__main__":
    main()
