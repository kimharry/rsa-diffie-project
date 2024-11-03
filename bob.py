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

def general_protocol(conn):
    logging.info("[*] Bob General protocol starts")

    a_msg = recv_packet(conn)
    logging.debug("a_msg: {}".format(a_msg))

    logging.info("[*] Received: {}".format(a_msg))

    if a_msg["type"] == "RSAKey":
        RSAKey_protocol(conn)
    elif a_msg["type"] == "RSA":
        RSA_protocol(conn)
    elif a_msg["type"] == "DH":
        DH_protocol(conn)
    else:
        logging.error(" - Unknown protocol")
        return

def RSAKey_protocol(conn):
    logging.info("[*] Bob RSAKey protocol starts")

    _, p, q, e, d = rsa_keygen(p_range=(400, 500), q_range=(400, 500))

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

def RSA_protocol(conn):
    logging.info("[*] Bob RSA protocol starts")

    n, _, _, e, d = rsa_keygen()

    b_msg = {}
    b_msg["opcode"] = 1
    b_msg["type"] = "RSA"
    b_msg["public"] = int_to_base64(e)
    b_msg["parameters"] = {}
    b_msg["parameters"]["n"] = n
    logging.debug("b_msg: {}".format(b_msg))

    send_packet(conn, b_msg)
    logging.info("[*] Sent: {}".format(b_msg))

    a_msg = recv_packet(conn)
    logging.debug("a_msg: {}".format(a_msg))

    enc_symm_key = base64_to_list(a_msg["encryption"])

    logging.info("[*] Received: {}".format(a_msg))
    logging.info(" - opcode: {}".format(a_msg["opcode"]))
    logging.info(" - type: {}".format(a_msg["type"]))
    logging.info(" - encrypted symmetric key: {}".format(enc_symm_key))

    symm_key = rsa_decrypt(n, d, enc_symm_key)
    symm_key = base64_to_bytes(symm_key)
    logging.info(" - symmetric key: {}".format(symm_key))

    message = "Hello, "
    logging.info(" - message: {}".format(message))

    c_msg = AES_encrypt(symm_key, message)
    logging.info(" - encrypted message: {}".format(c_msg))

    b_msg = {}
    b_msg["opcode"] = 2
    b_msg["type"] = "AES"
    b_msg["encryption"] = bytes_to_base64(c_msg)
    logging.debug("b_msg: {}".format(b_msg))

    send_packet(conn, b_msg)
    logging.info("[*] Sent: {}".format(b_msg))
    
    a_msg = recv_packet(conn)
    logging.debug("a_msg: {}".format(a_msg))

    logging.info("[*] Received: {}".format(a_msg))
    logging.info(" - opcode: {}".format(a_msg["opcode"]))
    logging.info(" - type: {}".format(a_msg["type"]))
    logging.info(" - encrypted message: {}".format(a_msg["encryption"]))

    decrypted_message = AES_decrypt(symm_key, base64_to_bytes(a_msg["encryption"]))
    logging.info(" - decrypted message: {}".format(decrypted_message))

    logging.info("[*] Bob RSA protocol ends")

    conn.close()

def DH_protocol(conn):
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

def run(addr, port):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()

        logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))

        conn_handle = threading.Thread(target=general_protocol, args=(conn,))
        conn_handle.start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<message>", help="Message to be encrypted", type=str, default="Hello, world!")
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port)

if __name__ == "__main__":
    main()
