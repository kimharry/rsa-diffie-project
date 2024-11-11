import socket
import argparse
import logging
import random
from utilities.RSA_funcs import *
from utilities.DH_funcs import * 
from utilities.AES_funcs import *
from utilities.utility import *

def RSAKey_protocol(conn):
    logging.info("[*] Bob RSAKey protocol starts")

    a_msg = recv_packet(conn)
    logging.info("[*] Received: {}".format(a_msg))

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

    a_msg1 = recv_packet(conn)
    logging.debug("a_msg1: {}".format(a_msg1))

    logging.info("[*] Received: {}".format(a_msg1))

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

def DH_protocol(conn, msg, is_protocol_4=0):
    logging.info("[*] Bob DH protocol starts")

    a_msg1 = recv_packet(conn)
    logging.debug("a_msg1: {}".format(a_msg1))

    logging.info("[*] Received: {}".format(a_msg1))

    p, g, private_bob, public_bob = dh_keygen()

    b_msg1 = {}
    b_msg1["opcode"] = 1
    b_msg1["type"] = "DH"
    b_msg1["public"] = public_bob
    b_msg1["parameter"] = {}
    if is_protocol_4 == 0:
        b_msg1["parameter"]["p"] = p
        b_msg1["parameter"]["g"] = g
    elif is_protocol_4 == 1:
        b_msg1["parameter"]["p"] = random.randint(1, 100)
        b_msg1["parameter"]["g"] = g
    elif is_protocol_4 == 2:
        b_msg1["parameter"]["p"] = p
        b_msg1["parameter"]["g"] = random.randint(1, 100)

    send_packet(conn, b_msg1)
    logging.info("[*] Sent: {}".format(b_msg1))

    a_msg2 = recv_packet(conn)
    logging.info("[*] Received: {}".format(a_msg2))

    if a_msg2["opcode"] == 3:
        logging.error(a_msg2["error"])
        logging.info("[*] Bob DH protocol ends")
        conn.close()
        return

    public_alice = a_msg2["public"]
    shared_key = dh_shared_key(p, public_alice, private_bob)
    symm_key = shared_key.to_bytes(2, byteorder="big") * 16
    logging.info(" - shared symmetric key: {}".format(symm_key))

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

    logging.info("[*] Bob DH protocol ends")

    conn.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-o", "--option", metavar="<option (1/2/3/4)>", help="Which protocol to run (1/2/3/4)", type=int, required=True)
    parser.add_argument("-m", "--msg", metavar="<message>", help="Message to send", type=str, default="hello")
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((args.addr, args.port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(args.addr, args.port))

    conn, info = bob.accept()
    bob.close()

    logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))

    if args.option == 1:
        RSAKey_protocol(conn)
    elif args.option == 2:
        RSA_protocol(conn, args.msg)
    elif args.option == 3:
        DH_protocol(conn, args.msg)
    elif args.option == 4:
        DH_protocol(conn, args.msg, random.randint(1, 2))
    else:
        logging.error("Invalid option")

    conn.close()

if __name__ == "__main__":
    main()
