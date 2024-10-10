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
    logging.debug("a_msg: {}".format(a_msg))

    a_js = json.dumps(a_msg)
    logging.debug("a_js: {}".format(a_js))

    a_bytes = a_js.encode("ascii")
    logging.debug("a_bytes: {}".format(a_bytes))

    conn.send(a_bytes)
    logging.info("[*] Sent: {}".format(a_js))

    b_bytes = conn.recv(1024)
    logging.debug("b_bytes: {}".format(b_bytes))

    b_js = b_bytes.decode("ascii")
    logging.debug("b_js: {}".format(b_js))

    b_msg = json.loads(b_js)
    logging.debug("b_msg: {}".format(b_msg))

    public = base64_to_int(b_msg["public"])
    private = base64_to_int(b_msg["private"])

    logging.info("[*] Received: {}".format(b_js))
    logging.info(" - public key: {}".format(public))
    logging.info(" - private key: {}".format(private))
    logging.info(" - p: {}".format(b_msg["parameters"]["p"]))
    logging.info(" - q: {}".format(b_msg["parameters"]["q"]))

    if verify_rsa_keypair(b_msg["parameters"]["p"], b_msg["parameters"]["q"], public, private):
        logging.info(" - RSA key pair is verified")
    else:
        logging.error(" - RSA key pair is not verified")
        return

    logging.info("[*] Alice RSAKey protocol ends")

    conn.close()

def RSA_protocol(conn):
    logging.info("[*] Alice RSA protocol starts")

    a_msg = {}
    a_msg["opcode"] = 0
    a_msg["type"] = "RSA"
    logging.debug("a_msg: {}".format(a_msg))

    a_js = json.dumps(a_msg)
    logging.debug("a_js: {}".format(a_js))

    a_bytes = a_js.encode("ascii")
    logging.debug("a_bytes: {}".format(a_bytes))

    conn.send(a_bytes)
    logging.info("[*] Sent: {}".format(a_js))

    b_bytes = conn.recv(1024)
    logging.debug("b_bytes: {}".format(b_bytes))

    b_js = b_bytes.decode("ascii")
    logging.debug("b_js: {}".format(b_js))

    b_msg = json.loads(b_js)
    logging.debug("b_msg: {}".format(b_msg))

    public = base64_to_int(b_msg["public"])
    n = b_msg["parameters"]["n"]

    logging.info("[*] Received: {}".format(b_js))
    logging.info(" - public key: {}".format(public))
    logging.info(" - n: {}".format(n))

    symm_key = AES_keygen()
    logging.info(" - symmetric key: {}".format(symm_key))

    c = rsa_encrypt(n, public, bytes_to_base64(symm_key))
    logging.info(" - encrypted symmetric key: {}".format(c))

    a_msg = {}
    a_msg["opcode"] = 2
    a_msg["type"] = "RSA"
    a_msg["encryption"] = list_to_base64(c)
    logging.debug("a_msg: {}".format(a_msg))

    a_js = json.dumps(a_msg)
    logging.debug("a_js: {}".format(a_js))

    a_bytes = a_js.encode("ascii")
    logging.debug("a_bytes: {}".format(a_bytes))

    conn.send(a_bytes)
    logging.info("[*] Sent: {}".format(a_js))

    b_bytes = conn.recv(1024)
    logging.debug("b_bytes: {}".format(b_msg))

    b_js = b_bytes.decode("ascii")
    logging.debug("b_js: {}".format(b_js))

    b_msg = json.loads(b_js)
    logging.debug("b_msg: {}".format(b_msg))

    logging.info("[*] Received: {}".format(b_js))
    logging.info(" - opcode: {}".format(b_msg["opcode"]))
    logging.info(" - type: {}".format(b_msg["type"]))
    logging.info(" - encrypted message: {}".format(b_msg["encryption"]))

    decrypted_message = AES_decrypt(symm_key, base64_to_bytes(b_msg["encryption"]))
    logging.info(" - decrypted message: {}".format(decrypted_message))

    new_message = "world!"
    logging.info(" - new message: {}".format(new_message))

    c_msg = AES_encrypt(symm_key, new_message)
    logging.info(" - encrypted message: {}".format(c_msg))

    a_msg = {}
    a_msg["opcode"] = 2
    a_msg["type"] = "AES"
    a_msg["encryption"] = bytes_to_base64(c_msg)
    logging.debug("a_msg: {}".format(a_msg))

    a_js = json.dumps(a_msg)
    logging.debug("a_js: {}".format(a_js))

    a_bytes = a_js.encode("ascii")
    logging.debug("a_bytes: {}".format(a_bytes))

    conn.send(a_bytes)
    logging.info("[*] Sent: {}".format(a_js))

    logging.info("[*] Alice RSA protocol ends")

    conn.close()
    
def DH_protocol(conn):
    pass

def run(addr, port, option):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    if option == 1:
        RSAKey_protocol(conn)
    elif option == 2:
        RSA_protocol(conn)
    elif option == 3:
        DH_protocol(conn)

    conn.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-o", "--option", metavar="<option (1/2/3/4)>", help="Which protocol to run (1/2/3/4)", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<message>", help="Message to be encrypted", type=str, default="Hello, world!")
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
