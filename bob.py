import socket
import threading
import argparse
import logging
import json
import base64
from utilities.rsa_funcs import *
from utilities.DH_funcs import * 

def handler(sock):
    sock.close()

def general_protocol(conn):
    logging.info("[*] Bob General protocol starts")

    a_bytes = conn.recv(1024)
    logging.debug("a_bytes: {}".format(a_bytes))

    a_js = a_bytes.decode("ascii")
    logging.debug("a_js: {}".format(a_js))

    a_msg = json.loads(a_js)
    logging.debug("a_msg: {}".format(a_msg))

    logging.info("[*] Received: {}".format(a_js))
    logging.info(" - opcode: {}".format(a_msg["opcode"]))
    logging.info(" - type: {}".format(a_msg["type"]))

    if a_msg["type"] == "RSAKey":
        RSAKey_protocol(conn)
    elif a_msg["type"] == "RSA":
        # RSA_protocol(conn)
        pass
    elif a_msg["type"] == "DH":
        # DH_protocol(conn)
        pass
    else:
        logging.error(" - Unknown protocol type")
        return

def RSAKey_protocol(conn):
    logging.info("[*] Bob RSAKey protocol starts")

    _, p, q, e, d = rsa_keygen()

    b_msg = {}
    b_msg["opcode"] = 0
    b_msg["type"] = "RSAKey"
    b_msg["public"] = base64.b64encode(str(e).encode("ascii")).decode("ascii")
    b_msg["private"] = base64.b64encode(str(d).encode("ascii")).decode("ascii")
    b_msg["parameters"] = {}
    b_msg["parameters"]["p"] = p
    b_msg["parameters"]["q"] = q
    logging.debug("b_msg: {}".format(b_msg))

    b_js = json.dumps(b_msg)
    logging.debug("b_js: {}".format(b_js))

    b_bytes = b_js.encode("ascii")
    logging.debug("b_bytes: {}".format(b_bytes))

    conn.send(b_bytes)
    logging.info("[*] Sent: {}".format(b_js))

    logging.info("[*] Bob RSAKey protocol ends")

    conn.close()

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
