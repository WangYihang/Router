# -*- coding: utf-8 -*-

import socket
import threading
import time
import hashlib
import sys

import os

from slave import slaver
from slave import port_data_to_int
from slave import int_to_port_data

slaves = {}

MAX_CONNECTION_NUMBER = 0x10

def md5(data):
    return hashlib.md5(data).hexdigest()

class Slave():
    def __init__(self, socket_fd):
        self.socket_fd = socket_fd
        self.hostname, self.port = socket_fd.getpeername()
        self.node_hash = node_hash(self.hostname, self.port)
        # slave_fd.shutdown(socket.SHUT_RDWR)
        # slave_fd.close()

    def show_info(self):
        print "[+] IP : %s" % (self.hostname)
        print "[+] Port : %s" % (self.port)

    def shell_exec(self, shell_command):
        CMD = "\x00" # Shell Exec CMD
        LENGTH = chr(len(shell_command) % 0x100) # Robust
        data = CMD + LENGTH + shell_command
        # print "[+] Sending data : %s" % (repr(data))
        self.socket_fd.send(data)
        return_code = self.socket_fd.recv(1)
        if return_code == "\x00":
            length_data = self.socket_fd.recv(2)
            length = (ord(length_data[1]) * 0x100) + ord(length_data[0])
            result = self.socket_fd.recv(length)
            return result
        else:
            return None

    def close_connection(self):
        self.socket_fd.shutdown(socket.SHUT_RDWR)
        self.socket_fd.close()

    def port_forwarding(self, listen_host, listen_port, dst_host, dst_port):
        CMD = "\x01" # Post Forwarding CMD
        data = CMD + listen_host + listen_port + dst_host + dst_port
        print "[+] Sending data : %s" % (repr(data))
        self.socket_fd.send(data)

def master(host, port):
    print "[+] Master starting at %s:%d" % (host, port)
    master_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    master_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    master_fd.bind((host, port))
    master_fd.listen(MAX_CONNECTION_NUMBER)
    while(True):
        slave_fd, slave_addr = master_fd.accept()
        print "[+] Slave online : %s:%d" % (slave_addr[0], slave_addr[1])
        slave = Slave(slave_fd)
        slaves[slave.node_hash] = slave

def show_commands():
    print "Commands : "
    print "        0. [h|help|?|\\n] : show this help"
    print "        0. [l] : list all online slaves"
    print "        1. [p] : print position"
    print "        1. [s] : show node info"
    print "        1. [i] : interactive shell"
    print "        2. [g] : goto a slave"
    print "        3. [c] : interact an shell"
    print "        3. [f] : port forwarding"
    print "        3. [q|quit|exit] : interact an shell"

def node_hash(host, port):
    return md5("%s:%d" % (host, port))


def main():
    if len(sys.argv) != 3:
        print "Usage : "
        print "\tpython master.py [HOST] [PORT]"
        exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    print "[+] Initing..."
    master_thread = threading.Thread(target=master, args=(host, port,))
    slaver_thread = threading.Thread(target=slaver, args=(host, port,))
    master_thread.start()
    slaver_thread.start()
    time.sleep(1)
    show_commands()
    position = slaves[slaves.keys()[0]].node_hash # master himself
    while True:
        command = raw_input("=>") or "h"
        if command == "h" or command == "help" or command == "?" or command == "\n":
            show_commands()
        elif command == "l":
            print "[+] Listing online slaves..."
            for key in slaves.keys():
                print "[>>>> %s <<<<]" % (key)
                slaves[key].show_info()
        elif command == "p":
            print "[+] Now position node hash : %s" % (position)
        elif command == "g":
            input_node_hash = raw_input("[+] Please input target node hash : ") or position
            print "[+] Input node hash : %s" % (repr(input_node_hash))
            if input_node_hash == position:
                print "[+] Position will not change!"
                continue
            found = False
            for key in slaves.keys():
                if key.startswith(input_node_hash):
                    old_slave = slaves[position]
                    new_slave = slaves[key]
                    print "[+] Changing position from [%s:%d] to [%s:%d]" % (old_slave.hostname, old_slave.port, new_slave.hostname, new_slave.port)
                    position = key
                    found = True
                    break
            if not found:
                print "[-] Please check your input node hash!"
                print "[-] Position is not changed!"
        elif command == "s":
            slaves[position].show_info()
        elif command == "f":
            listen_host = socket.inet_aton(raw_input("Input listen host (0.0.0.0) : ") or "0.0.0.0")
            listen_port = int_to_port_data(int(raw_input("Input listen port (8080) : ") or "8080"))
            dst_host = socket.inet_aton(raw_input("Input listen host (192.168.1.1) : ") or "192.168.1.1")
            dst_port = int_to_port_data(int(raw_input("Input listen port (22) : ") or "22"))
            slave = slaves[position]
            slave.port_forwarding(listen_host, listen_port, dst_host, dst_port)
        elif command == "i":
            slave = slaves[position]
            while True:
                shell_command = raw_input("$ ") or ""
                if shell_command == "exit":
                    break
                if shell_command == "":
                    continue
                result = slave.shell_exec(shell_command)
                if result:
                    print result
        elif command == "c":
            slave = slaves[position]
            shell_command = raw_input("$ ") or ""
            if shell_command == "":
                print "[-] Please input your command!"
            else:
                print "[+] Executing : %s" % (repr(shell_command))
                result = slave.shell_exec(shell_command)
                if result:
                    print "[+] Executing command success!"
                    print "[%s]" % ("-" * 0x10)
                    print result
                else:
                    print "[-] Executing command failed!"
        elif command == "q" or command == "quit" or command == "exit":
            # TODO : release all resources before closing
            print "[+] Releasing resources..."
            for key in slaves.keys():
                slave = slaves[key]
                print "[+] Closing conntion of %s:%d" % (slave.hostname, slave.port)
                slave.socket_fd.shutdown(socket.SHUT_RDWR)
                slave.socket_fd.close()
            print "[+] Exiting..."
            exit(0)
        else:
            print "[-] Please check your input!"

if __name__ == "__main__":
    main()
