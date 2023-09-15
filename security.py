#!/usr/bin/python3
import docker
import requests
import os
import subprocess
import sys
import pyfiglet
import socket
from queue import Queue
import threading
from datetime import datetime

class Bcolors:
    Black = '\033[30m'
    Red = '\033[31m'
    Green = '\033[32m'
    Yellow = '\033[33m'
    Blue = '\033[34m'
    Magenta = '\033[35m'
    Cyan = '\033[36m'
    White = '\033[37m'
    Endc = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
 
def linux():

    path_name=input("ENTER THE MALWARE FILE PATH LOCATION:")
    print(path_name)
    try:
        if not os.path.isdir(path_name):
            raise FileNotFoundError(f"The directory '{path_name}' does not exist.")
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)
    print("Linux Docker is going to executed")
    coname="ubuntu-sandbox"
    linuxscript="linux-script.sh"
    client=docker.from_env()
    container=client.containers.run("ubuntu",
                                    name=coname,detach=True,
                                    stdin_open=True,
                                    command=['/bin/bash'],
                                    restart_policy={"Name": "always"},
                                    volumes={path_name: {'bind': '/Malware-Folder', 'mode': 'ro'}}
                                    )

    cpcommand= ["docker","cp","linux-script.sh",coname+":/script.sh"]
    print(" *************Running Initial script and downloading the tools ***************")
    execommand=["docker","exec",coname,"bash","/script.sh"]
    command=["docker","exec","-it",coname,"/bin/bash"]
    subprocess.run(cpcommand)
    subprocess.run(execommand)
    subprocess.run(command)
    
def PortScanner():
    def clear():
        os.system('clear')
    clear()
    print('''
      
$$$$$$$\                       $$\                                                                      
$$  __$$\                      $$ |                                                                     
$$ |  $$ | $$$$$$\   $$$$$$\ $$$$$$\          $$$$$$$\  $$$$$$$\ $$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\ 
$$$$$$$  |$$  __$$\ $$  __$$\\_$$  _|        $$  _____|$$  _____|\____$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
$$  ____/ $$ /  $$ |$$ |  \__| $$ |          \$$$$$$\  $$ /      $$$$$$$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
$$ |      $$ |  $$ |$$ |       $$ |$$\        \____$$\ $$ |     $$  __$$ |$$ |  $$ |$$   ____|$$ |       
$$ |      \$$$$$$  |$$ |       \$$$$  |      $$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |\$$$$$$$\ $$ |      
\__|       \______/ \__|        \____/       \_______/  \_______|\_______|\__|  \__| \_______|\__|
|                                                                                                |
|--------------------------------------------Coded by Mohit--------------------------------------|''')

    print("\nGithub: https://github.com/0xMrR0b0t/TPScanner\n")


    host = socket.gethostbyname(input("Enter Your ip/domain: "))

    normalPortStart = 1
    normalPortEnd = 1024
    allPort = 1
    allPortEnd = 65535
    customPortStart = 0
    customPortEnd = 0

    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print("Select your scan type: ")
    print("[+] Select 1 for 1 to 1024 port scaning")
    print("[+] Select 2 for 1 to 65535 port scaning")
    print("[+] Select 3 for custom port scaning")
    print("[+] Select 4 for exit \n")

    mode = int(input("[+] Select any option: "))
    print()

    if mode == 3:
        customPortStart = int(input("[+] Enter starting port number: "))
        customPortEnd = int(input("[+] Enter ending port number: "))

    print("-"*50)
    print(f"Target IP: {host}")
    print("Scanning started at:" + str(datetime.now()))
    print("-"*50)
    def scan(port):
        s = socket.socket()
        s.settimeout(5)
        result = s.connect_ex((host, port))
        if result == 0:
            print("port open", port)
        s.close()

    queue = Queue()
    def get_ports(mode):
        if mode == 1:
            print("\n[+] scaning..\n")
            for port in range(normalPortStart, normalPortEnd+1):
                queue.put(port)
        elif mode == 2:
            print("\n[+] scaning..\n")
            for port in range(allPort, allPortEnd+1):
                queue.put(port)
        elif mode == 3:
            print("\n[+] scaning..\n")
            for port in range(customPortStart, customPortEnd+1):
                queue.put(port)
        elif mode == 4:
            print("[-] Exiting...")
            sys.exit()

    open_ports = [] 
    def worker():
        while not queue.empty():
            port = queue.get()
            if scan(port):
                print("Port {} is open!".format(port))
                open_ports.append(port)

    def run_scanner(threads, mode):

        get_ports(mode)

        thread_list = []

        for t in range(threads):
            thread = threading.Thread(target=worker)
            thread_list.append(thread)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

    run_scanner(1021, mode)
    print(f"Scanning compleate in: {current_time}")    
        
opt=int(input("The Available tools are ..... \n1.Malware Sandbox Environment Ubuntu \n2.Port Scanner"))
if opt==1:
     banner=pyfiglet.figlet_format("MAS")
     print(banner)
     linux()
elif opt==2:
     PortScanner()
else:
    print("There are only two Options") 




