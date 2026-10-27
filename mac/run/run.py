#!/usr/bin/env python3
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def clear():
    subprocess.run("clear", shell=True, check=False)

def run_script(script_path, *args):
    path = os.path.join(ROOT, script_path)
    if script_path.endswith(".py"):
        subprocess.run([sys.executable, path], check=False)
    else:
        subprocess.run(["sh", path] + [a for a in args if a], check=False)

def main_menu():
    while True:
        clear()
        print("Run Script")
        print("1. Run Nmap")
        print("2. Run Telnet")
        print("3. Run FTP")
        print("4. Run Rustscan (Faster Nmap)")
        print("5. Back")
        choice = input("Enter your choice: ")

        if choice == '1':
            clear()
            scan_type = input("Enter the scan type (If any): ")
            options = input("Enter options (If any): ")
            target = input("Enter the target: ")
            run_script("mac/run/runlist/nmap.sh", scan_type, options, target)
        elif choice == '2':
            clear()
            target = input("Enter the target: ")
            port = input("Enter the port: ")
            run_script("mac/run/runlist/telnet.sh", target, port)
        elif choice == '3':
            clear()
            options = input("Enter options (If any): ")
            user = input("Enter the user: ")
            host = input("Enter the host: ")
            userhost = f"{user}@{host}"
            run_script("mac/run/runlist/ftp.sh", options, userhost)
        elif choice == '4':
            clear()
            option = input("Enter options (if any): ")
            target = input("Enter the target: ")
            other = input("Enter other (if any): ")
            run_script("mac/run/runlist/rustscan.sh", option, target, other)
        elif choice == '5':
            clear()
            run_script("mac/main.py")
            break
        else:
            print("Invalid choice. Please try again.")
            time.sleep(1)

if __name__ == "__main__":
    clear()
    main_menu()
