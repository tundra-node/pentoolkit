#!/usr/bin/env python3
from imports import *


def main_menu():
    options = {
        '1': "mac/run/run.py",
        '2': "mac/install/install.py",
        '3': "mac/update.py",
        '4': "mac/help.py",
        '5': "mac/settings.py"
    }

    while True:
        clear()
        print("Main Menu")
        print("1. Run Script")
        print("2. Run Install Script")
        print("3. Run Update Script")
        print("4. Help")
        print("5. Settings")
        print("6. Exit")
        choice = input("Enter your choice: ")

        if choice in options:
            clear()
            run(options[choice])
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
            time.sleep(1)

if __name__ == "__main__":
    clear()
    main_menu()
