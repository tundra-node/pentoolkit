#!/usr/bin/env python3
from imports import *


def main_menu():
    options = {
        '1': None,
        '2': None,
        '3': None,
        '4': None,
        '5': None
    }

    while True:
        clear()
        print("Settings")
        print("1. Auto Update")
        print("2.")
        print("3.")
        print("4.")
        print("5.")
        print("6. Exit")
        choice = input("Enter your choice: ")

        if choice in options:
            clear()
            print("Not implemented yet.")
            time.sleep(1)
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
            time.sleep(1)


if __name__ == "__main__":
    clear()
    main_menu()
