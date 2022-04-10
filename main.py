import hashlib
import sqlite3


def open_file():
    try:
        dict_way = str(input())
        f = open(dict_way, 'r')
        f.close()
        return dict_way
    except FileNotFoundError:
        print("Error file not found\nEnter full way for dictionary or if you don't wanna choice type <test_dict.txt>\n")
        # TODO: Change name of directory
        open_file()


def check_input_bool():
    input_bool = str(input())
    while input_bool != ('0' or '1'):
        if input_bool == '1':
            return 1
        elif input_bool == '0':
            return 0
        input_bool = str(input("\nError, enter 0 or 1"))


def choice_dictionary():
    # Define dictionary
    print("\n2. Enter 0 - self-made dictionary, 1 - your dictionary")
    type_dict = bool(check_input_bool())

    if type_dict == 0:
        dict = "test_dict.txt"  # TODO: Change name of directory
    else:
        print("\nEnter way for dictionary")
        dict = open_file()

    return dict


def hashcat():
    pass  # TODO: Take hashcat from hashcat.net


def bruteforce():
    pass


def main():
    # Define hashcat or self-made
    print("\n1. Enter 0 - self-made bruteforce, 1 - hashcat bruteforce")
    type_bf = bool(check_input_bool())

    if type_bf == 0:
        bruteforce()
    else:
        hashcat()


if __name__ == '__main__':
    main()
