import hashlib

wordlists = {
    1: "/wordlists/cirt-default-passwords.txt",
    2: "/wordlists/darkweb2017-top10000.txt",
    3: "/wordlists/probable-v2-top12000.txt",
    4: "/wordlists/richelieu-french-top20000.txt",
    5: "/wordlists/xato-net-10-million-passwords.txt",
    6: "/wordlists/xato-net-10-million-usernames.txt",
    7: "/wordlists/rockyou1.txt",
    8: "/wordlists/rockyou2.txt",
    9: "/wordlists/rockyou3.txt",
    10: "/wordlists/rockyou4.txt"
}


## FUNCTIONS TO HELP //START
def print_final_error(hash, type_hash):
    print("\n6-7. HASH: {0}, have TYPE: {1}, and original PASSWORD can't found".format(hash, type_hash))


def print_final(hash, type_hash, word):
    print("\n6-7. HASH: {0}, have TYPE: {1}, and original PASSWORD: {2}".format(hash, type_hash, word))


def print_file_hashes():
    print("\n3. Enter file to hashes")


def is_hex(string):
    for symbol in string:
        if not symbol in string.hexdigits:
            return 0
    return 1


def get_file_way():
    try:
        file_way = str(input())
        f = open(file_way, 'r')
        f.close()
        return file_way
    except FileNotFoundError:
        print("\nError file not found...\nEnter another way to file")
        get_file_way()


def check_input_bool():
    input_bool = str(input())
    while input_bool != ('0' or '1'):
        if input_bool == '1':
            return 1
        elif input_bool == '0':
            return 0
        input_bool = str(input("\nError...\nEnter 0 or 1"))


## FUNCTIONS TO HELP //END


## FUNCTIONS TO DEFINE //START


def define_hash_type(hash):
    hash_len = hash.len()
    if hash_len == 32 and is_hex(hash):
        return 'md5'
    elif hash_len == 33 and is_hex(hash) and hash.count(':') == 1:
        return 'md5'
    elif hash_len == 40 and is_hex(hash):
        return 'sha1'
    elif hash_len == 41 and is_hex(hash) and hash.count(':') == 1:
        return 'sha1'
    elif hash_len == 56 and is_hex(hash):
        return 'sha224'
    elif hash_len == 57 and is_hex(hash) and hash.count(':') == 1:
        return 'sha224'
    elif hash_len == 64 and is_hex(hash):
        return 'sha256'
    elif hash_len == 65 and is_hex(hash) and hash.count(':') == 1:
        return 'sha256'
    elif hash_len == 96 and is_hex(hash):
        return 'sha384'
    elif hash_len == 97 and is_hex(hash) and hash.count(':') == 1:
        return 'sha384'
    elif hash_len == 128 and is_hex(hash):
        return 'sha512'
    elif hash_len == 129 and is_hex(hash) and hash.count(':') == 1:
        return 'sha512'


def define_dictionary():
    # Define dictionary
    print("\n2. Enter 0 - self-made dictionary, 1 - your dictionary")
    type_dict = bool(check_input_bool())

    if type_dict == 0:
        way_to_dict = wordlists
    else:
        print("\nEnter way to your dictionary")
        way_to_dict = get_file_way()

    return way_to_dict


## FUNCTIONS TO DEFINE //END


def hashcat():
    pass  # TODO: Take hashcat from hashcat.net


def bruteforce():  # TODO: MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512
    print_file_hashes()

    way_to_hashes = get_file_way()
    hashes = open(way_to_hashes, 'r')

    way_to_dict = define_dictionary()
    if isinstance(way_to_dict, str):
        dictionary_words = open(way_to_dict, 'r')
        dictionary_salts = open(way_to_dict, 'r')

        for hash in hashes:
            type_hash = define_hash_type(hash)
            for word in dictionary_words:
                for salts in dictionary_salts:
                    if type_hash == 'md5':
                        if hash.count(':') == 0:  # WORK WITHOUT SALT
                            hash_word = hashlib.new(type_hash)
                            hash_word.update(word)
                        else:  # TODO: WORK WITH SALT
                            pass
                        if hash == hash_word:
                            print_final(hash, type_hash, word)
                            return 1

            print_final_error(hash, type_hash)
            return 0

    else:
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
