import hashlib
from hashlib import md5, sha1, sha256, sha224, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512
import string

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
    print("\n2. Enter file to hashes")


def is_hex(strk):
    for symbol in strk:
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
    hash_len = len(hash)
    if hash_len == 32 and is_hex(hash):
        return 'md5'
    elif hash_len >= 32 and is_hex(hash) and hash.count(':') == 1:
        return 'md5'
    elif hash_len == 40 and is_hex(hash):
        return 'sha1'
    elif hash_len >= 40 and is_hex(hash) and hash.count(':') == 1:
        return 'sha1'
    elif hash_len == 56 and is_hex(hash):
        return 'sha224'
    elif hash_len >= 56 and is_hex(hash) and hash.count(':') == 1:
        return 'sha224'
    elif hash_len == 64 and is_hex(hash):
        return 'sha256'
    elif hash_len >= 64 and is_hex(hash) and hash.count(':') == 1:
        return 'sha256'
    elif hash_len == 96 and is_hex(hash):
        return 'sha384'
    elif hash_len >= 96 and is_hex(hash) and hash.count(':') == 1:
        return 'sha384'
    elif hash_len == 128 and is_hex(hash):
        return 'sha512'
    elif hash_len >= 128 and is_hex(hash) and hash.count(':') == 1:
        return 'sha512'


def define_dictionary():
    # Define dictionary
    print("\n3. Enter 0 - self-made dictionary, 1 - your dictionary")
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


def bruteforce():
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
                word = word.replace('\n', '')

                if hash.count(':') == 0:  # TODO: Make another def to make hashes
                    if type_hash == 'md5':

                        hash_word = md5(word.encode()).hexdigest()  # md5

                        if hash == hash_word:
                            print_final(hash, type_hash, word)
                            return 1

                        hash_word = md5(hash_word.encode()).hexdigest()  # md5(md5($pass))

                        if hash == hash_word:
                            print_final(hash, 'md5(md5($pass))', word)
                            return 1

                        hash_word = md5(hash_word.encode()).hexdigest()  # md5(md5(md5($pass)))

                        if hash == hash_word:
                            print_final(hash, 'md5(md5(md5($pass)))', word)
                            return 1

                        hash_word = sha1(word.encode()).hexdigest()  # md5(sha1($pass))
                        hash_word = md5(hash_word.encode()).hexdigest()

                        if hash == hash_word:
                            print_final(hash, 'md5(sha1($pass))', word)
                            return 1

                    elif type_hash == 'sha1':

                        hash_word = sha1(word.encode()).hexdigest()  # sha1($pass)

                        if hash == hash_word:
                            print_final(hash, 'sha1($pass)', word)
                            return 1

                        hash_word = md5(word.encode()).hexdigest()
                        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1(md5($pass))

                        if hash == hash_word:
                            print_final(hash, 'sha1(md5($pass))', word)
                            return 1

                        hash_word = md5(word.encode()).hexdigest()
                        hash_word = md5(hash_word.encode()).hexdigest()
                        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1(md5(md5($pass)))

                        if hash == hash_word:
                            print_final(hash, 'sha1(md5(md5($pass)))', word)
                            return 1

                        hash_word = sha1(word.encode()).hexdigest()
                        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1(sha1($pass))

                        if hash == hash_word:
                            print_final(hash, 'sha1(sha1($pass))', word)
                            return 1

                    elif type_hash == 'sha224':

                        hash_word = sha224(word.encode()).hexdigest()  # sha224($pass)

                        if hash == hash_word:
                            print_final(hash, 'sha224($pass)', word)
                            return 1

                        hash_word = sha3_224(word.encode()).hexdigest()  # sha3_224($pass)

                        if hash == hash_word:
                            print_final(hash, 'sha3_224($pass)', word)
                            return 1

                    elif type_hash == 'sha256':

                        hash_word = sha256(word.encode()).hexdigest()  # sha256($pass)

                        if hash == hash_word:
                            print_final(hash, 'sha256($pass)', word)
                            return 1

                        hash_word = sha3_256(word.encode()).hexdigest()  # sha3_256($pass)

                        if hash == hash_word:
                            print_final(hash, 'sha3_256($pass)', word)
                            return 1

                        hash_word = md5(word.encode()).hexdigest()
                        hash_word = sha256(hash_word.encode()).hexdigest()

                        if hash == hash_word:
                            print_final(hash, 'sha256(md5($pass))', word)
                            return 1

                    elif type_hash == 'sha384':

                        hash_word = sha384(word.encode()).hexdigest()  # sha384($pass)

                        if hash == hash_word:
                            print_final(hash, 'sha384($pass)', word)
                            return 1

                        hash_word = sha3_384(word.encode()).hexdigest()  # sha3_384($pass)

                        if hash == hash_word:
                            print_final(hash, 'sha3_384($pass)', word)
                            return 1

                    elif type_hash == 'sha512':

                        hash_word = sha512(word.encode()).hexdigest()  # sha512($pass)

                        if hash == hash_word:
                            print_final(hash, 'sha512($pass)', word)
                            return 1

                        hash_word = sha3_512(word.encode()).hexdigest()  # sha3_512($pass)

                        if hash == hash_word:
                            print_final(hash, 'sha3_512($pass)', word)
                            return 1

                else:

                    for salt in dictionary_salts:
                        pass

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
