import time
from hashlib import md5, sha1, sha256, sha224, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512
import string
import platform
import os
from tqdm import tqdm

# initialize tqdm
pbar = tqdm()

# initialize global parameters
global_hashes = []
words_for_rt = []

# help global parameter to check <1.> stage
buttons = {'0', '1', '2', 'e', "exit"}

# help global parameter to check hashes
check_spec_symbols = '~!@#$%^&*()_+-={}[];:\'/\\|.,\"`'


## FUNCTIONS TO HELP //START

# function to check output direction
def check_output_dir():
    try:
        os.chdir(os.getcwd() + '/output_files')
    except FileNotFoundError:
        os.mkdir(os.getcwd() + '/output_files')

    os.chdir('..')


# function to clear console
def clear_console():
    if platform.system() == 'Linux':
        os.system('clear')
    elif platform.system() == 'Windows':
        os.system('cls')


# function to output to file
def write_in_file(hash, type_hash, word, salt):
    exit_file = open("output_files/output_cracked_hashes.txt", "a+")

    if type_hash == 'unknown' or word == '':
        exit_hash = "HASH: {0}, have TYPE: {1}, and original PASSWORD: can't found\n".format(hash, type_hash)

        exit_file.write(exit_hash)
        exit_file.close()
        return

    if salt == '':
        exit_hash = "HASH: {0}, have TYPE: {1}, and original PASSWORD: <{2}>\n".format(hash, type_hash, word)

    else:
        exit_hash = "HASH: {0}, have TYPE: {1}, and original PASSWORD: <{2}>, SALT: <{3}>\n".format(hash, type_hash,
                                                                                                    word, salt)

    exit_file.write(exit_hash)

    exit_file.close()


# print function & output hash
def print_final_error(hash, type_hash):
    if hash not in global_hashes:
        global_hashes.append(hash)
        write_in_file(hash, type_hash, '', '')


# print function & output hash
def print_final(hash, type_hash, word):
    if hash not in global_hashes:
        global_hashes.append(hash)
        write_in_file(hash, type_hash, word, '')


# print function & output hash
def print_final_salt(hash, type_hash, word, salt):
    if hash not in global_hashes:
        global_hashes.append(hash)
        write_in_file(hash, type_hash, word, salt)


# print function
def print_file_hashes():
    print("\n4. Enter file to hashes")


# help function to check hex str
def is_hex(strk):
    for symbol in strk:
        if not symbol in string.hexdigits:
            return 0
    return 1


# function to check exist file
def get_file_way():
    while True:
        try:
            file_way = str(input())
            f = open(file_way, 'r', encoding='latin-1')
            f.close()
            return file_way
        except FileNotFoundError:
            print("\nError file not found...\nEnter another way to file")


# help function to check input from keyboard
def check_input_str():
    input_str = str(input())

    if input_str in buttons:
        return input_str

    else:

        while input_str not in buttons:
            input_str = str(input("\nError...\nEnter <0 / 1 / 2 / e>\n"))
            if input_str in buttons:
                return input_str


# help function to check input from keyboard
def check_input_bool():
    input_bool = str(input())
    while input_bool != ('0' or '1'):
        if input_bool == '1':
            return 1
        elif input_bool == '0':
            return 0
        input_bool = str(input("\nError...\nEnter <0 / 1>\n"))


# help function to close self-made dictionaries
def close_wordlists(way_to_dict):
    way_to_dict.close()


## FUNCTIONS TO HELP //END


## FUNCTIONS TO DEFINE //START


# function to brute hash with salt
def define_hash_word_with_salt(hash, type_hash, word, salt):
    if type_hash == 'md5':
        hash_word = word + salt
        hash_word = md5(hash_word.encode()).hexdigest()  # md5($pass.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'md5($pass.$salt)', word, salt)
            return 1

        hash_word = salt + word
        hash_word = md5(hash_word.encode()).hexdigest()  # md5($salt.$pass)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'md5($salt.$pass)', word, salt)
            return 1

        hash_word = salt + word + salt
        hash_word = md5(hash_word.encode()).hexdigest()  # md5($salt.$pass.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'md5($salt.$pass.$salt)', word, salt)
            return 1

        hash_word = salt + md5(word.encode()).hexdigest()
        hash_word = md5(hash_word.encode()).hexdigest()  # md5($salt.md5($pass))

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'md5($salt.md5($pass))', word, salt)
            return 1

        hash_word = word + salt
        hash_word = md5(hash_word.encode()).hexdigest()  # md5($salt.md5($pass.$salt))
        hash_word = salt + hash_word
        hash_word = md5(hash_word.encode()).hexdigest()

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'md5($salt.md5($pass.$salt))', word, salt)
            return 1

        hash_word = salt + word
        hash_word = md5(hash_word.encode()).hexdigest()  # md5($salt.md5($salt.$pass))
        hash_word = salt + hash_word
        hash_word = md5(hash_word.encode()).hexdigest()

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'md5($salt.md5($salt.$pass))', word, salt)
            return 1

        hash_word = salt + word
        hash_word = sha1(hash_word.encode()).hexdigest()  # md5($salt.sha1($salt.$pass))
        hash_word = salt + hash_word
        hash_word = md5(hash_word.encode()).hexdigest()

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'md5($salt.sha1($salt.$pass))', word, salt)
            return 1

        hash_word = sha1(salt.encode()).hexdigest() + md5(word.encode()).hexdigest()
        hash_word = md5(hash_word.encode()).hexdigest()  # md5(sha1($salt).md5($pass))

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'md5(sha1($salt).md5($pass))', word, salt)
            return 1

    elif type_hash == 'sha1':

        hash_word = word + salt
        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1($pass.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha1($pass.$salt)', word, salt)
            return 1

        hash_word = salt + word
        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1($salt.$word)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha1($salt.$word)', word, salt)
            return 1

        hash_word = salt + word + salt
        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1($salt.$word.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha1($salt.$word.$salt)', word, salt)
            return 1

        hash_word = salt + sha1(word.encode()).hexdigest()
        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1($salt.sha1($word))

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha1($salt.sha1($word))', word, salt)
            return 1

        hash_word = word + salt
        hash_word = salt + sha1(hash_word.encode()).hexdigest()
        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1($salt.sha1($word.$salt))

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha1($salt.sha1($word.$salt))', word, salt)
            return 1

        hash_word = sha1(word.encode()).hexdigest() + salt
        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1(sha1($word).$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha1(sha1($word).$salt)', word, salt)
            return 1

        hash_word = salt + word + salt
        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1(sha1($salt.$word.$salt))
        hash_word = sha1(hash_word.encode()).hexdigest()

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha1(sha1($salt.$word.$salt))', word, salt)
            return 1

        hash_word = md5(word.encode()).hexdigest() + salt
        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1(md5($pass).$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha1(md5($pass).$salt)', word, salt)
            return 1

        hash_word = word + salt
        hash_word = md5(hash_word.encode()).hexdigest()
        hash_word = sha1(hash_word.encode()).hexdigest()  # sha1(md5($pass.$salt))

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha1(md5($pass.$salt))', word, salt)
            return 1

    elif type_hash == 'sha256':

        hash_word = word + salt
        hash_word = sha256(hash_word.encode()).hexdigest()  # sha256($pass.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha256($pass.$salt)', word, salt)
            return 1

        hash_word = word + salt
        hash_word = sha3_256(hash_word.encode()).hexdigest()  # sha3_256($pass.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha3_256($pass.$salt)', word, salt)
            return 1

        hash_word = salt + word
        hash_word = sha256(hash_word.encode()).hexdigest()  # sha256($salt.$word)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha256($salt.$word)', word, salt)
            return 1

        hash_word = salt + word
        hash_word = sha3_256(hash_word.encode()).hexdigest()  # sha3_256($salt.$word)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha3_256($salt.$word)', word, salt)
            return 1

        hash_word = salt + word + salt
        hash_word = sha256(hash_word.encode()).hexdigest()  # sha256($salt.$word.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha256($salt.$word.$salt)', word, salt)
            return 1

        hash_word = salt + word + salt
        hash_word = sha3_256(hash_word.encode()).hexdigest()  # sha3_256($salt.$word.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha3_256($salt.$word.$salt)', word, salt)
            return 1

        hash_word = salt + sha256(word.encode()).hexdigest()
        hash_word = sha256(hash_word.encode()).hexdigest()  # sha256($salt.sha256($word))

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha256($salt.sha256($word))', word, salt)
            return 1

        hash_word = salt + sha3_256(word.encode()).hexdigest()
        hash_word = sha3_256(hash_word.encode()).hexdigest()  # sha3_256($salt.sha3_256($word))

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha3_256($salt.sha3_256($word))', word, salt)
            return 1

        hash_word = sha256(word.encode()).hexdigest() + salt
        hash_word = sha256(hash_word.encode()).hexdigest()  # sha256(sha256($pass).$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha256(sha256($pass).$salt)', word, salt)
            return 1

        hash_word = sha3_256(word.encode()).hexdigest() + salt
        hash_word = sha3_256(hash_word.encode()).hexdigest()  # sha3_256(sha3_256($pass).$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha3_256($pass.$salt)', word, salt)
            return 1

    elif type_hash == 'sha384':

        hash_word = word + salt
        hash_word = sha384(hash_word.encode()).hexdigest()  # sha384($pass.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha384($pass.$salt)', word, salt)
            return 1

        hash_word = word + salt
        hash_word = sha3_384(hash_word.encode()).hexdigest()  # sha3_384($pass.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha3_384($pass.$salt)', word, salt)
            return 1

        hash_word = salt + word
        hash_word = sha384(hash_word.encode()).hexdigest()  # sha384($salt.$pass)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha384($salt.$pass)', word, salt)
            return 1

        hash_word = salt + word
        hash_word = sha3_384(hash_word.encode()).hexdigest()  # sha3_384($salt.$pass)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha3_384($salt.$pass)', word, salt)
            return 1

    elif type_hash == 'sha512':

        hash_word = word + salt
        hash_word = sha512(hash_word.encode()).hexdigest()  # sha512($pass.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha512($pass.$salt)', word, salt)
            return 1

        hash_word = word + salt
        hash_word = sha3_512(hash_word.encode()).hexdigest()  # sha3_512($pass.$salt)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha3_512($pass.$salt)', word, salt)
            return 1

        hash_word = salt + word
        hash_word = sha512(hash_word.encode()).hexdigest()  # sha512($salt.$pass)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha512($salt.$pass)', word, salt)
            return 1

        hash_word = salt + word
        hash_word = sha3_512(hash_word.encode()).hexdigest()  # sha3_512($salt.$pass)

        if hash.partition(':')[0] == hash_word:
            print_final_salt(hash, 'sha3_512($salt.$pass)', word, salt)
            return 1

    return 0


# function to make hashes to rainbow tables
def generate_rt(word, file):
    hash_word = md5(word.encode()).hexdigest()  # md5

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = md5(hash_word.encode()).hexdigest()  # md5(md5($pass))

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = md5(hash_word.encode()).hexdigest()  # md5(md5(md5($pass)))

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha1(word.encode()).hexdigest()  # md5(sha1($pass))
    hash_word = md5(hash_word.encode()).hexdigest()

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha1(word.encode()).hexdigest() + md5(word.encode()).hexdigest() + sha1(
        word.encode()).hexdigest()  # md5(sha1($pass).md5($pass).sha1($pass))
    hash_word = md5(hash_word.encode()).hexdigest()

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha1(word.encode()).hexdigest()  # sha1($pass)

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = md5(word.encode()).hexdigest()
    hash_word = sha1(hash_word.encode()).hexdigest()  # sha1(md5($pass))

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = md5(word.encode()).hexdigest()
    hash_word = md5(hash_word.encode()).hexdigest()
    hash_word = sha1(hash_word.encode()).hexdigest()  # sha1(md5(md5($pass)))

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha1(word.encode()).hexdigest()
    hash_word = sha1(hash_word.encode()).hexdigest()  # sha1(sha1($pass))

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha224(word.encode()).hexdigest()  # sha224($pass)

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha3_224(word.encode()).hexdigest()  # sha3_224($pass)

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha256(word.encode()).hexdigest()  # sha256($pass)

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha3_256(word.encode()).hexdigest()  # sha3_256($pass)

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = md5(word.encode()).hexdigest()
    hash_word = sha256(hash_word.encode()).hexdigest()

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha384(word.encode()).hexdigest()  # sha384($pass)

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha3_384(word.encode()).hexdigest()  # sha3_384($pass)

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha512(word.encode()).hexdigest()  # sha512($pass)

    file.write("{0}:{1}\n".format(word, hash_word))

    hash_word = sha3_512(word.encode()).hexdigest()  # sha3_512($pass)

    file.write("{0}:{1}\n".format(word, hash_word))


# function to brute hash with no salt
def define_hash_word_no_salt(hash, type_hash, word):
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

        hash_word = sha1(word.encode()).hexdigest() + md5(word.encode()).hexdigest() + sha1(
            word.encode()).hexdigest()  # md5(sha1($pass).md5($pass).sha1($pass))
        hash_word = md5(hash_word.encode()).hexdigest()

        if hash == hash_word:
            print_final(hash, 'md5(sha1($pass).md5($pass).sha1($pass))', word)
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

    return 0


# function to define hash without salt for hashcat
def define_hash_hashcat(hash):
    hash_len = len(hash)
    if hash_len == 32 and is_hex(hash):
        return '0'
    elif hash_len == 40 and is_hex(hash):
        return '100'
    elif hash_len == 56 and is_hex(hash):
        return '1300'
    elif hash_len == 64 and is_hex(hash):
        return '1400'
    elif hash_len == 96 and is_hex(hash):
        return '10800'
    elif hash_len == 128 and is_hex(hash):
        return '1700'
    return None


# function to define hash type
def define_hash_type(hash):
    hash_len = len(hash)
    if hash_len == 32 and is_hex(hash):
        return 'md5'
    elif hash_len == 40 and is_hex(hash):
        return 'sha1'
    elif hash_len == 56 and is_hex(hash):
        return 'sha224'
    elif hash_len == 64 and is_hex(hash):
        return 'sha256'
    elif hash_len == 96 and is_hex(hash):
        return 'sha384'
    elif hash_len == 128 and is_hex(hash):
        return 'sha512'
    return None


# function to define dictionary
def define_dictionary():
    wordlists = ''

    # Define dictionary
    print("\n2. Enter 0 - self-made dictionary, 1 - your dictionary")
    type_dict = bool(check_input_bool())

    if type_dict == 0:
        if platform.system() == 'Linux':
            wordlists = open('wordlists_for_os/wordlists_linux.txt', 'r', encoding='latin-1')
        elif platform.system() == 'Windows':
            wordlists = open('wordlists_for_os/wordlists_win.txt', 'r', encoding='latin-1')
        print("\n3. Self-made dictionary")
        way_to_dict = wordlists
    else:
        print("\n3. Enter way to your dictionary")
        way_to_dict = get_file_way()

    return way_to_dict


## FUNCTIONS TO DEFINE //END

# main function to brute hash/es
def brute(way_to_dict, way_to_hashes, sm_dir):
    hashes = open(way_to_hashes, 'r', encoding='latin-1')

    dictionary_words = open(way_to_dict, 'r', encoding='latin-1')
    dictionary_salts = open(way_to_dict, 'r', encoding='latin-1')

    for hash in hashes:
        pbar.update(1)
        time.sleep(0.05)

        count_for_error = 0

        hash = hash.replace('\n', '')
        bool_word_found = 0

        if hash not in global_hashes and hash not in check_spec_symbols:

            if hash.count(':') == 0:  # WORK WITHOUT <:>

                type_hash = define_hash_type(hash)

                if type_hash is None:
                    print_final_error(hash, 'unknown')
                    continue

                dictionary_words.seek(0, 0)

                for word in dictionary_words:

                    word = word.replace('\n', '')

                    if not define_hash_word_no_salt(hash, type_hash, word):
                        bool_word_found = 0
                        count_for_error += 1
                    else:
                        bool_word_found = 1
                        break

                if bool_word_found == 1:
                    continue

            else:

                dictionary_words.seek(0, 0)  # WORK WITH <:>

                type_hash = define_hash_type(hash.partition(':')[0])

                if type_hash is None:
                    print_final_error(hash, 'unknown')
                    continue

                salt = hash.partition(':')[2]

                for word in dictionary_words:

                    word = word.replace('\n', '')

                    salt = salt.replace('\n', '')

                    if not define_hash_word_with_salt(hash, type_hash, word, salt):
                        bool_word_found = 0
                        count_for_error += 1
                    else:
                        bool_word_found = 1
                        break

            if sm_dir == 1:
                if bool_word_found == 0 and count_for_error != 0 and way_to_dict.count('4') == 1:
                    print_final_error(hash, type_hash)
                    continue
            else:
                if bool_word_found == 0 and count_for_error != 0:
                    print_final_error(hash, type_hash)
                    continue

    dictionary_words.close()
    dictionary_salts.close()


# function makes rainbow table from dicts
def rainbow():
    print("\n2. Enter way to your words to make rainbow-tables")
    way_to_dict = get_file_way()

    dicts = open(way_to_dict, 'r')
    output_rt = open('output_files/output_rainbow_tables.txt', 'a+')

    pbar.refresh()
    pbar.reset(total=2)
    clear_console()

    pbar.update(1)
    time.sleep(0.5)

    for word in dicts:
        word = word.replace('\n', '')

        if word not in words_for_rt:
            generate_rt(word, output_rt)
            words_for_rt.append(word)

    pbar.update(1)
    time.sleep(0.5)
    pbar.close()
    clear_console()

    output_rt.close()
    dicts.close()


# function to integrate with hashcat
def hashcat(way_to_dict, way_to_hashes, len_hash):
    if isinstance(way_to_dict, str):

        pbar.refresh()
        pbar.reset(total=len_hash)
        clear_console()

        hashes = open(way_to_hashes, 'r', encoding='latin-1')

        for hash in hashes:

            pbar.update(1)
            time.sleep(0.05)

            hash = hash.replace('\n', '')

            if hash not in global_hashes and hash not in check_spec_symbols:

                type_hash = define_hash_hashcat(hash)

                output = os.popen(
                    'hashcat ' + hash + ' -m ' + type_hash + ' -a 0 -o "output_files/output_cracked_hashes.txt" "' + way_to_dict + '"').read()

                if output.find('Status...........: Cracked') != -1:
                    global_hashes.append(hash)

        hashes.close()

    else:

        pbar.refresh()
        pbar.reset(total=(len_hash * 10) + 10)
        clear_console()

        for way_to_dict_else in way_to_dict:

            pbar.update(1)
            time.sleep(0.05)

            way_to_dict_else = way_to_dict_else.replace('\n', '')

            hashes = open(way_to_hashes, 'r', encoding='latin-1')

            for hash in hashes:

                pbar.update(1)
                time.sleep(0.05)

                hash = hash.replace('\n', '')

                if hash not in global_hashes and hash not in check_spec_symbols:

                    type_hash = define_hash_hashcat(hash)

                    output = os.popen(
                        'hashcat ' + hash + ' -m ' + type_hash + " -a 0 -o output_files/output_cracked_hashes.txt  \"" + way_to_dict_else + '"').read()

                    if output.find('Status...........: Cracked') != -1:
                        global_hashes.append(hash)

            hashes.close()

        close_wordlists(way_to_dict)

    clear_console()
    os.chdir('..')


# main function to open files to bruteforce
def bruteforce():
    way_to_dict = define_dictionary()

    print_file_hashes()
    way_to_hashes = get_file_way()

    len_hash_file = open(way_to_hashes, 'r', encoding='latin-1')
    len_hash = 0
    for _ in len_hash_file:
        len_hash += 1
    len_hash_file.close()

    if isinstance(way_to_dict, str):
        brute(way_to_dict, way_to_hashes, 0)
        pbar.refresh()
        pbar.reset(total=len_hash)
        clear_console()

    else:
        pbar.refresh()
        pbar.reset(total=(len_hash * 10) + 10)
        clear_console()
        for way_to_dict_else in way_to_dict:
            pbar.update(1)
            time.sleep(0.05)
            way_to_dict_else = way_to_dict_else.replace('\n', '')

            brute(way_to_dict_else, way_to_hashes, 1)

        close_wordlists(way_to_dict)

    pbar.close()
    clear_console()


# Define hashcat or self-made
def main():
    check_output_dir()

    print(
        '=' * 15 + "\n\n1. Enter 0 - self-made bruteforce, 1 - hashcat bruteforce, 2 - generate rainbow-tables, e(xit) - to exit from program")
    type_bf = check_input_str()

    if type_bf == "e" or type_bf == "exit":
        print('\n\nExit from program...')
        time.sleep(0.05)
        pbar.close()
        clear_console()
        exit(101)

    if type_bf == '0':
        bruteforce()
        print('+' * 15 + "\n\nCheck <output_files/output_cracked_hashes.txt>")

    elif type_bf == '1':

        print(
            '\n' + '+' * 15 + "\n\nHashcat works with ONLY <md5, sha1, sha256, sha224, sha384, sha512> NO SALT\n\n" + '+' * 15 + '\n')
        way_to_dict = define_dictionary()

        print_file_hashes()
        way_to_hashes = get_file_way()

        len_hash_file = open(way_to_hashes, 'r', encoding='latin-1')
        len_hash = 0
        for _ in len_hash_file:
            len_hash += 1
        len_hash_file.close()

        hashcat(way_to_dict, way_to_hashes, len_hash)
        print('+' * 15 + "\n\nCheck <output_files/output_cracked_hashes.txt>")

    elif type_bf == '2':
        rainbow()
        print('+' * 15 + "\n\nCheck <output_files/output_rainbow_tables.txt> ")

    print('\n' + '+' * 15 + "\n\nWork finished\n\n" + '+' * 15)

    time.sleep(8)
    clear_console()


if __name__ == '__main__':
    while True:
        pbar = tqdm()
        clear_console()
        main()
        global_hashes = []
