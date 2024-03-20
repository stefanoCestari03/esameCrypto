from Crypto.Cipher import AES
from Crypto.Hash import BLAKE2b
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from getpass import getpass
import json
import os.path

def process_pwd(password, salt):
    # Use the password and scrypt to generate a key
    key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
    return key

def load_data(path, password):
    with open(path, 'rb') as in_file:
        salt = in_file.read(16)
        nonce = in_file.read(15)
        tag = in_file.read(16)
        ciphertext = in_file.read(-1)

    key = process_pwd(password, salt)
    cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    try: 
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        raise IOError(f'data not valid: {str(err)}')
    return credentials

def save_and_exit(path, password, credentials):
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    salt = get_random_bytes(16)
    key = process_pwd(password, salt)
    cipher = AES.new(key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(path, 'wb') as out_file:
        out_file.write(salt)
        out_file.write(cipher.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)

def search_and_add(query, dic):
    if query in dic:
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            username_n = input('Insert username: ')
            password_n = getpass('Insert password: ')
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic

def log_in(username, password):
    path_file = BLAKE2b.new(digest_bits=512, data=username.encode()).hexdigest()
    if os.path.exists(path_file):
        try:
            credentials = load_data(path_file, password)
        except ValueError as err:
            print('Authentication failed')
            return
        except IOError as err:
            print('Error loading data:')
            print(err)
            return
    else:
        prompt = 'User not found. Add as new?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        sign_up = input(prompt)
        if sign_up == 'y':
            credentials = {}
        else:
            return
    prompt = 'Credentials to search:'
    prompt += '\n(leave blank and press "enter" to save and exit)\n'
    while True:
        query = input(prompt)
        if query != '':
            credentials = search_and_add(query, credentials)
        else:
            try:
                print('Saving data...')
                save_and_exit(path_file, password, credentials)
                print('Data saved!')
            except IOError:
                print('Error while saving, new data has not been updated!')
            return

#MAIN
while True:
    print('Insert username and password to load data,')
    print('leave blank and press "enter" to exit.')
    username = input('Username: ')
    if username == '':
        print('Goodbye!')
        exit()
    else:
        password = getpass('Password: ')
        log_in(username, password)