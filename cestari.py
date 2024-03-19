# importare i moduli crittografici
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import BLAKE2b
import json
import os.path
import getpass

def process_pwd(password, salt):
    # elabora la password in maniera opportuna
    return scrypt(password, salt, 32, N=2**14, r=8, p=1)

def load_data(path, password):
    credentials = dict()
    try:
        with open(path, 'rb') as data:
            print("Decrypting file...")
            salt = data.read(16)
            nonce = data.read(12)  # Correzione: leggiamo un nonce di 12 byte
            tag = data.read(16)
            ciphertext = data.read()
            # key generator
            key = process_pwd(password, salt)
            # Decrypt with ChaCha20
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            credentials = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        print(str(e))
        return None
    return credentials


def save_and_exit(path, password, credentials):
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    print("Encrypting file...")
    # Generate the salt
    salt = get_random_bytes(16)
    # Generate a nonce of correct length
    nonce = get_random_bytes(12)  # Correzione: generiamo un nonce di 12 byte
    # key generator
    key = process_pwd(password, salt)
    # ChaCha20-Poly1305
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    with open(path, 'wb') as out_file:
        out_file.write(salt)
        out_file.write(nonce)
        out_file.write(tag)
        out_file.write(ciphertext)
        

def search_and_add(query, dic):
    hasher = BLAKE2b.new(digest_bits=256)  # Usiamo BLAKE2b con una lunghezza di digest di 256 bit
    hasher.update(query.encode())  # Aggiorna l'hasher con i byte della query
    query_hash = hasher.digest() 
    query_hash_hex = query_hash.hex()    # Converti il digest hash in una stringa 
    
    if query_hash in dic:
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            username_n = input('Insert username: ')
            # leggi la password in maniera opportuna
            password_n = getpass.getpass('Insert password: ')
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic

def log_in(username, password):
    # deriva il percorso del file associato all'utente
    path_file = username.encode().hex() + '.cred'
    if os.path.exists(path_file):
        try:
            credentials = load_data(path_file, password)
        except ValueError as err:
            print('Authentication failed')
            return
        if credentials is not None:
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
    else:
        prompt = 'User not found. Add as new?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        sign_up = input(prompt)
        if sign_up == 'y':
            credentials = {}
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
        else:
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
        # leggi la password in maniera opportuna
        password = getpass.getpass('Password: ')
        log_in(username, password)
