# Import necessary libraries
from Crypto.Hash import BLAKE2b # SHA (hashing) BLAKE2b version that's optimized for 64-bit CPUs (BLAKE2 is a cryptographic hash function faster than MD5, SHA-1, SHA-2, and SHA-3, yet is at least as secure as the latest standard SHA-3)
from Crypto.Cipher import AES # Advanced Encryption Standard (AES) symmetric block cipher to securely store usernames and passwords (AES is a symmetric key algorithm that uses the same key to encrypt and decrypt data)
from Crypto.Protocol.KDF import scrypt # Key Derivation Function (KDF) to derive a cryptographic key from a password (scrypt is a password-based key derivation function that is designed to be far more secure against hardware brute-force attacks than alternative functions such as PBKDF2 or bcrypt)
from Crypto.Random import get_random_bytes
from getpass import getpass
import json
import os.path

# Function to process the password using scrypt (KDF)
def process_pwd(password, salt):
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1)
    return key

# Function to load data from a file
def load_data(path, password):
    # Read data from file
    with open(path, 'rb') as in_file:
        salt = in_file.read(16) # Read salt used to derive the key
        nonce = in_file.read(15) # Read nonce used for encryption
        tag = in_file.read(16) # Read tag used for authentication
        ciphertext = in_file.read(-1) # Read encrypted data
    
    # Decrypt data using AES OCB mode
    key = process_pwd(password, salt)
    cipher = AES.new(key, AES.MODE_OCB, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    
    # Decode JSON data
    try: 
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        raise IOError(f'data not valid: {str(err)}')
    return credentials

# Function to save data to a file and exit
def save_and_exit(path, password, credentials):
    # Encode data to JSON format
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    salt = get_random_bytes(16)
    
    # Encrypt data using AES OCB mode
    key = process_pwd(password, salt)
    cipher = AES.new(key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce
    
    # Write encrypted data to file
    with open(path, 'wb') as out_file:
        out_file.write(nonce)
        out_file.write(tag)
        out_file.write(salt)
        out_file.write(ciphertext)

# Function to search for credentials and add new ones if not found
def search_and_add(query, dic):
    if query in dic:
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        # Prompt user to add new entry
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

# Function to log in with username and password
def log_in(username, password):
    # Generate unique file path based on username
    blake2 = BLAKE2b.new(digest_bits=512, data=username.encode())
    path_file = blake2.hexdigest()
    
    # Check if file exists for the user
    if os.path.exists(path_file):
        try:
            # Load credentials from file
            credentials = load_data(path_file, password)
        except ValueError as err:
            print('Authentication failed')
            return
        except IOError as err:
            print('Error loading data:')
            print(err)
            return
    else:
        # Prompt user to add as new user
        prompt = 'User not found. Add as new?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        sign_up = input(prompt)
        if sign_up == 'y':
            credentials = {}
        else:
            return
    
    # Loop to search for credentials and add new ones
    prompt = 'Credentials to search:'
    prompt += '\n(leave blank and press "enter" to save and exit)\n'
    while True:
        query = input(prompt)
        if query != '':
            credentials = search_and_add(query, credentials)
        else:
            try:
                # Save data to file and exit
                print('Saving data...')
                save_and_exit(path_file, password, credentials)
                print('Data saved!')
            except IOError:
                print('Error while saving, new data has not been updated!')
            return

# MAIN
while True:
    print('Insert username and password to load data,')
    print('leave blank and press "enter" to exit.')
    username = input('Username: ')
    if username == '':
        print('Goodbye!')
        exit()
    else:
        password = getpass("Password: ")
        log_in(username, password)
