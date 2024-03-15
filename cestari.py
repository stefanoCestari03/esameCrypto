from Crypto.Hash import BLAKE2b
from getpass import getpass
from Crypto.Signature import DSS
from getpass import getpass
from base64 import b64encode, b64decode
import json
import binascii
import os.path
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt

#READ FILE.
#It permit you to read the file you are searching file.
def write(path, mod, data):
    try:
        with open (path, mod) as outfile:
            for content in data:
                outfile.write(content)
    except IOError as e:
        print(str(e))

#WRITE FILE.
#It permit you to write on the file.
#Used when you register a new user or 
#you modified the file and want to save
#the changes.
def read(path, mod):
    try:
        with open (path, mod) as infile:
            return infile.read()
    except IOError as e:
        print(str(e))

#AUTHENTICATION
#This function ask to the user 'username' and 'password'
#It makes the hash of the username and check if in the folder
#there is a file with the same hash as the username.
#If it can find it it try to decrypt with the password insert.
#If the password is correct it load the json file inside it and the
#user can use the option of the menu; else is shown an error message
#and you have to do again the authentication with 'username and password.
#If the read function cannot find a file called with the same hash of the username
#permit the user to register that username and the program create the file in the same 
#folder and send you back to authentication.
def authentication():
    username = input("Insert username: ")
    blake = BLAKE2b.new(digest_bits=512)
    username_digest = blake.update((username).encode()).hexdigest()
    if os.path.isfile(username_digest):
        data = read(username_digest , 'rb')
        password = getpass("Insert password: ")
        print("Reading file...")
        json_data = decrypt(data, password)
        data_decoded = json.loads(json_data.decode())
        while True:
            prompt = '''What do you want to do?
            1 -> show list id
            2 -> search by id
            3 -> add a new id
            4 -> save file
            5 -> return to authentication
            0 -> quit
            -> '''
            choice = input(prompt)
            try:
                if choice == '1':
                    #call of the function show list
                    show_list_id(data_decoded)
                elif choice == '2':
                    #call of the function search by id
                    search_id(data_decoded)
                elif choice == '3':
                    #call of the function to add a new id
                    data_decoded = add_id(data_decoded)
                elif choice == '4':
                    #call of the function to save the file (encrypt and write) after you used it.
                    encrypt(username_digest, password, json.dumps(data_decoded).encode())
                elif choice == '5':
                    #return to authentication
                    authentication()
                elif choice == '0':
                    exit()
                else:
                    #default error message for wrong inputs
                    print('Invalid choice, please try again!')
            except ValueError as e:
                print(str(e))
    else: 
        print("User not found. Please register")
        #insert password to register the user and encrypt the file
        password = getpass("Insert password: ")
        #call the encrypt function
        encrypt(username_digest, password, json.dumps({}).encode())
        main()

#this function is used when you register a new user or when 
#when you save the file after you have added a new id
#or search an id.
#It permit you to encrypt the file associated with the hexdigest
#of the username you have insert. 
#The password passed is the same of the password you used for register.
def encrypt(username_digest, password, data):
    print("Encrypting file...")
    #enter password
    enc_password = password
    # Generate the salt
    salt = get_random_bytes(16)
    # key generator
    key = scrypt(enc_password, salt, 32, N=2**20, r=8, p=1)
    #ChaCha20-poly1305
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    write(username_digest, 'wb', [salt, cipher.nonce, tag, ciphertext])
    print("Writing file...")

#this function permit you to decrypt the file associated with the hexdigest
#of the username you have insert. If the password is not correctly you have to
#enter again your username and password.
#The password passed is the same of the password you used for register.
def decrypt(data, password):
    try:
        print("Decrypting file...")
        salt = data[:16]
        nonce = data[16:28]
        tag = data[28:44]
        ciphertext = data[44:]
        #enter the password you used for encryption
        dec_password = password
        # key generator
        key = scrypt(dec_password, salt, 32, N=2**20, r=8, p=1)
        # Decrypt with ChaCha20
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        decipher = cipher.decrypt_and_verify(ciphertext, tag)
        return decipher
    except ValueError as e:
        print(str(e))

#this function permit you to see all ID you have insert in your json file
def show_list_id(data_decoded):
    if len(data_decoded) == 0:
        print("No entries for this user.")
    else:
        for i in data_decoded:
            print("id:", i)
            #print("username:", data_decoded[i]["username"])
            #print("password:", data_decoded[i]["password"])
    

#this function permit you to do a research filter by ID in your json file sjowing
#you also the username and password saved in that id
def search_id(data_decoded): 
    #input the id you want to search
    id = input("Insert the id you want to search: (ex. inbank):")
    found = False
    for i in data_decoded:
        if i == id:
            print("id:", i)
            print("username:", data_decoded[i]["username"])
            print("password:", data_decoded[i]["password"])
            found = True
    if found == False:
        print("Id not found.")

#this function permit to add a new id with username and password that you 
#can see as soon as you have created it when you do search in the menù before 
#saving the file. 
def add_id(data_decoded):
    id = input("Insert your new id (ex. InBank): ")
    page = dict()
    username_id = input("Insert the username: ")
    password_id = getpass("Insert the password: ")
    page['username']=username_id
    page['password']=password_id
    data_decoded[id] = page
    print("Dictionary upload correctly.")
    return data_decoded

#main
def main():
    while True:
        prompt = '''KEY FILE MANAGER'''
        print(prompt)
        try:
            authentication()
        except ValueError as e:
            print(str(e))

if __name__ == '__main__':
    main()