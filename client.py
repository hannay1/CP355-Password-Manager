import sqlite3,requests, os, datetime, sys, base64, urllib.parse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend


class Client:

    def __init__(self):
        self.dbName = "LocalDB.db"
        self.connex = sqlite3.connect(self.dbName)
        self.cur = self.connex.cursor()
        self.isLoggedIn = False
        self.backend = default_backend()
        self.welcome()

    def welcome(self):
        print("*****PASSWORD MANAGER*****")
        picd = True
        while picd:
            resp = input("please select an option number:\n" \
                         "1.Login\n" \
                         "2.Register\n" \
                         "3.Exit\n")
            try:
                resp = int(resp)
            except ValueError:
                pass
            if resp not in range(1,4):
                pass
            else:
                picd = False
        if resp == 1:
            self.local_login()
        elif resp == 2:
            self.local_register()
        elif resp == 3:
            sys.exit(0)

    def menu(self, username_hash, cipher,  private_key):
        print("*****PASSWORD MANAGER*****")
        picd = True
        while picd:
            resp = input("please select an option number:\n" \
                         "1.View your passwords\n" \
                         "2.Update a password\n" \
                         "3.Logout\n")
            try:
                resp = int(resp)
            except ValueError:
                pass
            if resp not in range(1,4):
                pass
            else:
                picd = False
        if resp == 1:
            self.view_db()
            self.menu(username_hash, cipher, private_key)
        elif resp == 2:
            self.add_password()
            new_enc_db = self.enc_db(cipher)
            signature = self.sign_enc_db(private_key, new_enc_db)
            self.dec_db(cipher, new_enc_db)
            #sign enc'd dtabase with private key, verify on server wth pubkey
            update_dict = {"updatePasswordRequest" : username_hash,
                           "replacement_enc_db" : base64.b64encode(new_enc_db),
                           "sig" : signature} #server should
            statResp = self.return_post_response(update_dict)
            if statResp[0] == 400:
                print("Could not update remote database, bad request")
                self.menu(username_hash, cipher, private_key)
            elif statResp[0] == 200:
                print("***Successful password addition***")
                self.menu(username_hash, cipher, private_key)
        elif resp == 3:
            print("(logout)")
            self.local_logout(cipher)

    def local_login(self):
        print("*****LOG IN*****")
        if self.isLoggedIn == False:
            self.isLoggedIn = True
            username_plain = input("username:")
            username_hash = self.hash_uname(username_plain) #stores hash of username
            password_plain = input("password:")
            statResp = self.return_get_response(username_hash)
            if statResp[0] == 404:
                self.isLoggedIn = False
                print("username not found, try again")
                self.welcome()
            elif statResp[0] == 200:
                from_server = statResp[1]
                for key in from_server.keys():
                    from_server[key] = from_server[key][0]
                salt = from_server['salt']
                salt = base64.b64decode(salt)
                enc_private_key = from_server['enc_private_key']
                enc_private_key = base64.b64decode(enc_private_key)
                enc_db = from_server['enc_db']
                enc_db = base64.b64decode(enc_db)
                pbkdf_key = self.gen_pbkdf_key(password_plain, salt)
                cipher = Cipher(algorithms.AES(pbkdf_key), modes.CFB(salt), backend=self.backend)
                self.validate_pbkdf_key(cipher, enc_db) #throws error if password not valid
                private_key = self.decrypt_privkey(cipher, enc_private_key)
                self.dec_db(cipher, enc_db)
                print("Welcome, %s" % username_plain)
            elif statResp[0] == 500:
                print("serer error: something went wrong")
                self.isLoggedIn = False
                self.local_login()
        else:
            print("already logged in")
        self.menu(username_hash, cipher, private_key)




    def return_get_response(self, username_hash):
        url = 'https://127.0.0.1:443'
        param_dict = {"checkUsernameHash" : username_hash}
        req = requests.get(url, params=param_dict ,verify=False)
        status = req.status_code
        resp =req.text
        resp = urllib.parse.parse_qs(resp)
        return (status, resp) #return JSON object


    def local_register(self):
        print("*****REGISTER*****")
        print("please enter new credentials:\n")
        username_plain = input("username:")
        username_hash = self.hash_uname(username_plain)
        print("hashed username:", username_hash)
        password_plain = input("password(SAVE THIS!!!):")
        print("creating account...")
        self.init_db()
        salt = self.new_salt()
        pbkdf_key = self.gen_pbkdf_key(password_plain, salt) #make sym key
        cipher = Cipher(algorithms.AES(pbkdf_key), modes.CFB(salt), backend=self.backend)
        pubkey, privkey = self.make_new_keys() #makes rsa keys
        enc_privkey = self.encrypt_privkey(cipher,privkey)
        enc_db = self.enc_db(cipher)
        to_server = self.genToServerDict(username_hash, pubkey,enc_privkey, salt, enc_db)
        statResp = self.return_post_response(to_server)
        if statResp[0] == 400:
            print("Username already taken, try again")
            self.welcome()
        elif statResp[0] == 200:
            print("***Successful registration***")
            self.welcome()

    def genToServerDict(self, username_hash, pubkey, enc_privkey, salt, enc_db):
        to_server = {"newUsernameRequest" : username_hash,
                     "public_key" : pubkey,
                     "enc_private_key" : base64.b64encode(enc_privkey),
                     "salt" : base64.b64encode(salt),
                     "enc_db" : base64.b64encode(enc_db)}
        print(to_server)
        return to_server

    def return_post_response(self, param_dict):
        url = 'https://127.0.0.1:443'
        req = requests.post(url, params=param_dict, verify=False)
        resp = req.text
        statcode = req.status_code
        print("status code form server:", req.status_code)
        return statcode, resp

    def local_logout(self, cipher):
        self.isLoggedIn = False
        self.enc_db(cipher)
        return self.welcome()


    def view_db(self):
        print("Current stored passwords:")
        try:
            self.cur.execute('SELECT * FROM LocalDB')
            table = self.cur.fetchall()
            self.connex.commit()
            i = 1
            for row in table:
                print(str(i), ">", "| ACCOUNT:", row[0], "| USERNAME:", row[1], "| PASSWORD:", row[2], "| DATE ADDED:", row[3], "|")
                i +=1
        except UnicodeEncodeError:
            print("error printing DB")
            pass
        except sqlite3.OperationalError as SQE:
            print("error selecting from local db", SQE)
            pass



    def init_db(self):
        query = 'CREATE TABLE IF NOT EXISTS LocalDB' \
                '(associated_account TEXT NOT NULL,' \
                'account_username TEXT PRIMARY KEY NOT NULL,' \
                'password_plain TEXT NOT NULL,' \
                'added_date DATE NOT NULL)'
        try:
            self.cur.execute(query)
            self.connex.commit()
        except sqlite3.Error as SE:
            print("error creating local db:", SE)
            sys.exit(1)



    def add_password(self):
        print("***ADD PASSWORD***")
        picd = True
        while picd:
            resp = input("please select an option number:\n" \
                         "1.Add a new password\n" \
                         "2.Update a password\n" \
                         "3.Back to menu\n")
            try:
                resp = int(resp)
            except ValueError:
                pass
            if resp not in range(1,4):
                pass
            else:
                picd = False
        if resp == 2:
            #update existing
            account = input("associated account:")
            update_username = input("new username:")
            update_password = input("new password:")
            now = datetime.datetime.now()
            try:
                self.cur.execute('UPDATE LocalDB SET account_username = ?, password_plain = ?, added_date = ? WHERE associated_account = ?', [update_username,update_password, now, account])
                self.connex.commit()
            except sqlite3.OperationalError:
                print("could not update")
                self.add_password()
            except sqlite3.IntegrityError:
                print("account already in database")
                self.add_password()
        elif resp == 1:
            new_account = input("new account:")
            new_username = input("new username:")
            new_password = input("new password:")
            now = datetime.datetime.now()
            try:
                self.cur.execute('INSERT INTO LocalDB  VALUES (?,?,?,?) ', [new_account, new_username, new_password,  now])
                self.connex.commit()
            except sqlite3.OperationalError:
                print("could not update")
                self.add_password()
            except sqlite3.IntegrityError:
                print("account already in database")
                self.add_password()


    def make_new_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=self.backend)
        public_key = private_key.public_key()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key = pem
        pem2 = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key = pem2
        #keys are now strings, so encode in b64
        private_key = base64.b64encode(private_key)
        public_key = base64.b64encode(public_key)
        return public_key, private_key

    def sign_enc_db(self, private_key, enc_db):
        private_key = base64.b64decode(private_key)
        private_key = load_pem_private_key(private_key, backend=self.backend, password=None) #deserialize key
        signer = private_key.signer(
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                        ),hashes.SHA256())
        signer.update(enc_db)
        signature = signer.finalize()
        signature = str(base64.b64encode(signature), encoding='utf-8')
        return signature

    def gen_pbkdf_key(self, password_plain, salt):
        key_func = PBKDF2HMAC(algorithm=hashes.SHA256(),
                              length=32,
                              salt=salt,
                              iterations=10000,
                              backend=self.backend)
        key = key_func.derive(password_plain.encode())
        return key


    def validate_pbkdf_key(self, cipher, enc_db):
        try:
            self.dec_db(cipher, enc_db)
            self.cur.execute("SELECT * FROM LocalDB")
        except sqlite3.DatabaseError:
            print("!!!PASSWORD IS INCORRECT, KEYS DO NOT MATCH!!!")
            self.isLoggedIn = False
            self.welcome()

    def encrypt_privkey(self, cipher, private_key):
        aes_encryptor = cipher.encryptor()
        enc_priv = aes_encryptor.update(private_key) + aes_encryptor.finalize()
        return enc_priv

    def decrypt_privkey(self, cipher, enc_privkey):
        aes_decryptor = cipher.decryptor()
        dec_priv = aes_decryptor.update(enc_privkey) + aes_decryptor.finalize()
        return  dec_priv

    def new_salt(self):
        return os.urandom(16)

    def hash_uname(self, username_plain):
        uname_bytes = username_plain.encode()
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        digest.update(uname_bytes)
        final = digest.finalize()
        return final

    def enc_db(self, cipher):
        with open(self.dbName, "rb") as dbFile:
            f = dbFile.read()
        aes_encryptor = cipher.encryptor()
        enc_db = aes_encryptor.update(f) + aes_encryptor.finalize()
        with open(self.dbName, "wb") as dbFile:
            dbFile.write(enc_db)
        return enc_db

    def dec_db(self,cipher, enc_db):
        aes_decryptor = cipher.decryptor()
        dec_db = aes_decryptor.update(enc_db) + aes_decryptor.finalize()
        with open(self.dbName, "wb") as dbFile:
            dbFile.write(dec_db)
        return dec_db



if __name__ == '__main__':
    c = Client()
