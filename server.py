import sqlite3,cryptography.exceptions, urllib.parse, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from urllib.parse import urlencode



class Server:

    def __init__(self):
        self.backend = default_backend()
        self.dbName = 'MetaDB.db'
        self.connex = sqlite3.connect(self.dbName)
        self.cur = self.connex.cursor()
        self.initMetaDB()

    def initMetaDB(self):
        query = 'CREATE TABLE IF NOT EXISTS MetaDB' \
                '(username_hash BLOB PRIMARY KEY NOT NULL,' \
                'pubkey BLOB NOT NULL,' \
                'enc_priv_key BLOB NOT NULL,' \
                'salt BLOB NOT NULL,' \
                'pw_db BLOB NOT NULL)'
        self.cur.execute(query)
        self.connex.commit()

    def login(self, uname_pass):
        print("in login")
        try:
            print(uname_pass)
            self.cur.execute('SELECT * FROM MetaDB WHERE username_hash = ?', [uname_pass[0]])
            isIn = self.cur.fetchall()
            if not isIn:
                raise sqlite3.OperationalError
            print("found username hash in db")
            to_dict = {'username_hash' : isIn[0][0],
                       'public_key' : isIn[0][1],
                       'enc_private_key' : isIn[0][2],
                       'salt' : isIn[0][3],
                       'enc_db' : isIn[0][4]}
            print(urlencode(to_dict))
            return "200", urlencode(to_dict)
        except sqlite3.OperationalError as SQE:
            print("could not find username hash")
            return "404", None


    def parse_http_request(self, environ):
        print("in parse_http_response")
        req_meth = environ['REQUEST_METHOD']
        req_qs = environ['QUERY_STRING']
        if req_meth == "GET" and len(req_qs) > 0:
            if "checkUsernameHash" in req_qs:
                print("in login parse in server side")
                usr_dict = urllib.parse.parse_qs(req_qs)
                status, resp_dict =self.login(usr_dict['checkUsernameHash']) #returns params for client's meta_dict
                if status == "200" and resp_dict is not None:
                    print("in 200")
                    response = (status, resp_dict)
                    return response
                elif status == "404":
                    response = (status, "LookupError: Username not found")
                    return response
            else:
                response = ("400", "malformed request")
        elif req_meth == "POST" and len(req_qs) > 0:
            usr_dict = urllib.parse.parse_qs(req_qs)
            if "updatePasswordRequest" in usr_dict.keys():
                user_db = usr_dict['replacement_enc_db'][0]
                user_signature = usr_dict['sig'][0]
                status = self.update_user_db(usr_dict['updatePasswordRequest'][0],user_db, user_signature)
                if status == "200":
                    print("Successful password addition")
                    response = (status, "Successful password addition")
                    return  response
                elif status == "400":
                    print("Unsuccessful password addition attempt")
                    response = (status, "AssignmentError: could not add password")
                    return response
            elif "newUsernameRequest" in usr_dict.keys():
                print("in parse_http_request, register")
                status = self.register_new_user(usr_dict['newUsernameRequest'][0],
                                                usr_dict['public_key'][0],
                                                usr_dict['enc_private_key'][0],
                                                usr_dict['salt'][0],
                                                usr_dict['enc_db'][0])
                if status == "200":
                    print("Successfully registered new user")
                    response = (status, "successfully registered new user")
                    return response
                elif status == "400":
                    print("Unsuccessful registration attempt")
                    response = (status, "unsuccessful registration attempt")
                    return response
            else:
                response = ("400", "malformed request")
                return response
        else:
            print("in final else")
            response = ("500", "not implemented")
            return response


    def update_user_db(self, username_hash, user_db, signature):
        print("in update_user_db")
        verf = self.verify_signature(username_hash, signature, user_db)
        if verf == 1:
            print("successfully verified signature")
        elif verf == -1:
            print("invalid signature detected")
            return "400"
        try:
            self.cur.execute("UPDATE MetaDB SET  pw_db = ? WHERE username_hash = ?", [user_db, username_hash])
            self.connex.commit()
            status = "200"
        except sqlite3.Error as SQE:
            print("error updating record:", SQE)
            status = "400"
            pass
        return status

    def get_user_db(self, username_hash):
        try:
            self.cur.execute("SELECT pw_db FROM MetaDB WHERE username_hash = ?", [username_hash])
            pw_db = self.cur.fetchone()
            if not pw_db:
                raise sqlite3.Error
            print("got enc'd user db")
            return pw_db
        except sqlite3.Error as SQE:
            print("error updating record:", SQE)
            return None

    def get_public_key(self, username_hash):
        print("in get_public_key")
        try:
            self.cur.execute("SELECT pubkey FROM MetaDB WHERE username_hash = ?", [username_hash])
            pubkey = self.cur.fetchone()[0]
            if not pubkey:
                raise sqlite3.Error
            pubkey = base64.b64decode(pubkey) #decode from base64 into PEM
            pubkey = load_pem_public_key(pubkey, backend=self.backend)   #unserialize pubkey
            return pubkey
        except sqlite3.Error as SQE:
            print("error getting pubkey:", SQE)
            return None



    def verify_signature(self, user_hash, signature, user_db):
        print("in verify_signature")
        signature = base64.b64decode(signature)
        verf = self.get_public_key(user_hash).verifier(
            signature,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verf.update(base64.b64decode(user_db))
        try:
            verf.verify()
            return 1
        except cryptography.exceptions.InvalidSignature as IFS:
            return -1



    def register_new_user(self, uname_hash, pubkey, enc_privkey, salt, pw_db):
        print("in register_new_user")
        try:
            self.cur.execute("INSERT INTO MetaDB VALUES (?,?,?,?,?)", [uname_hash, pubkey, enc_privkey, salt, pw_db])
            self.connex.commit()
            status = "200"
        except sqlite3.Error as SQE:
            print("error inserting record:", SQE)
            status = "400"
            pass
        return status



sv = Server()

def serve_PWMServer(environ, start_response):
    resp = sv.parse_http_request(environ)
    status = resp[0]
    headers = [('Content-type', 'text/plain; charset=utf-8')]
    start_response(status, headers)
    print(resp)
    return [resp[1].encode('utf-8')]


if __name__ == "__main__":
    sv.initMetaDB()

