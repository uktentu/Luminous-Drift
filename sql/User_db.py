import hashlib
import base64
import secrets

class Users():
    def __init__(self, firstName, lastName, username, email, password, admin, is_active):
        self.firstName = firstName
        self.lastName = lastName
        self.username = username
        self.email = email
        self.password = self.hash_password(password)
        self.admin = admin
        self.is_active = is_active
    
    def getfirstName(self):
        return self.firstName
    
    def getlastName(self):
        return self.lastName
    
    def getemail(self):
        return self.email
    
    def getpassword(self):
        return self.password
    
    def getadmin(self):
        return self.admin
    
    def getis_active(self):
        return self.is_active
    
    def setfirstName(self, firstName):
        self.firstName = firstName

    def setlastName(self, lastName):
        self.lastName = lastName
    
    def setusername(self, username):
        self.username = username
    
    def setemail(self, email):
        self.email = email

    def setpassword(self, password):
        self.password = self.hash_password(password, self.salt)

    def setadmin(self, admin):
        self.admin = admin
    
    def setis_active(self, is_active):
        self.is_active = is_active

    def __str__(self):
        return f"{self.firstName} {self.lastName} {self.username} {self.email} {self.password} {self.admin} {self.is_active}"
    
    def generate_salt(self):
        return secrets.token_bytes(16)
    
    def hash_password(self, password, salt=None):
        if salt is None:
            salt = self.generate_salt()
        
        password = password.encode('utf-8')
        
        salted_password = password + salt

        hashed_password = hashlib.sha256(salted_password).digest()
        
        encoded_hash = base64.b64encode(hashed_password)

        return encoded_hash, salt
    
    def verify_password(self, password, salt, hash):
        new_hash, _ = self.hash_password(password, salt)
        return secrets.compare_digest(hash, new_hash)