import sqlite3
import hashlib
import base64
import secrets
from typing import Optional, List, Dict, Any

class UserError(Exception):
    pass

class User:
    def __init__(
        self, 
        firstName: str, 
        lastName: str, 
        username: str, 
        email: str,
        password: str = None,
        admin: bool = False,
        is_active: bool = True,
        salt: bytes = None,
        hashed_password: bytes = None
    ):
        self.firstName = firstName
        self.lastName = lastName
        self.username = username
        self.email = email
        self.admin = admin
        self.is_active = is_active
        
        if password:
            self.salt = self._generate_salt() if salt is None else salt
            self.password = self._hash_password(password, self.salt)[0] if hashed_password is None else hashed_password
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            'firstName': self.firstName,
            'lastName': self.lastName,
            'username': self.username,
            'email': self.email,
            'admin': self.admin,
            'is_active': self.is_active
        }

    @staticmethod
    def _generate_salt(length: int = 16) -> bytes:
        return secrets.token_bytes(length)
    
    @staticmethod
    def _hash_password(password: str, salt: bytes) -> tuple[bytes, bytes]:
        if not isinstance(password, str):
            raise UserError("Password must be a string")
        
        password_bytes = password.encode('utf-8')
        salted_password = password_bytes + salt
        hashed_password = hashlib.sha256(salted_password).digest()
        return base64.b64encode(hashed_password), salt

class UserDB:
    def __init__(self, db_name: str = 'users.db'):
        self.db_name = db_name
        self._create_table()
    
    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_name)
    
    def _create_table(self) -> None:
        with self._get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    password BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    admin BOOLEAN DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
    
    def create_user(self, user: User) -> User:
        with self._get_connection() as conn:
            try:
                conn.execute('''
                    INSERT INTO users 
                    (username, email, first_name, last_name, password, salt, admin, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user.username, user.email, user.firstName, user.lastName,
                    user.password, user.salt, user.admin, user.is_active
                ))
                return user
            except sqlite3.IntegrityError:
                raise UserError("Username or email already exists")

    def get_user_by_username(self, username: str) -> Optional[User]:
        with self._get_connection() as conn:
            row = conn.execute('''
                SELECT first_name, last_name, username, email, password, 
                       salt, admin, is_active 
                FROM users WHERE username = ?
            ''', (username,)).fetchone()
            
            if row:
                return User(
                    firstName=row[0], lastName=row[1],
                    username=row[2], email=row[3],
                    hashed_password=row[4], salt=row[5],
                    admin=bool(row[6]), is_active=bool(row[7])
                )
            return None

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        user = self.get_user_by_username(username)
        if not user:
            return None
            
        new_hash, _ = User._hash_password(password, user.salt)
        if secrets.compare_digest(user.password, new_hash):
            return user
        return None

    def get_all_users(self) -> List[User]:
        with self._get_connection() as conn:
            rows = conn.execute('''
                SELECT first_name, last_name, username, email, admin, is_active
                FROM users
            ''').fetchall()
            return [
                User(
                    firstName=row[0], lastName=row[1],
                    username=row[2], email=row[3],
                    admin=bool(row[4]), is_active=bool(row[5])
                ) for row in rows
            ]

    def get_filtered_users(self, admin: Optional[bool] = None, active: Optional[bool] = None) -> List[User]:
        query = "SELECT first_name, last_name, username, email, admin, is_active FROM users WHERE 1=1"
        params = []
        
        if admin is not None:
            query += " AND admin = ?"
            params.append(admin)
        
        if active is not None:
            query += " AND is_active = ?"
            params.append(active)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [
                User(
                    firstName=row[0], lastName=row[1],
                    username=row[2], email=row[3],
                    admin=bool(row[4]), is_active=bool(row[5])
                ) for row in rows
            ]