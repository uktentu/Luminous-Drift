import sqlite3
import hashlib
import base64
import secrets
from typing import Optional, List, Tuple, Dict, Any

class Users:
    """
    A user class with secure password hashing and database integration.
    """
    
    def __init__(
        self, 
        firstName: str, 
        lastName: str, 
        username: str, 
        email: str, 
        password: str, 
        admin: bool = False, 
        is_active: bool = True
    ):
        """
        Initialize a new user with provided details.
        """
        self.firstName = firstName
        self.lastName = lastName
        self.username = username
        self.email = email
        
        self.salt: bytes = self._generate_salt()
        self.password: bytes = self._hash_password(password, self.salt)[0]
        
        self.admin = admin
        self.is_active = is_active
    
    @staticmethod
    def _generate_salt(length: int = 16) -> bytes:
        """Generate a cryptographically secure random salt."""
        return secrets.token_bytes(length)
    
    @staticmethod
    def _hash_password(
        password: str, 
        salt: Optional[bytes] = None
    ) -> tuple[bytes, bytes]:
        """Hash and salt a password using SHA-256."""
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        
        if salt is None:
            salt = Users._generate_salt()
        
        password_bytes = password.encode('utf-8')
        salted_password = password_bytes + salt
        
        # Hash and encode
        hashed_password = hashlib.sha256(salted_password).digest()
        return base64.b64encode(hashed_password), salt
    
    def verify_password(self, input_password: str) -> bool:
        """Verify if the provided password is correct."""
        # Verify password against stored hash
        new_hash, _ = self._hash_password(input_password, self.salt)
        return secrets.compare_digest(self.password, new_hash)

class UserDatabase:
    """
    Database management class for user operations.
    Handles database connection, user creation, retrieval, and management.
    """
    
    def __init__(self, db_name: str = 'users.db'):
        """
        Initialize database connection and create users table if not exists.
        
        Args:
            db_name (str, optional): Name of the SQLite database file. 
                                     Defaults to 'users.db'.
        """
        self.db_name = db_name
        self._create_table()
    
    def _get_connection(self) -> sqlite3.Connection:
        """
        Create and return a database connection.
        
        Returns:
            sqlite3.Connection: Active database connection
        """
        return sqlite3.connect(self.db_name)
    
    def _create_table(self) -> None:
        """
        Create users table if it doesn't exist.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    password BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    admin BOOLEAN DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
    
    def create_user(self, user: Users) -> int:
        """
        Create a new user in the database.
        
        Args:
            user (Users): User object to be inserted
        
        Returns:
            int: ID of the newly created user
        
        Raises:
            sqlite3.IntegrityError: If username or email already exists
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO users 
                    (username, email, first_name, last_name, password, salt, admin, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user.username, 
                    user.email, 
                    user.firstName, 
                    user.lastName, 
                    user.password, 
                    user.salt, 
                    user.admin, 
                    user.is_active
                ))
                conn.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                raise ValueError("Username or email already exists")
    
    def get_user_by_username(self, username: str) -> Optional[Users]:
        """
        Retrieve a user by username.
        
        Args:
            username (str): Username to search for
        
        Returns:
            Optional[Users]: User object if found, None otherwise
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT username, email, first_name, last_name, password, 
                       salt, admin, is_active 
                FROM users 
                WHERE username = ?
            ''', (username,))
            
            row = cursor.fetchone()
            if row:
                user = Users(
                    firstName=row[2],
                    lastName=row[3],
                    username=row[0],
                    email=row[1],
                    password=base64.b64encode(row[4]).decode('utf-8'),  # Dummy password for initialization
                    admin=bool(row[6]),
                    is_active=bool(row[7])
                )
                # Override password and salt with actual stored values
                user.password = row[4]
                user.salt = row[5]
                return user
            return None
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """
        Authenticate a user by username and password.
        
        Args:
            username (str): Username to authenticate
            password (str): Password to verify
        
        Returns:
            bool: True if authentication is successful, False otherwise
        """
        user = self.get_user_by_username(username)
        if user:
            return user.verify_password(password)
        return False
    
    def update_user(self, username: str, **kwargs) -> bool:
        """
        Update user information.
        
        Args:
            username (str): Username of user to update
            **kwargs: Keyword arguments of fields to update
        
        Returns:
            bool: True if update was successful, False otherwise
        """
        # Allowed fields for update
        allowed_fields = {
            'email', 'first_name', 'last_name', 
            'admin', 'is_active', 'password'
        }
        
        # Validate input fields
        update_fields = {
            k: v for k, v in kwargs.items() if k in allowed_fields
        }
        
        if not update_fields:
            return False
        
        # Special handling for password
        if 'password' in update_fields:
            user = self.get_user_by_username(username)
            if user:
                # Generate new salt and hash for password
                salt = Users._generate_salt()
                password_hash, _ = Users._hash_password(update_fields['password'], salt)
                update_fields['password'] = password_hash
                update_fields['salt'] = salt
        
        # Construct update query
        set_clause = ', '.join(f"{k} = ?" for k in update_fields.keys())
        query = f"UPDATE users SET {set_clause} WHERE username = ?"
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    query, 
                    list(update_fields.values()) + [username]
                )
                conn.commit()
                return cursor.rowcount > 0
            except Exception:
                return False
    
    def delete_user(self, username: str) -> bool:
        """
        Delete a user from the database.
        
        Args:
            username (str): Username of user to delete
        
        Returns:
            bool: True if deletion was successful, False otherwise
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            return cursor.rowcount > 0
    
    def list_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        List users with optional pagination.
        
        Args:
            limit (int, optional): Maximum number of users to return. Defaults to 100.
            offset (int, optional): Number of users to skip. Defaults to 0.
        
        Returns:
            List[Dict[str, Any]]: List of user dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT username, email, first_name, last_name, 
                       admin, is_active, created_at
                FROM users
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            columns = [
                'username', 'email', 'first_name', 
                'last_name', 'admin', 'is_active', 'created_at'
            ]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
