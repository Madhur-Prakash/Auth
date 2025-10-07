import bcrypt

class Hash():
    def bcrypt(password: str):
        try:
            if not password or len(password.strip()) == 0:
                raise ValueError("Password cannot be empty")
            pwd_bytes = password.encode('utf-8')
            salt = bcrypt.gensalt(rounds=12)  # Increased rounds for better security
            hashed_password = bcrypt.hashpw(password=pwd_bytes, salt=salt)
            hashed_password_str = hashed_password.decode('utf-8')
            return hashed_password_str
        except Exception as e:
            raise ValueError("Password hashing failed")
 
    async def verify(hashed_password, plain_password):
        try:
            if not hashed_password or not plain_password:
                return False
            
            # Ensure plain_password is encoded
            if isinstance(plain_password, str):
                plain_password = plain_password.encode('utf-8')
            
            # Ensure hashed_password is encoded
            if isinstance(hashed_password, str):
                hashed_password = hashed_password.encode('utf-8')
            
            # Use positional arguments instead of keyword arguments
            return bcrypt.checkpw(plain_password, hashed_password)
        except Exception:
            return False  # Don't expose error details