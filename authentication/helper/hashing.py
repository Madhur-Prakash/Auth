import bcrypt



class Hash():
    def bcrypt(password: str):
        pwd_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password=pwd_bytes, salt=salt)
        hashed_password_str = hashed_password.decode('utf-8')
        return hashed_password_str

    async def verify(hashed_password, plain_password):
        # Ensure plain_password is encoded
        if isinstance(plain_password, str):
            plain_password = plain_password.encode('utf-8')
        
        # Ensure hashed_password is encoded
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
        
        # Use positional arguments instead of keyword arguments
        return bcrypt.checkpw(plain_password, hashed_password)