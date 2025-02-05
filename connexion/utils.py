# auth/utils.py
import bcrypt

def hash_password(password):
    # Hash un mot de passe
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed_password):
    # Vérifie si un mot de passe correspond au hash
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))