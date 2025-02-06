import bcrypt

def hash_password(password):
    # Hash un mot de passe avec bcrypt
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed_password):
    # Vérifie si un mot de passe correspond au hash
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')  # Convertit en bytes si nécessaire
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
