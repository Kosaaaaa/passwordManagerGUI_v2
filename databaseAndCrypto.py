import sqlite3
from hashlib import sha256
import sys
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os


class DatabaseAndCrypto():
    def __init__(self):
        self.dataBase = sqlite3.connect('passwords.db')
        self.createTables()

    def createTables(self):
        # ------------------- USERS DATA TABLE-------------------
        self.dataBase.execute('''
            CREATE TABLE IF NOT EXISTS users_data (
        	id_user	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
        	user_name	TEXT NOT NULL UNIQUE,
        	master_password	TEXT NOT NULL,
        	salt TEXT NOT NULL
        );
        ''')
        # dataBase.commit()
        # ------------------- PASSWORDS TABLE-------------------
        self.dataBase.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
        	id_passwords INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
        	service	TEXT NOT NULL,
        	password TEXT NOT NULL,
        	user_name TEXT NOT NULL
        );
        ''')
        self.dataBase.commit()

    @staticmethod
    def get_crypto_key(master_Password_Plain, salt):
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=sha256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        return base64.urlsafe_b64encode(kdf.derive(master_Password_Plain.encode('utf-8')))

    def get_salt_user(self, userName):
        userSalt = self.dataBase.cursor().execute("SELECT salt from users_data WHERE user_name=:currentUser",
                                                  {'currentUser': userName})
        try:
            return userSalt.fetchone()[0]
        except TypeError:
            return False

    def encryptPassword(self, userName, password_service, master_Password_Plain):
        salt = self.get_salt_user(userName)
        crypto_key = self.get_crypto_key(master_Password_Plain, salt)
        f = Fernet(crypto_key)
        encrypted = f.encrypt(password_service.encode('utf-8'))
        return encrypted

    def decryptPassword(self, userName, encrypted, master_Password_Plain, ):
        salt = self.get_salt_user(userName)
        crypto_key = self.get_crypto_key(master_Password_Plain, salt)
        f = Fernet(crypto_key)
        decrypted = f.decrypt(encrypted)
        return decrypted.decode('utf-8')

    @staticmethod
    def get_hex_key(key):
        return sha256(key.encode('utf-8')).hexdigest()

    def add_password(self, service, userName, encrypted_password):
        # print("wlo ",self.get_encrypted_password(service, userName))
        if self.get_encrypted_password(service, userName) is not None:
            #print("juz jest")
            return False

        else:
            self.dataBase.execute('''
                INSERT INTO passwords(service, password, user_name) VALUES (:service,:password,:user_name);
            ''', {'service': service, 'password': encrypted_password, 'user_name': userName})
            self.dataBase.commit()
            print('Hasło zostało dodane pomyślnie.')
            return True

    def get_encrypted_password(self, service, userName):

        encryptedPassword = self.dataBase.execute(
            "SELECT password from passwords WHERE user_name=:currentUser AND service=:service",
            {'currentUser': userName, 'service': service})
        if encryptedPassword.fetchone() is None:
            return False
        return encryptedPassword.fetchone()

    def getUserData(self, currentUserName):
        currentUserData = self.dataBase.cursor().execute("SELECT * from users_data WHERE user_name=:currentUser",
                                                         {'currentUser': currentUserName})
        return currentUserData.fetchone()

    def update_encrypted_password(self, service, userName, newEncryptedPassword):
        serviceData = self.dataBase.execute("SELECT * from passwords WHERE user_name=:currentUser AND service=:service",
                                            {'currentUser': userName, 'service': service}).fetchone()

        if not serviceData:
            # return print('Hasło nie mogło zostać zaktualizowane.')
            return False
        else:
            self.dataBase.execute(
                "UPDATE passwords SET password=:newPassword WHERE user_name=:currentUser AND service=:service",
                {'currentUser': userName, 'service': service, 'newPassword': newEncryptedPassword})
            self.dataBase.commit()
            # return print('Hasło zostało zaktualizowane pomyślnie.')
            return True

    def add_user(self, userName, masterPassword):
        hashedMasterPassword = self.get_hex_key(masterPassword)
        salt = os.urandom(32)
        try:
            self.dataBase.execute('''
                            INSERT INTO users_data(user_name, master_password, salt) VALUES (:user_name,:master_password,:salt);
                        ''', {'user_name': userName, 'master_password': hashedMasterPassword, 'salt': salt})
            self.dataBase.commit()
        except sqlite3.IntegrityError:
            return False

        print('Konto %s zostało utworzone pomyślnie.' % userName)
        return True
        # return [userName, masterPassword]

    def validateLogin(self, userName, masterPassword):
        currentUserData = self.getUserData(userName)
        hashedMasterPassword = self.get_hex_key(masterPassword)
        # print(currentUserData)
        if currentUserData is not None:
            if hashedMasterPassword == currentUserData[2]:
                return True
                #print('Poprawne hasło')
            else:
                #print('Błędne hasło')
                return False
        else:
            #print('Nie ma takiego użytkownika')
            return False
