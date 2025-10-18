"""Encryption service for sensitive data like AWS credentials"""

import os
from cryptography.fernet import Fernet
import base64
import hashlib


class EncryptionService:
    """Service for encrypting and decrypting sensitive data"""
    
    def __init__(self):
        # Get encryption key from environment or generate one
        encryption_key = os.getenv("ENCRYPTION_KEY")
        
        if not encryption_key:
            # Generate a key from SECRET_KEY for backward compatibility
            secret_key = os.getenv("SECRET_KEY", "alert-whisperer-secret-key-change-in-production")
            # Create a Fernet-compatible key from SECRET_KEY
            key_bytes = hashlib.sha256(secret_key.encode()).digest()
            encryption_key = base64.urlsafe_b64encode(key_bytes)
        else:
            encryption_key = encryption_key.encode()
        
        self.cipher = Fernet(encryption_key)
        print("✅ Encryption service initialized")
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext and return base64-encoded ciphertext"""
        if not plaintext:
            return ""
        
        try:
            encrypted_bytes = self.cipher.encrypt(plaintext.encode())
            return encrypted_bytes.decode()
        except Exception as e:
            print(f"❌ Encryption error: {e}")
            raise
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt base64-encoded ciphertext and return plaintext"""
        if not ciphertext:
            return ""
        
        try:
            decrypted_bytes = self.cipher.decrypt(ciphertext.encode())
            return decrypted_bytes.decode()
        except Exception as e:
            print(f"❌ Decryption error: {e}")
            raise
    
    def encrypt_dict(self, data: dict) -> dict:
        """Encrypt all string values in a dictionary"""
        encrypted = {}
        for key, value in data.items():
            if isinstance(value, str) and value:
                encrypted[key] = self.encrypt(value)
            else:
                encrypted[key] = value
        return encrypted
    
    def decrypt_dict(self, data: dict) -> dict:
        """Decrypt all string values in a dictionary"""
        decrypted = {}
        for key, value in data.items():
            if isinstance(value, str) and value:
                try:
                    decrypted[key] = self.decrypt(value)
                except:
                    # If decryption fails, assume it's not encrypted
                    decrypted[key] = value
            else:
                decrypted[key] = value
        return decrypted


# Global encryption service instance
encryption_service = EncryptionService()
