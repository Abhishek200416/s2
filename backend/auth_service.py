"""Enhanced Authentication Service with Refresh Tokens"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import jwt
from jwt import PyJWTError
import secrets
import os
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "alert-whisperer-secret-key-change-in-production")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", "alert-whisperer-refresh-key-change-in-production")
ALGORITHM = "HS256"

# OWASP-compliant token lifetimes
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Short-lived: 30 minutes
REFRESH_TOKEN_EXPIRE_DAYS = 7  # Long-lived: 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    """Production-grade authentication service with refresh tokens"""
    
    def __init__(self, db):
        self.db = db
        self.refresh_tokens = db["refresh_tokens"]
    
    async def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create a short-lived access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access"
        })
        
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    async def create_refresh_token(self, user_id: str, user_email: str) -> str:
        """Create a long-lived refresh token and store it in DB"""
        token_id = secrets.token_urlsafe(32)
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        # Store refresh token in database with TTL
        refresh_doc = {
            "token_id": token_id,
            "user_id": user_id,
            "user_email": user_email,
            "created_at": datetime.now(timezone.utc),
            "expires_at": expire,
            "revoked": False
        }
        
        await self.refresh_tokens.insert_one(refresh_doc)
        
        # Create JWT with token_id
        to_encode = {
            "sub": user_email,
            "id": user_id,
            "token_id": token_id,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "refresh"
        }
        
        encoded_jwt = jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    async def verify_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode access token"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            if payload.get("type") != "access":
                return None
            
            return payload
        except PyJWTError:
            return None
    
    async def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify refresh token and check if not revoked"""
        try:
            payload = jwt.decode(token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
            
            if payload.get("type") != "refresh":
                return None
            
            # Check if token is revoked in database
            token_id = payload.get("token_id")
            token_doc = await self.refresh_tokens.find_one({"token_id": token_id})
            
            if not token_doc or token_doc.get("revoked", False):
                return None
            
            return payload
        except PyJWTError:
            return None
    
    async def revoke_refresh_token(self, token_id: str) -> bool:
        """Revoke a refresh token"""
        result = await self.refresh_tokens.update_one(
            {"token_id": token_id},
            {"$set": {"revoked": True, "revoked_at": datetime.now(timezone.utc)}}
        )
        return result.modified_count > 0
    
    async def revoke_all_user_tokens(self, user_id: str) -> int:
        """Revoke all refresh tokens for a user (logout all devices)"""
        result = await self.refresh_tokens.update_many(
            {"user_id": user_id, "revoked": False},
            {"$set": {"revoked": True, "revoked_at": datetime.now(timezone.utc)}}
        )
        return result.modified_count
    
    async def rotate_refresh_token(self, old_token: str) -> Optional[tuple[str, str]]:
        """Rotate refresh token (return new access + refresh tokens)"""
        payload = await self.verify_refresh_token(old_token)
        
        if not payload:
            return None
        
        user_id = payload.get("id")
        user_email = payload.get("sub")
        token_id = payload.get("token_id")
        
        # Revoke old token
        await self.revoke_refresh_token(token_id)
        
        # Create new tokens
        access_token = await self.create_access_token({"sub": user_email, "id": user_id})
        refresh_token = await self.create_refresh_token(user_id, user_email)
        
        return (access_token, refresh_token)
    
    def hash_password(self, password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    async def cleanup_expired_tokens(self):
        """Clean up expired refresh tokens (called periodically)"""
        result = await self.refresh_tokens.delete_many({
            "expires_at": {"$lt": datetime.now(timezone.utc)}
        })
        return result.deleted_count
