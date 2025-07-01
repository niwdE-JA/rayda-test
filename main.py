import asyncio
import json
import sqlite3
import hashlib
import hmac
import time
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import StrEnum
import logging

import jwt
from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import httpx
import asyncio
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware


# Configuration
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = "multi_tenant_saas.db"


# Rate limiting
limiter = Limiter(key_func=get_remote_address)


# Enums for roles and other stuff
class UserRole(StrEnum):
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"

class WebhookStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCESS = "success"
    FAILED = "failed"
    RETRY = "retry"

class IntegrationStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"

#  Pydantic Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: UserRole = UserRole.USER

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    organization_id: int
    created_at: str
    is_active: bool

class OrganizationCreate(BaseModel):
    name: str
    domain: str

class OrganizationResponse(BaseModel):
    id: int
    name: str
    domain: str
    created_at: str
    is_active: bool

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class WebhookPayload(BaseModel):
    event_type: str
    data: Dict[str, Any]
    timestamp: Optional[str] = None

class IntegrationHealth(BaseModel):
    service_name: str
    status: IntegrationStatus
    last_check: str
    response_time_ms: Optional[int] = None
    error_message: Optional[str] = None


# Database Setup
class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Organizations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                domain TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Users table with tenant isolation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL,
                organization_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (organization_id) REFERENCES organizations (id),
                UNIQUE(email, organization_id)
            )
        ''')
        
        # Audit logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                user_id INTEGER,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                old_values TEXT,
                new_values TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organization_id) REFERENCES organizations (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Webhooks
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS webhooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                retry_count INTEGER DEFAULT 0,
                max_retries INTEGER DEFAULT 3,
                next_retry TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP,
                error_message TEXT,
                FOREIGN KEY (organization_id) REFERENCES organizations (id)
            )
        ''')
        
        # Integration health
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS integration_health (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                response_time_ms INTEGER,
                error_message TEXT
            )
        ''')
        
        # External service data sync
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS external_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                external_id TEXT NOT NULL,
                email TEXT NOT NULL,
                full_name TEXT,
                status TEXT DEFAULT 'active',
                last_sync TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sync_status TEXT DEFAULT 'synced',
                FOREIGN KEY (organization_id) REFERENCES organizations (id),
                UNIQUE(organization_id, external_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)

# Initialize database
db = Database(DATABASE_URL)


# Security utilities
security = HTTPBearer()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Tenant isolation utilities
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_token(token)
    user_id = payload.get("sub")
    org_id = payload.get("org_id")
    
    if not user_id or not org_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, email, full_name, role, organization_id, is_active 
        FROM users 
        WHERE id = ? AND organization_id = ? AND is_active = TRUE
    ''', (user_id, org_id))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {
        "id": user[0],
        "email": user[1],
        "full_name": user[2],
        "role": user[3],
        "organization_id": user[4],
        "is_active": user[5]
    }

def require_role(required_role: UserRole):
    def role_checker(current_user: dict = Depends(get_current_user)):
        user_role = UserRole(current_user["role"])
        role_hierarchy = {UserRole.VIEWER: 1, UserRole.USER: 2, UserRole.ADMIN: 3}
        
        if role_hierarchy.get(user_role, 0) < role_hierarchy.get(required_role, 0):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_checker


