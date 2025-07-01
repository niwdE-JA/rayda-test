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



# External service mocks
class ExternalUserService:
    @staticmethod
    async def get_user(user_id: str) -> Dict[str, Any]:
        await asyncio.sleep(0.1)  # Simulate API delay
        return {
            "id": user_id,
            "email": f"user{user_id}@example.com",
            "full_name": f"User {user_id}",
            "status": "active"
        }
    
    @staticmethod
    async def create_user(user_data: Dict[str, Any]) -> Dict[str, Any]:
        await asyncio.sleep(0.2)
        return {"id": f"ext_{int(time.time())}", **user_data}

class ExternalPaymentService:
    @staticmethod
    async def get_subscription(org_id: str) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        return {
            "org_id": org_id,
            "plan": "premium",
            "status": "active",
            "next_billing": "2024-02-01"
        }

class ExternalCommunicationService:
    @staticmethod
    async def send_notification(recipient: str, message: str) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        return {
            "recipient": recipient,
            "status": "sent",
            "message_id": f"msg_{int(time.time())}"
        }


# Async webhook processor
class WebhookProcessor:
    @staticmethod
    async def process_webhook(webhook_id: int):
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Get webhook
        cursor.execute('SELECT * FROM webhooks WHERE id = ?', (webhook_id,))
        webhook = cursor.fetchone()
        
        if not webhook:
            conn.close()
            return
        
        # Update status to processing
        cursor.execute(
            'UPDATE webhooks SET status = ?, processed_at = CURRENT_TIMESTAMP WHERE id = ?',
            (WebhookStatus.PROCESSING, webhook_id)
        )
        conn.commit()
        
        try:
            # Process based on event type
            payload = json.loads(webhook[3])  # payload column
            event_type = webhook[2]  # event_type column
            org_id = webhook[1]  # organization_id column
            
            if event_type == "user.created":
                await WebhookProcessor._handle_user_created(org_id, payload)
            elif event_type == "payment.subscription_updated":
                await WebhookProcessor._handle_subscription_updated(org_id, payload)
            elif event_type == "communication.email_status":
                await WebhookProcessor._handle_email_status(org_id, payload)
            
            # Mark as successful
            cursor.execute(
                'UPDATE webhooks SET status = ? WHERE id = ?',
                (WebhookStatus.SUCCESS, webhook_id)
            )
            conn.commit()
            
        except Exception as e:
            # Handle failure with retry logic
            retry_count = webhook[5] + 1  # retry_count column
            max_retries = webhook[6]  # max_retries column
            
            if retry_count < max_retries:
                next_retry = datetime.now() + timedelta(minutes=2 ** retry_count)
                cursor.execute('''
                    UPDATE webhooks 
                    SET status = ?, retry_count = ?, next_retry = ?, error_message = ?
                    WHERE id = ?
                ''', (WebhookStatus.RETRY, retry_count, next_retry, str(e), webhook_id))
            else:
                cursor.execute('''
                    UPDATE webhooks 
                    SET status = ?, error_message = ?
                    WHERE id = ?
                ''', (WebhookStatus.FAILED, str(e), webhook_id))
            
            conn.commit()
            print(f"Webhook {webhook_id} failed: {e}")
        
        finally:
            conn.close()
    
    @staticmethod
    async def _handle_user_created(org_id: int, payload: Dict[str, Any]):
        # Sync external user data
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO external_users 
            (organization_id, external_id, email, full_name, status, last_sync)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            org_id, payload.get("user_id"), payload.get("email"),
            payload.get("full_name"), payload.get("status", "active")
        ))
        conn.commit()
        conn.close()
    
    @staticmethod
    async def _handle_subscription_updated(org_id: int, payload: Dict[str, Any]):
        # Log subscription change
        print(
            org_id, None, "subscription_updated", "subscription",
            str(org_id), payload
        )
    
    @staticmethod
    async def _handle_email_status(org_id: int, payload: Dict[str, Any]):
        # Log email delivery status
        print(
            org_id, None, "email_status_updated", "communication",
            payload.get("message_id"), payload
        )

# Background task for processing webhooks
async def process_pending_webhooks():
    while True:
        try:
            conn = db.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id FROM webhooks 
                WHERE status = 'pending' OR (status = 'retry' AND next_retry <= CURRENT_TIMESTAMP)
                ORDER BY created_at ASC
                LIMIT 10
            ''')
            webhooks = cursor.fetchall()
            conn.close()
            
            tasks = [WebhookProcessor.process_webhook(webhook[0]) for webhook in webhooks]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            await asyncio.sleep(5)  # Check every 5 seconds
        except Exception as e:
            print(f"Error in webhook processor: {e}")
            await asyncio.sleep(10)

# Health monitoring
async def monitor_integrations():
    services = [
        ("user_service", "https://api.userservice.com/health"),
        ("payment_service", "https://api.paymentservice.com/health"),
        ("communication_service", "https://api.commservice.com/health")
    ]
    
    while True:
        try:
            async with httpx.AsyncClient() as client:
                for service_name, health_url in services:
                    try:
                        start_time = time.time()
                        response = await client.get(health_url, timeout=5.0)
                        response_time = int((time.time() - start_time) * 1000)
                        
                        status = IntegrationStatus.HEALTHY if response.status_code == 200 else IntegrationStatus.DEGRADED
                        error_msg = None if response.status_code == 200 else f"HTTP {response.status_code}"
                        
                    except Exception as e:
                        status = IntegrationStatus.DOWN
                        response_time = None
                        error_msg = str(e)
                    
                    # Update health status
                    conn = db.get_connection()
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO integration_health 
                        (service_name, status, last_check, response_time_ms, error_message)
                        VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?)
                    ''', (service_name, status, response_time, error_msg))
                    conn.commit()
                    conn.close()
            
            await asyncio.sleep(30)  # Check every 30 seconds
        except Exception as e:
            print(f"Error in health monitor: {e}")
            await asyncio.sleep(60)


# FastAPI app setup
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start background tasks
    webhook_task = asyncio.create_task(process_pending_webhooks())
    health_task = asyncio.create_task(monitor_integrations())
    
    try:
        yield
    finally:
        webhook_task.cancel()
        health_task.cancel()
        try:
            await webhook_task
            await health_task
        except asyncio.CancelledError:
            pass

app = FastAPI(
    title="Multi-Tenant SaaS Platform",
    description="A comprehensive SaaS platform with external integrations",
    version="1.0.0",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


# Authentication endpoints
@app.post("/auth/register", response_model=UserResponse)
@limiter.limit("5/minute")
async def register(request: Request, user_data: UserCreate, organization_id: int):
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Check if organization exists
    cursor.execute('SELECT id FROM organizations WHERE id = ? AND is_active = TRUE', (organization_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Check if user already exists in this organization
    cursor.execute('SELECT id FROM users WHERE email = ? AND organization_id = ?', (user_data.email, organization_id))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="User already exists in this organization")
    
    # Create user
    password_hash = hash_password(user_data.password)
    cursor.execute('''
        INSERT INTO users (email, password_hash, full_name, role, organization_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_data.email, password_hash, user_data.full_name, user_data.role, organization_id))
    
    user_id = cursor.lastrowid
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.commit()
    conn.close()
    
    return UserResponse(
        id=user[0], email=user[1], full_name=user[3],
        role=user[4], organization_id=user[5],
        created_at=user[6], is_active=user[7]
    )

@app.post("/auth/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(request: Request, email: str, password: str, organization_id: int):
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, password_hash, role FROM users 
        WHERE email = ? AND organization_id = ? AND is_active = TRUE
    ''', (email, organization_id))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not verify_password(password, user[1]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user[0]), "org_id": organization_id, "role": user[2]},
        expires_delta=access_token_expires
    )
    
    
    return TokenResponse(access_token=access_token, token_type="bearer")
# Organization endpoints
@app.post("/organizations", response_model=OrganizationResponse)
@limiter.limit("3/minute")
async def create_organization(request: Request, org_data: OrganizationCreate):
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO organizations (name, domain)
            VALUES (?, ?)
        ''', (org_data.name, org_data.domain))
        
        org_id = cursor.lastrowid
        cursor.execute('SELECT * FROM organizations WHERE id = ?', (org_id,))
        org = cursor.fetchone()
        conn.commit()
        
        return OrganizationResponse(
            id=org[0], name=org[1], domain=org[2],
            created_at=org[3], is_active=org[4]
        )
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Domain already exists")
    finally:
        conn.close()

@app.get("/organizations/me", response_model=OrganizationResponse)
async def get_my_organization(current_user: dict = Depends(get_current_user)):
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM organizations WHERE id = ?', (current_user["organization_id"],))
    org = cursor.fetchone()
    conn.close()
    
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    return OrganizationResponse(
        id=org[0], name=org[1], domain=org[2],
        created_at=org[3], is_active=org[4]
    )


@app.get("/users", response_model=List[UserResponse])
async def get_users(current_user: dict = Depends(require_role(UserRole.ADMIN))):
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, email, full_name, role, organization_id, created_at, is_active
        FROM users WHERE organization_id = ? AND is_active = TRUE
    ''', (current_user["organization_id"],))
    users = cursor.fetchall()
    conn.close()
    
    return [
        UserResponse(
            id=user[0], email=user[1], full_name=user[2],
            role=user[3], organization_id=user[4],
            created_at=user[5], is_active=user[6]
        ) for user in users
    ]

@app.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        full_name=current_user["full_name"],
        role=current_user["role"],
        organization_id=current_user["organization_id"],
        created_at="",  # Would need to fetch from DB
        is_active=current_user["is_active"]
    )

@app.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    request: Request,
    current_user: dict = Depends(require_role(UserRole.ADMIN))
):
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Get current user data
    cursor.execute('''
        SELECT * FROM users 
        WHERE id = ? AND organization_id = ? AND is_active = TRUE
    ''', (user_id, current_user["organization_id"]))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update fields
    update_fields = []
    update_values = []
    old_values = {"full_name": user[3], "role": user[4]}
    new_values = {}
    
    if user_update.full_name is not None:
        update_fields.append("full_name = ?")
        update_values.append(user_update.full_name)
        new_values["full_name"] = user_update.full_name
    
    if user_update.role is not None:
        update_fields.append("role = ?")
        update_values.append(user_update.role)
        new_values["role"] = user_update.role
    
    if update_fields:
        update_values.append(user_id)
        cursor.execute(f'''
            UPDATE users SET {', '.join(update_fields)}
            WHERE id = ?
        ''', update_values)
        conn.commit()
    
    
    # Get updated user
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    updated_user = cursor.fetchone()
    conn.close()
    
    return UserResponse(
        id=updated_user[0], email=updated_user[1], full_name=updated_user[3],
        role=updated_user[4], organization_id=updated_user[5],
        created_at=updated_user[6], is_active=updated_user[7]
    )



# Webhook endpoints
@app.post("/webhooks/{service_name}")
@limiter.limit("100/minute")
async def receive_webhook(
    service_name: str,
    payload: WebhookPayload,
    background_tasks: BackgroundTasks,
    request: Request,
    x_signature: Optional[str] = None
):
    # Verify webhook signature (simplified)
    if x_signature:
        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            json.dumps(payload.dict()).encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(f"sha256={expected_signature}", x_signature):
            raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Store webhook for processing
    # For demo, we'll use organization_id = 1
    organization_id = 1
    
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO webhooks (organization_id, event_type, payload, status)
        VALUES (?, ?, ?, ?)
    ''', (organization_id, payload.event_type, json.dumps(payload.dict()), WebhookStatus.PENDING))
    
    webhook_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {"status": "received", "webhook_id": webhook_id}