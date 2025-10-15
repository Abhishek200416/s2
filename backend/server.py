from fastapi import FastAPI, APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any, Set
import uuid
from datetime import datetime, timezone, timedelta
import random
import google.generativeai as genai
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
import secrets
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import asyncio
import json


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Gemini AI Setup
genai.configure(api_key=os.environ['GEMINI_API_KEY'])
model = genai.GenerativeModel('gemini-2.5-pro')

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "alert-whisperer-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# Security
security = HTTPBearer()

# WebSocket Connection Manager for Real-Time Updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.add(connection)
        # Clean up disconnected clients
        self.active_connections -= disconnected

manager = ConnectionManager()

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


# ============= Models =============
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str
    role: str  # admin, technician
    company_ids: List[str] = []
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class UserCreate(BaseModel):
    email: str
    password: str
    name: str
    role: str = "technician"
    company_ids: List[str] = []

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: Dict[str, Any]

class Company(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    policy: Dict[str, Any] = {}
    assets: List[Dict[str, Any]] = []
    critical_assets: List[str] = []  # List of asset IDs that are critical
    api_key: Optional[str] = None
    api_key_created_at: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class Alert(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    asset_id: str
    asset_name: str
    signature: str
    severity: str  # low, medium, high, critical
    message: str
    tool_source: str
    status: str = "active"  # active, acknowledged, resolved
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class Incident(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    alert_ids: List[str] = []
    alert_count: int = 0
    priority_score: float = 0.0
    status: str = "new"  # new, in_progress, resolved, escalated
    assigned_to: Optional[str] = None
    signature: str
    asset_id: str
    asset_name: str
    severity: str
    decision: Optional[Dict[str, Any]] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class Runbook(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    risk_level: str  # low, medium, high
    signature: str  # which alert signature this handles
    actions: List[str] = []
    health_checks: Dict[str, Any] = {}
    auto_approve: bool = False
    company_id: str

class PatchPlan(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    patches: List[Dict[str, Any]] = []
    canary_assets: List[str] = []
    status: str = "proposed"  # proposed, canary_in_progress, canary_complete, rolling_out, complete, failed
    window: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AuditLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: Optional[str] = None
    event_type: str
    payload: Dict[str, Any] = {}
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class KPI(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    total_alerts: int = 0
    total_incidents: int = 0
    noise_reduction_pct: float = 0.0
    mttr_minutes: float = 0.0
    self_healed_count: int = 0
    self_healed_pct: float = 0.0
    patch_compliance_pct: float = 0.0
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class DecisionRequest(BaseModel):
    incident_id: str

class ExecuteRunbookRequest(BaseModel):
    incident_id: str
    runbook_id: str
    approval_token: Optional[str] = None

class ApproveIncidentRequest(BaseModel):
    incident_id: str


# ============= Auth Functions =============
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_api_key():
    """Generate a secure API key"""
    return f"aw_{secrets.token_urlsafe(32)}"

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user_doc = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
        if user_doc is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user_doc)
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")


# ============= Decision Engine =============
async def generate_decision(incident: Incident, company: Company, runbook: Optional[Runbook]) -> Dict[str, Any]:
    """Generate AI-powered decision for incident remediation"""
    
    # Calculate priority score
    severity_scores = {"low": 10, "medium": 30, "high": 60, "critical": 90}
    base_score = severity_scores.get(incident.severity, 30)
    
    # Add bonus for multiple alerts (correlation bonus)
    duplicate_bonus = min(incident.alert_count * 2, 20)
    
    priority_score = base_score + duplicate_bonus
    
    # Determine action based on risk and policy
    action = "ESCALATE"
    approval_required = True
    reason = "No runbook available for this incident type"
    
    if runbook:
        if runbook.risk_level == "low" and runbook.auto_approve:
            action = "EXECUTE"
            approval_required = False
            reason = f"Correlated {incident.alert_count} alerts; low-risk runbook auto-approved"
        elif runbook.risk_level == "medium" or not runbook.auto_approve:
            action = "REQUEST_APPROVAL"
            approval_required = True
            reason = f"Medium risk or policy requires approval for {runbook.name}"
        else:
            action = "REQUEST_APPROVAL"
            approval_required = True
            reason = "High risk runbook requires manual approval"
    
    # Build decision JSON
    decision = {
        "action": action,
        "reason": reason,
        "incident_id": incident.id,
        "priority_score": priority_score,
        "runbook_id": runbook.id if runbook else None,
        "params": {},
        "approval_required": approval_required,
        "health_check": runbook.health_checks if runbook else {},
        "escalation": {
            "skill_tag": "linux" if "linux" in incident.signature.lower() else "windows",
            "urgency": incident.severity
        },
        "kpi_update": {
            "alerts_after": 1,
            "mttr_after_min": 8,
            "self_healed_incidents": 1 if action == "EXECUTE" else 0
        },
        "audit": {
            "event": action.lower().replace("_", " "),
            "notes": f"Decision engine processed incident {incident.id}"
        }
    }
    
    # Get AI explanation using Gemini
    try:
        prompt = f"""You are an MSP operations AI agent. Explain the following decision in 2-3 sentences:
        
Incident: {incident.alert_count} alerts for {incident.signature} on {incident.asset_name}
Severity: {incident.severity}
Action: {action}
Reason: {reason}

Provide a brief technical explanation suitable for an operations dashboard."""
        
        response = model.generate_content(prompt)
        decision["ai_explanation"] = response.text
    except Exception as e:
        decision["ai_explanation"] = f"AI explanation unavailable: {str(e)}"
    
    return decision


# ============= Routes =============
@api_router.get("/")
async def root():
    return {"message": "Alert Whisperer API", "version": "1.0"}


# Auth Routes
@api_router.post("/auth/register", response_model=User)
async def register(user_data: UserCreate):
    # Check if user exists
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_dict = user_data.model_dump()
    password = user_dict.pop("password")
    hashed_password = get_password_hash(password)
    
    user = User(**user_dict)
    doc = user.model_dump()
    doc["password_hash"] = hashed_password
    
    await db.users.insert_one(doc)
    return user

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user_doc = await db.users.find_one({"email": credentials.email})
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(credentials.password, user_doc["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Remove sensitive data
    user_doc.pop("password_hash", None)
    user_doc.pop("_id", None)
    
    # Create token
    access_token = create_access_token(data={"sub": user_doc["email"], "id": user_doc["id"]})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_doc
    }


# Profile Routes
@api_router.get("/profile", response_model=User)
async def get_profile(current_user: User = Depends(get_current_user)):
    """Get current user profile"""
    return current_user

class ProfileUpdate(BaseModel):
    name: str
    email: str

@api_router.put("/profile", response_model=User)
async def update_profile(profile_data: ProfileUpdate, current_user: User = Depends(get_current_user)):
    """Update user profile"""
    # Check if email is already taken by another user
    if profile_data.email != current_user.email:
        existing = await db.users.find_one({"email": profile_data.email})
        if existing and existing["id"] != current_user.id:
            raise HTTPException(status_code=400, detail="Email already in use")
    
    # Update user
    await db.users.update_one(
        {"id": current_user.id},
        {"$set": {
            "name": profile_data.name,
            "email": profile_data.email
        }}
    )
    
    # Get updated user
    updated_user = await db.users.find_one({"id": current_user.id}, {"_id": 0, "password_hash": 0})
    return User(**updated_user)

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

@api_router.put("/profile/password")
async def change_password(password_data: PasswordChange, current_user: User = Depends(get_current_user)):
    """Change user password"""
    # Get user with password hash
    user_doc = await db.users.find_one({"id": current_user.id})
    
    # Verify current password
    if not verify_password(password_data.current_password, user_doc["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Update password
    new_hash = get_password_hash(password_data.new_password)
    await db.users.update_one(
        {"id": current_user.id},
        {"$set": {"password_hash": new_hash}}
    )
    
    return {"message": "Password updated successfully"}


# User Management Routes (Admin only)
@api_router.get("/users", response_model=List[User])
async def get_users(current_user: User = Depends(get_current_user)):
    """Get all users (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(100)
    return users

class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    role: str = "technician"

@api_router.post("/users", response_model=User)
async def create_user(user_data: UserCreate, current_user: User = Depends(get_current_user)):
    """Create a new user (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if email already exists
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    new_user = {
        "id": str(uuid.uuid4()),
        "name": user_data.name,
        "email": user_data.email,
        "password_hash": get_password_hash(user_data.password),
        "role": user_data.role,
        "company_ids": [],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.users.insert_one(new_user)
    
    # Remove password_hash from response
    del new_user["password_hash"]
    del new_user["_id"]
    
    return new_user

class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None

@api_router.put("/users/{user_id}", response_model=User)
async def update_user(user_id: str, user_data: UserUpdate, current_user: User = Depends(get_current_user)):
    """Update a user (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Find user
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prepare update data
    update_data = {}
    if user_data.name:
        update_data["name"] = user_data.name
    if user_data.email:
        # Check if email is already taken by another user
        existing = await db.users.find_one({"email": user_data.email, "id": {"$ne": user_id}})
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use")
        update_data["email"] = user_data.email
    if user_data.password:
        update_data["password_hash"] = get_password_hash(user_data.password)
    
    if update_data:
        await db.users.update_one({"id": user_id}, {"$set": update_data})
    
    # Get updated user
    updated_user = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    return updated_user

@api_router.delete("/users/{user_id}")
async def delete_user(user_id: str, current_user: User = Depends(get_current_user)):
    """Delete a user (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Don't allow deleting yourself
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    result = await db.users.delete_one({"id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User deleted successfully"}


# Company Routes
@api_router.get("/companies", response_model=List[Company])
async def get_companies():
    companies = await db.companies.find({}, {"_id": 0}).to_list(100)
    return companies

@api_router.get("/companies/{company_id}", response_model=Company)
async def get_company(company_id: str):
    company = await db.companies.find_one({"id": company_id}, {"_id": 0})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    return company

class CompanyCreate(BaseModel):
    name: str
    policy: Dict[str, Any] = {"auto_approve_low_risk": True, "maintenance_window": "Sat 22:00-02:00"}
    assets: List[Dict[str, Any]] = []

@api_router.post("/companies", response_model=Company)
async def create_company(company_data: CompanyCreate):
    # Check if company exists
    existing = await db.companies.find_one({"name": company_data.name})
    if existing:
        raise HTTPException(status_code=400, detail="Company with this name already exists")
    
    company = Company(**company_data.model_dump())
    # Generate API key for new company
    company.api_key = generate_api_key()
    company.api_key_created_at = datetime.now(timezone.utc).isoformat()
    
    await db.companies.insert_one(company.model_dump())
    
    # Initialize KPI for new company
    kpi = KPI(company_id=company.id)
    await db.kpis.insert_one(kpi.model_dump())
    
    return company

@api_router.put("/companies/{company_id}", response_model=Company)
async def update_company(company_id: str, company_data: CompanyCreate):
    existing = await db.companies.find_one({"id": company_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Company not found")
    
    update_data = company_data.model_dump()
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.companies.update_one(
        {"id": company_id},
        {"$set": update_data}
    )
    
    updated = await db.companies.find_one({"id": company_id}, {"_id": 0})
    return Company(**updated)

@api_router.delete("/companies/{company_id}")
async def delete_company(company_id: str):
    result = await db.companies.delete_one({"id": company_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Company not found")
    
    # Cleanup related data
    await db.alerts.delete_many({"company_id": company_id})
    await db.incidents.delete_many({"company_id": company_id})
    await db.runbooks.delete_many({"company_id": company_id})
    await db.patch_plans.delete_many({"company_id": company_id})
    await db.kpis.delete_many({"company_id": company_id})
    
    return {"message": "Company deleted successfully"}

@api_router.post("/companies/{company_id}/regenerate-api-key", response_model=Company)
async def regenerate_api_key(company_id: str):
    """Regenerate API key for a company"""
    company = await db.companies.find_one({"id": company_id})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    # Generate new API key
    new_api_key = generate_api_key()
    
    await db.companies.update_one(
        {"id": company_id},
        {"$set": {
            "api_key": new_api_key,
            "api_key_created_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    updated = await db.companies.find_one({"id": company_id}, {"_id": 0})
    return Company(**updated)


# Alert Routes
@api_router.get("/alerts", response_model=List[Alert])
async def get_alerts(company_id: Optional[str] = None, status: Optional[str] = None):
    query = {}
    if company_id:
        query["company_id"] = company_id
    if status:
        query["status"] = status
    
    alerts = await db.alerts.find(query, {"_id": 0}).sort("timestamp", -1).to_list(500)
    return alerts

@api_router.post("/alerts/generate")
async def generate_alerts(company_id: str, count: int = 50):
    """Generate mock alerts for demo purposes"""
    company = await db.companies.find_one({"id": company_id}, {"_id": 0})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    signatures = [
        "service_down:nginx", "service_down:mysql", "service_down:redis",
        "disk_full", "memory_high", "cpu_spike", "network_timeout",
        "ssl_expiring", "backup_failed", "replication_lag"
    ]
    severities = ["low", "medium", "high", "critical"]
    tools = ["Nagios", "Zabbix", "Datadog", "Prometheus", "CloudWatch"]
    
    generated_alerts = []
    base_time = datetime.now(timezone.utc)
    
    for i in range(count):
        asset = random.choice(company["assets"])
        signature = random.choice(signatures)
        
        alert = Alert(
            company_id=company_id,
            asset_id=asset["id"],
            asset_name=asset["name"],
            signature=signature,
            severity=random.choice(severities),
            message=f"{signature.replace('_', ' ').title()} detected on {asset['name']}",
            tool_source=random.choice(tools),
            timestamp=(base_time - timedelta(minutes=random.randint(0, 120))).isoformat()
        )
        
        doc = alert.model_dump()
        await db.alerts.insert_one(doc)
        generated_alerts.append(alert)
    
    return {"generated": len(generated_alerts), "alerts": generated_alerts[:10]}


# Incident Routes
@api_router.get("/incidents", response_model=List[Incident])
async def get_incidents(company_id: Optional[str] = None, status: Optional[str] = None):
    query = {}
    if company_id:
        query["company_id"] = company_id
    if status:
        query["status"] = status
    
    incidents = await db.incidents.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    return incidents

@api_router.post("/incidents/correlate")
async def correlate_alerts(company_id: str):
    """Correlate alerts into incidents using signature + asset grouping"""
    # Get all active alerts
    alerts = await db.alerts.find({
        "company_id": company_id,
        "status": "active"
    }, {"_id": 0}).to_list(1000)
    
    # Group by signature + asset
    incident_groups = {}
    for alert in alerts:
        key = f"{alert['signature']}:{alert['asset_id']}"
        if key not in incident_groups:
            incident_groups[key] = []
        incident_groups[key].append(alert)
    
    # Create incidents
    created_incidents = []
    for key, alert_group in incident_groups.items():
        if len(alert_group) == 0:
            continue
        
        first_alert = alert_group[0]
        
        # Check if incident already exists
        existing = await db.incidents.find_one({
            "company_id": company_id,
            "signature": first_alert["signature"],
            "asset_id": first_alert["asset_id"],
            "status": {"$ne": "resolved"}
        })
        
        if existing:
            # Update existing incident
            await db.incidents.update_one(
                {"id": existing["id"]},
                {
                    "$set": {
                        "alert_count": len(alert_group),
                        "updated_at": datetime.now(timezone.utc).isoformat()
                    },
                    "$addToSet": {"alert_ids": {"$each": [a["id"] for a in alert_group]}}
                }
            )
            continue
        
        # Create new incident
        incident = Incident(
            company_id=company_id,
            alert_ids=[a["id"] for a in alert_group],
            alert_count=len(alert_group),
            signature=first_alert["signature"],
            asset_id=first_alert["asset_id"],
            asset_name=first_alert["asset_name"],
            severity=first_alert["severity"]
        )
        
        doc = incident.model_dump()
        await db.incidents.insert_one(doc)
        created_incidents.append(incident)
        
        # Mark alerts as acknowledged
        await db.alerts.update_many(
            {"id": {"$in": [a["id"] for a in alert_group]}},
            {"$set": {"status": "acknowledged"}}
        )
        
        # Log activity
        activity = {
            "id": str(uuid.uuid4()),
            "company_id": company_id,
            "type": "incident_created",
            "message": f"Incident created: {incident.signature} on {incident.asset_name} ({incident.alert_count} alerts)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": incident.severity
        }
        await db.activities.insert_one(activity)
    
    # Update KPIs
    total_alerts = len(alerts)
    total_incidents = len(incident_groups)
    noise_reduction = ((total_alerts - total_incidents) / total_alerts * 100) if total_alerts > 0 else 0
    
    await db.kpis.update_one(
        {"company_id": company_id},
        {
            "$set": {
                "total_alerts": total_alerts,
                "total_incidents": total_incidents,
                "noise_reduction_pct": round(noise_reduction, 2),
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        },
        upsert=True
    )
    
    return {
        "total_alerts": total_alerts,
        "incidents_created": len(created_incidents),
        "noise_reduction_pct": round(noise_reduction, 2),
        "incidents": created_incidents
    }

@api_router.post("/incidents/{incident_id}/decide")
async def decide_on_incident(incident_id: str):
    """Generate decision for an incident using AI"""
    incident_doc = await db.incidents.find_one({"id": incident_id}, {"_id": 0})
    if not incident_doc:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    incident = Incident(**incident_doc)
    
    # Get company
    company_doc = await db.companies.find_one({"id": incident.company_id}, {"_id": 0})
    company = Company(**company_doc)
    
    # Find matching runbook
    runbook_doc = await db.runbooks.find_one({
        "company_id": incident.company_id,
        "signature": incident.signature
    }, {"_id": 0})
    
    runbook = Runbook(**runbook_doc) if runbook_doc else None
    
    # Generate decision
    decision = await generate_decision(incident, company, runbook)
    
    # Update incident with decision
    await db.incidents.update_one(
        {"id": incident_id},
        {
            "$set": {
                "decision": decision,
                "priority_score": decision["priority_score"],
                "status": "in_progress",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    
    # Log audit
    audit = AuditLog(
        incident_id=incident_id,
        event_type=decision["action"],
        payload=decision
    )
    await db.audit_logs.insert_one(audit.model_dump())
    
    return decision

@api_router.post("/incidents/{incident_id}/approve")
async def approve_incident(incident_id: str):
    """Approve an incident for execution"""
    incident_doc = await db.incidents.find_one({"id": incident_id}, {"_id": 0})
    if not incident_doc:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Simulate runbook execution
    await db.incidents.update_one(
        {"id": incident_id},
        {
            "$set": {
                "status": "resolved",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    
    # Update KPIs
    company_id = incident_doc["company_id"]
    kpi_doc = await db.kpis.find_one({"company_id": company_id})
    if kpi_doc:
        self_healed = kpi_doc.get("self_healed_count", 0) + 1
        total_incidents = kpi_doc.get("total_incidents", 1)
        self_healed_pct = (self_healed / total_incidents * 100) if total_incidents > 0 else 0
        
        await db.kpis.update_one(
            {"company_id": company_id},
            {
                "$set": {
                    "self_healed_count": self_healed,
                    "self_healed_pct": round(self_healed_pct, 2),
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }
            }
        )
    
    return {"message": "Incident approved and executed", "status": "resolved"}

@api_router.post("/incidents/{incident_id}/escalate")
async def escalate_incident(incident_id: str):
    """Escalate an incident to a technician"""
    await db.incidents.update_one(
        {"id": incident_id},
        {
            "$set": {
                "status": "escalated",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    
    return {"message": "Incident escalated to on-call technician"}


# Runbook Routes
@api_router.get("/runbooks", response_model=List[Runbook])
async def get_runbooks(company_id: Optional[str] = None):
    query = {}
    if company_id:
        query["company_id"] = company_id
    
    runbooks = await db.runbooks.find(query, {"_id": 0}).to_list(100)
    return runbooks

class RunbookCreate(BaseModel):
    name: str
    description: str
    risk_level: str
    signature: str
    actions: List[str] = []
    health_checks: Dict[str, Any] = {}
    auto_approve: bool = False
    company_id: str

@api_router.post("/runbooks", response_model=Runbook)
async def create_runbook(runbook_data: RunbookCreate):
    runbook = Runbook(**runbook_data.model_dump())
    await db.runbooks.insert_one(runbook.model_dump())
    return runbook

@api_router.put("/runbooks/{runbook_id}", response_model=Runbook)
async def update_runbook(runbook_id: str, runbook_data: RunbookCreate):
    existing = await db.runbooks.find_one({"id": runbook_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Runbook not found")
    
    await db.runbooks.update_one(
        {"id": runbook_id},
        {"$set": runbook_data.model_dump()}
    )
    
    updated = await db.runbooks.find_one({"id": runbook_id}, {"_id": 0})
    return Runbook(**updated)

@api_router.delete("/runbooks/{runbook_id}")
async def delete_runbook(runbook_id: str):
    result = await db.runbooks.delete_one({"id": runbook_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Runbook not found")
    return {"message": "Runbook deleted successfully"}


# Patch Routes
@api_router.get("/patches", response_model=List[PatchPlan])
async def get_patches(company_id: Optional[str] = None):
    query = {}
    if company_id:
        query["company_id"] = company_id
    
    patches = await db.patch_plans.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    return patches

@api_router.post("/patches/{patch_id}/canary")
async def start_canary(patch_id: str):
    """Start canary deployment"""
    await db.patch_plans.update_one(
        {"id": patch_id},
        {
            "$set": {
                "status": "canary_in_progress",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    return {"message": "Canary deployment started"}

@api_router.post("/patches/{patch_id}/rollout")
async def rollout_patch(patch_id: str):
    """Rollout patch to all assets"""
    await db.patch_plans.update_one(
        {"id": patch_id},
        {
            "$set": {
                "status": "rolling_out",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    return {"message": "Patch rollout initiated"}

@api_router.post("/patches/{patch_id}/complete")
async def complete_patch(patch_id: str):
    """Mark patch as complete"""
    await db.patch_plans.update_one(
        {"id": patch_id},
        {
            "$set": {
                "status": "complete",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    return {"message": "Patch deployment complete"}


# KPI Routes
@api_router.get("/kpis/{company_id}", response_model=KPI)
async def get_kpis(company_id: str):
    kpi = await db.kpis.find_one({"company_id": company_id}, {"_id": 0})
    if not kpi:
        # Return default KPI
        return KPI(company_id=company_id)
    return kpi


# Audit Routes
@api_router.get("/audit", response_model=List[AuditLog])
async def get_audit_logs(incident_id: Optional[str] = None, limit: int = 100):
    query = {}
    if incident_id:
        query["incident_id"] = incident_id
    
    logs = await db.audit_logs.find(query, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    return logs


# Webhook & Integration Routes
class WebhookAlert(BaseModel):
    asset_name: str
    signature: str
    severity: str
    message: str
    tool_source: str = "External"

@api_router.post("/webhooks/alerts")
async def receive_webhook_alert(alert_data: WebhookAlert, api_key: str):
    """Webhook endpoint for external monitoring tools to send alerts"""
    # Validate API key and get company
    company = await db.companies.find_one({"api_key": api_key})
    if not company:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    company_id = company["id"]
    
    # Find asset by name
    asset = None
    for a in company.get("assets", []):
        if a["name"] == alert_data.asset_name:
            asset = a
            break
    
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {alert_data.asset_name} not found")
    
    # Create alert
    alert = Alert(
        company_id=company_id,
        asset_id=asset["id"],
        asset_name=alert_data.asset_name,
        signature=alert_data.signature,
        severity=alert_data.severity,
        message=alert_data.message,
        tool_source=alert_data.tool_source
    )
    
    await db.alerts.insert_one(alert.model_dump())
    
    # Log activity
    activity = {
        "id": str(uuid.uuid4()),
        "company_id": company_id,
        "type": "alert_received",
        "message": f"New {alert_data.severity} alert: {alert_data.message}",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.activities.insert_one(activity)
    
    return {"message": "Alert received", "alert_id": alert.id}


# Activity Feed Routes
@api_router.get("/activities")
async def get_activities(company_id: Optional[str] = None, limit: int = 50):
    """Get real-time activity feed"""
    query = {}
    if company_id:
        query["company_id"] = company_id
    
    activities = await db.activities.find(query, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    return activities


# Real-time Stats Route
@api_router.get("/realtime/stats/{company_id}")
async def get_realtime_stats(company_id: str):
    """Get real-time statistics for live dashboard updates"""
    # Get counts
    active_alerts = await db.alerts.count_documents({"company_id": company_id, "status": "active"})
    total_incidents = await db.incidents.count_documents({"company_id": company_id})
    active_incidents = await db.incidents.count_documents({"company_id": company_id, "status": {"$in": ["new", "in_progress"]}})
    resolved_incidents = await db.incidents.count_documents({"company_id": company_id, "status": "resolved"})
    
    # Get recent activity
    recent_activities = await db.activities.find(
        {"company_id": company_id},
        {"_id": 0}
    ).sort("timestamp", -1).limit(10).to_list(10)
    
    # Get KPIs
    kpi = await db.kpis.find_one({"company_id": company_id}, {"_id": 0})
    
    return {
        "active_alerts": active_alerts,
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "resolved_incidents": resolved_incidents,
        "recent_activities": recent_activities,
        "kpis": kpi if kpi else {}
    }


# ============= Seed Data Route =============
@api_router.post("/seed")
async def seed_database():
    """Initialize database with mock MSP data"""
    
    # Clear existing data
    await db.users.delete_many({})
    await db.companies.delete_many({})
    await db.alerts.delete_many({})
    await db.incidents.delete_many({})
    await db.runbooks.delete_many({})
    await db.patch_plans.delete_many({})
    await db.kpis.delete_many({})
    await db.audit_logs.delete_many({})
    
    # Create companies
    companies = [
        Company(
            id="comp-acme",
            name="Acme Corp",
            policy={"auto_approve_low_risk": True, "maintenance_window": "Sat 22:00-02:00"},
            assets=[
                {"id": "srv-app-01", "name": "srv-app-01", "type": "webserver", "os": "Ubuntu 22.04"},
                {"id": "srv-app-02", "name": "srv-app-02", "type": "webserver", "os": "Ubuntu 22.04"},
                {"id": "srv-db-01", "name": "srv-db-01", "type": "database", "os": "Ubuntu 22.04"},
                {"id": "srv-redis-01", "name": "srv-redis-01", "type": "cache", "os": "Ubuntu 22.04"},
                {"id": "srv-lb-01", "name": "srv-lb-01", "type": "loadbalancer", "os": "Ubuntu 22.04"},
            ],
            api_key=generate_api_key(),
            api_key_created_at=datetime.now(timezone.utc).isoformat()
        ),
        Company(
            id="comp-techstart",
            name="TechStart Inc",
            policy={"auto_approve_low_risk": False, "maintenance_window": "Sun 00:00-04:00"},
            assets=[
                {"id": "win-dc-01", "name": "win-dc-01", "type": "domain_controller", "os": "Windows Server 2022"},
                {"id": "win-app-01", "name": "win-app-01", "type": "appserver", "os": "Windows Server 2022"},
                {"id": "win-db-01", "name": "win-db-01", "type": "database", "os": "Windows Server 2022"},
                {"id": "srv-api-01", "name": "srv-api-01", "type": "apiserver", "os": "Ubuntu 22.04"},
            ],
            api_key=generate_api_key(),
            api_key_created_at=datetime.now(timezone.utc).isoformat()
        ),
        Company(
            id="comp-global",
            name="Global Services Ltd",
            policy={"auto_approve_low_risk": True, "maintenance_window": "Fri 23:00-03:00"},
            assets=[
                {"id": "srv-web-01", "name": "srv-web-01", "type": "webserver", "os": "CentOS 8"},
                {"id": "srv-web-02", "name": "srv-web-02", "type": "webserver", "os": "CentOS 8"},
                {"id": "srv-mysql-01", "name": "srv-mysql-01", "type": "database", "os": "Ubuntu 22.04"},
                {"id": "srv-backup-01", "name": "srv-backup-01", "type": "backup", "os": "Ubuntu 22.04"},
            ],
            api_key=generate_api_key(),
            api_key_created_at=datetime.now(timezone.utc).isoformat()
        )
    ]
    
    for company in companies:
        await db.companies.insert_one(company.model_dump())
    
    # Create users
    users = [
        UserCreate(
            email="admin@alertwhisperer.com",
            password="admin123",
            name="Admin User",
            role="admin",
            company_ids=["comp-acme", "comp-techstart", "comp-global"]
        ),
        UserCreate(
            email="tech@acme.com",
            password="tech123",
            name="Acme Technician",
            role="technician",
            company_ids=["comp-acme"]
        ),
        UserCreate(
            email="tech@techstart.com",
            password="tech123",
            name="TechStart Technician",
            role="technician",
            company_ids=["comp-techstart"]
        )
    ]
    
    for user_data in users:
        user_dict = user_data.model_dump()
        password = user_dict.pop("password")
        user = User(**user_dict)
        doc = user.model_dump()
        doc["password_hash"] = get_password_hash(password)
        await db.users.insert_one(doc)
    
    # Create runbooks
    runbooks = [
        # Acme runbooks
        Runbook(
            company_id="comp-acme",
            name="Restart Nginx",
            description="Restart nginx service and verify health",
            risk_level="low",
            signature="service_down:nginx",
            actions=["sudo systemctl restart nginx", "curl -f http://localhost/healthz"],
            health_checks={"type": "http", "url": "http://localhost/healthz", "status": 200},
            auto_approve=True
        ),
        Runbook(
            company_id="comp-acme",
            name="Free Disk Space",
            description="Clean old logs to free disk space",
            risk_level="medium",
            signature="disk_full",
            actions=["find /var/log -name '*.log' -mtime +7 -delete", "df -h"],
            health_checks={"type": "disk_free", "min_gb": 10},
            auto_approve=False
        ),
        Runbook(
            company_id="comp-acme",
            name="Restart Redis",
            description="Restart Redis cache service",
            risk_level="low",
            signature="service_down:redis",
            actions=["sudo systemctl restart redis", "redis-cli ping"],
            health_checks={"type": "tcp", "port": 6379},
            auto_approve=True
        ),
        # TechStart runbooks
        Runbook(
            company_id="comp-techstart",
            name="Restart IIS",
            description="Restart IIS web server",
            risk_level="medium",
            signature="service_down:iis",
            actions=["iisreset /restart"],
            health_checks={"type": "http", "status": 200},
            auto_approve=False
        ),
        Runbook(
            company_id="comp-techstart",
            name="Clear Memory Cache",
            description="Clear memory cache to reduce usage",
            risk_level="low",
            signature="memory_high",
            actions=["powershell Clear-RecycleBin -Force"],
            health_checks={"type": "memory", "max_pct": 85},
            auto_approve=False
        ),
    ]
    
    for runbook in runbooks:
        await db.runbooks.insert_one(runbook.model_dump())
    
    # Create patch plans
    patch_plans = [
        PatchPlan(
            company_id="comp-acme",
            patches=[
                {"id": "KB5012345", "name": "OpenSSL Security Update", "severity": "critical"},
                {"id": "KB5012346", "name": "Kernel Security Patch", "severity": "high"},
            ],
            canary_assets=["srv-app-02"],
            status="proposed",
            window="Sat 22:00-23:00"
        ),
        PatchPlan(
            company_id="comp-techstart",
            patches=[
                {"id": "KB5023456", "name": "Windows Security Update", "severity": "critical"},
            ],
            canary_assets=["win-app-01"],
            status="proposed",
            window="Sun 00:00-01:00"
        ),
    ]
    
    for patch_plan in patch_plans:
        await db.patch_plans.insert_one(patch_plan.model_dump())
    
    # Initialize KPIs
    for company in companies:
        kpi = KPI(company_id=company.id)
        await db.kpis.insert_one(kpi.model_dump())
    
    return {
        "message": "Database seeded successfully",
        "companies": len(companies),
        "users": len(users),
        "runbooks": len(runbooks),
        "patch_plans": len(patch_plans)
    }


# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()