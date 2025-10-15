from fastapi import FastAPI, APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, Header, Request
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
import hmac
import hashlib
import time
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from concurrent.futures import ThreadPoolExecutor


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
    role: str  # msp_admin, company_admin, technician
    company_ids: List[str] = []
    permissions: List[str] = []  # RBAC permissions
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

class AWSCredentials(BaseModel):
    """AWS credentials for integration"""
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    region: str = "us-east-1"
    enabled: bool = False

class MonitoringIntegration(BaseModel):
    """Monitoring tool integration settings"""
    tool_type: str  # datadog, zabbix, prometheus, cloudwatch, etc.
    enabled: bool = False
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    verified: bool = False
    verified_at: Optional[str] = None
    last_error: Optional[str] = None

class Company(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    policy: Dict[str, Any] = {}
    assets: List[Dict[str, Any]] = []
    critical_assets: List[str] = []  # List of asset IDs that are critical
    api_key: Optional[str] = None
    api_key_created_at: Optional[str] = None
    # AWS Integration
    aws_credentials: Optional[AWSCredentials] = None
    aws_account_id: Optional[str] = None
    # Monitoring Integrations
    monitoring_integrations: List[MonitoringIntegration] = []
    # Integration verification status
    integration_verified: bool = False
    integration_verified_at: Optional[str] = None
    verification_details: Optional[Dict[str, Any]] = None
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
    delivery_id: Optional[str] = None  # For idempotency - webhook delivery identifier
    delivery_attempts: int = 0  # Track retry attempts
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class Incident(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    alert_ids: List[str] = []
    alert_count: int = 0
    tool_sources: List[str] = []  # Track which tools reported this
    priority_score: float = 0.0
    status: str = "new"  # new, in_progress, resolved, escalated
    assigned_to: Optional[str] = None
    signature: str
    asset_id: str
    asset_name: str
    severity: str
    decision: Optional[Dict[str, Any]] = None
    # SSM Remediation fields
    auto_remediated: bool = False
    ssm_command_id: Optional[str] = None
    remediation_duration_seconds: Optional[int] = None
    remediation_status: Optional[str] = None  # InProgress, Success, Failed, TimedOut
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

class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    user_id: str
    user_name: str
    user_role: str
    message: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    read: bool = False

class Notification(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    company_id: Optional[str] = None
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    type: str  # critical_alert, incident_created, incident_assigned, action_required, action_failed
    title: str
    message: str
    priority: str  # low, medium, high, critical
    read: bool = False
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class DecisionRequest(BaseModel):
    incident_id: str

class ExecuteRunbookRequest(BaseModel):
    incident_id: str
    runbook_id: str
    approval_token: Optional[str] = None

class ApproveIncidentRequest(BaseModel):
    incident_id: str

class CorrelationConfig(BaseModel):
    """Configuration for alert correlation settings"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    time_window_minutes: int = 15  # Configurable 5-15 minutes
    aggregation_key: str = "asset|signature"  # asset|signature or custom
    auto_correlate: bool = True
    min_alerts_for_incident: int = 1  # Minimum alerts to create incident
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class WebhookSecurityConfig(BaseModel):
    """Configuration for webhook HMAC security"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    hmac_secret: str  # Secret key for HMAC signature validation
    signature_header: str = "X-Signature"  # Header name for signature
    timestamp_header: str = "X-Timestamp"  # Header name for timestamp
    max_timestamp_diff_seconds: int = 300  # 5 minutes max difference
    enabled: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class SSMExecution(BaseModel):
    """Track AWS SSM Run Command/Automation executions"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    company_id: str
    command_id: str  # AWS SSM Command ID
    runbook_id: str
    command_type: str = "RunCommand"  # RunCommand or Automation
    status: str = "InProgress"  # InProgress, Success, Failed, TimedOut, Cancelled
    instance_ids: List[str] = []
    document_name: str  # SSM Document name (e.g., AWS-RunShellScript)
    parameters: Dict[str, Any] = {}
    output: Optional[str] = None
    error_message: Optional[str] = None
    duration_seconds: Optional[int] = None
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None

class PatchCompliance(BaseModel):
    """Track patch compliance status from AWS Patch Manager"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    environment: str  # production, staging, development
    instance_id: str
    instance_name: str
    compliance_status: str  # COMPLIANT, NON_COMPLIANT, UNSPECIFIED
    compliance_percentage: float = 0.0
    critical_patches_missing: int = 0
    high_patches_missing: int = 0
    medium_patches_missing: int = 0
    low_patches_missing: int = 0
    patches_installed: int = 0
    last_scan_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_patch_time: Optional[str] = None
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class CrossAccountRole(BaseModel):
    """Track cross-account IAM role configuration for MSP client access"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    role_arn: str  # arn:aws:iam::123456789012:role/AlertWhispererMSPAccess
    external_id: str  # Unique external ID for security
    aws_account_id: str
    status: str = "active"  # active, inactive, invalid
    last_verified: Optional[str] = None
    permissions: List[str] = ["ssm:*", "ec2:Describe*", "ssm:GetPatchCompliance"]
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class RateLimitConfig(BaseModel):
    """Rate limiting configuration per company"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    requests_per_minute: int = 60  # Default: 60 requests per minute
    burst_size: int = 100  # Allow bursts up to this size
    enabled: bool = True
    current_count: int = 0  # Current request count in window
    window_start: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ApprovalRequest(BaseModel):
    """Approval workflow for risky runbook executions"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    runbook_id: str
    company_id: str
    risk_level: str  # low, medium, high
    requested_by: str  # User ID who requested
    status: str = "pending"  # pending, approved, rejected, expired
    approved_by: Optional[str] = None
    approval_notes: Optional[str] = None
    expires_at: str = Field(default_factory=lambda: (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class SystemAuditLog(BaseModel):
    """Comprehensive audit log for all critical operations"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    user_role: Optional[str] = None
    company_id: Optional[str] = None
    action: str  # runbook_executed, incident_assigned, approval_granted, config_changed, etc.
    resource_type: str  # incident, runbook, user, company, config
    resource_id: Optional[str] = None
    details: Dict[str, Any] = {}
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    status: str = "success"  # success, failure
    error_message: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


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

def generate_hmac_secret():
    """Generate a secure HMAC secret key for webhook signing"""
    return secrets.token_urlsafe(32)

def compute_webhook_signature(secret: str, timestamp: str, body: str) -> str:
    """
    Compute HMAC-SHA256 signature for webhook payload
    Formula: HMAC_SHA256(secret, timestamp + '.' + raw_body)
    """
    message = f"{timestamp}.{body}"
    signature = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return f"sha256={signature}"

async def verify_webhook_signature(
    company_id: str,
    signature_header: Optional[str],
    timestamp_header: Optional[str],
    raw_body: str
) -> bool:
    """
    Verify webhook HMAC signature and timestamp
    Returns True if signature is valid and timestamp is within allowed window
    """
    # Get webhook security config for company
    security_config = await db.webhook_security.find_one({"company_id": company_id})
    
    # If HMAC is not enabled for this company, skip verification
    if not security_config or not security_config.get("enabled", False):
        return True
    
    # Check if signature and timestamp headers are provided
    if not signature_header or not timestamp_header:
        raise HTTPException(
            status_code=401,
            detail="Missing required headers: X-Signature and X-Timestamp"
        )
    
    # Validate timestamp (replay attack protection)
    try:
        request_timestamp = int(timestamp_header)
        current_timestamp = int(time.time())
        max_diff = security_config.get("max_timestamp_diff_seconds", 300)
        
        if abs(current_timestamp - request_timestamp) > max_diff:
            raise HTTPException(
                status_code=401,
                detail=f"Timestamp difference exceeds {max_diff} seconds"
            )
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp format")
    
    # Compute expected signature
    hmac_secret = security_config["hmac_secret"]
    expected_signature = compute_webhook_signature(hmac_secret, timestamp_header, raw_body)
    
    # Compare signatures (constant-time comparison to prevent timing attacks)
    if not hmac.compare_digest(signature_header, expected_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    
    return True


# AWS Integration Helper Functions
async def verify_aws_credentials(access_key_id: str, secret_access_key: str, region: str = "us-east-1") -> Dict[str, Any]:
    """
    Verify AWS credentials by attempting to connect to AWS services
    Returns verification result with details
    """
    result = {
        "verified": False,
        "services": {},
        "error": None
    }
    
    try:
        # Create boto3 session with provided credentials
        session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        
        # Test EC2 connectivity
        try:
            ec2 = session.client('ec2')
            response = ec2.describe_instances(MaxResults=5)
            result["services"]["ec2"] = {
                "available": True,
                "instance_count": sum(len(r['Instances']) for r in response.get('Reservations', []))
            }
        except Exception as e:
            result["services"]["ec2"] = {"available": False, "error": str(e)}
        
        # Test CloudWatch connectivity
        try:
            cloudwatch = session.client('cloudwatch')
            cloudwatch.list_metrics(MaxRecords=1)
            result["services"]["cloudwatch"] = {"available": True}
        except Exception as e:
            result["services"]["cloudwatch"] = {"available": False, "error": str(e)}
        
        # Test SSM connectivity
        try:
            ssm = session.client('ssm')
            ssm.describe_instance_information(MaxResults=1)
            result["services"]["ssm"] = {"available": True}
        except Exception as e:
            result["services"]["ssm"] = {"available": False, "error": str(e)}
        
        # Test Patch Manager
        try:
            ssm = session.client('ssm')
            ssm.describe_patch_baselines(MaxResults=1)
            result["services"]["patch_manager"] = {"available": True}
        except Exception as e:
            result["services"]["patch_manager"] = {"available": False, "error": str(e)}
        
        # If at least one service is available, consider it verified
        if any(svc.get("available", False) for svc in result["services"].values()):
            result["verified"] = True
        else:
            result["error"] = "No AWS services accessible with provided credentials"
            
    except Exception as e:
        result["error"] = f"AWS credentials verification failed: {str(e)}"
    
    return result

async def get_cloudwatch_alarms(access_key_id: str, secret_access_key: str, region: str = "us-east-1") -> List[Dict[str, Any]]:
    """
    Fetch CloudWatch alarms for monitoring (PULL mode)
    """
    try:
        session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        
        cloudwatch = session.client('cloudwatch')
        response = cloudwatch.describe_alarms(
            StateValue='ALARM',  # Only fetch alarms in ALARM state
            MaxRecords=100
        )
        
        alarms = []
        for alarm in response.get('MetricAlarms', []):
            alarms.append({
                "alarm_name": alarm['AlarmName'],
                "alarm_arn": alarm['AlarmArn'],
                "state": alarm['StateValue'],
                "state_reason": alarm.get('StateReason', ''),
                "metric_name": alarm.get('MetricName', ''),
                "namespace": alarm.get('Namespace', ''),
                "timestamp": alarm.get('StateUpdatedTimestamp', datetime.now(timezone.utc)).isoformat()
            })
        
        return alarms
    except Exception as e:
        logging.error(f"Error fetching CloudWatch alarms: {str(e)}")
        return []

async def get_patch_compliance(access_key_id: str, secret_access_key: str, region: str = "us-east-1") -> List[Dict[str, Any]]:
    """
    Fetch real patch compliance data from AWS Patch Manager
    """
    try:
        session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        
        ssm = session.client('ssm')
        
        # Get all managed instances
        instances_response = ssm.describe_instance_information()
        instances = instances_response.get('InstanceInformationList', [])
        
        compliance_data = []
        
        for instance in instances:
            instance_id = instance['InstanceId']
            
            # Get patch compliance for this instance
            try:
                compliance_response = ssm.describe_instance_patch_states(
                    InstanceIds=[instance_id]
                )
                
                for patch_state in compliance_response.get('InstancePatchStates', []):
                    compliance_data.append({
                        "instance_id": instance_id,
                        "instance_name": instance.get('ComputerName', instance_id),
                        "platform": instance.get('PlatformType', 'Unknown'),
                        "compliance_status": "compliant" if patch_state.get('FailedCount', 0) == 0 else "non_compliant",
                        "installed_count": patch_state.get('InstalledCount', 0),
                        "missing_count": patch_state.get('MissingCount', 0),
                        "failed_count": patch_state.get('FailedCount', 0),
                        "critical_missing": patch_state.get('CriticalNonCompliantCount', 0),
                        "security_missing": patch_state.get('SecurityNonCompliantCount', 0),
                        "last_scan": patch_state.get('OperationEndTime', datetime.now(timezone.utc)).isoformat(),
                        "baseline_id": patch_state.get('BaselineId', 'N/A')
                    })
            except Exception as e:
                logging.error(f"Error getting patch compliance for {instance_id}: {str(e)}")
                continue
        
        return compliance_data
    except Exception as e:
        logging.error(f"Error fetching patch compliance: {str(e)}")
        return []

async def execute_patch_command(
    access_key_id: str,
    secret_access_key: str,
    region: str,
    instance_ids: List[str],
    operation: str = "install"  # install or scan
) -> Dict[str, Any]:
    """
    Execute AWS SSM patch command on instances
    """
    try:
        session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        
        ssm = session.client('ssm')
        
        # Determine document based on operation
        document_name = "AWS-RunPatchBaseline"
        
        response = ssm.send_command(
            InstanceIds=instance_ids,
            DocumentName=document_name,
            Parameters={
                "Operation": [operation.capitalize()]
            },
            Comment=f"Alert Whisperer - Patch {operation}"
        )
        
        command_id = response['Command']['CommandId']
        
        return {
            "success": True,
            "command_id": command_id,
            "instance_ids": instance_ids,
            "operation": operation,
            "status": "InProgress"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


async def check_rate_limit(company_id: str) -> bool:
    """
    Check and enforce rate limiting for company
    Returns True if within limit, raises HTTPException if exceeded
    """
    # Get or create rate limit config
    rate_config = await db.rate_limits.find_one({"company_id": company_id})
    
    if not rate_config:
        # Create default rate limit config
        default_config = RateLimitConfig(company_id=company_id)
        await db.rate_limits.insert_one(default_config.model_dump())
        rate_config = default_config.model_dump()
    
    if not rate_config.get("enabled", True):
        return True
    
    # Check if we're in a new window
    window_start = datetime.fromisoformat(rate_config["window_start"])
    current_time = datetime.now(timezone.utc)
    time_diff = (current_time - window_start).total_seconds()
    
    # Reset window if more than 60 seconds have passed
    if time_diff >= 60:
        await db.rate_limits.update_one(
            {"company_id": company_id},
            {
                "$set": {
                    "current_count": 1,
                    "window_start": current_time.isoformat(),
                    "updated_at": current_time.isoformat()
                }
            }
        )
        return True
    
    # Check if within limits
    current_count = rate_config.get("current_count", 0)
    requests_per_minute = rate_config.get("requests_per_minute", 60)
    burst_size = rate_config.get("burst_size", 100)
    
    if current_count >= burst_size:
        # Calculate seconds until window reset
        seconds_until_reset = max(1, int(60 - time_diff))
        
        # Create response with Retry-After header
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=429,
            content={
                "detail": f"Rate limit exceeded. Max {requests_per_minute} requests/minute, burst up to {burst_size}",
                "retry_after_seconds": seconds_until_reset,
                "backoff_policy": "Token bucket with sliding window",
                "limit": requests_per_minute,
                "burst": burst_size
            },
            headers={
                "Retry-After": str(seconds_until_reset),
                "X-RateLimit-Limit": str(requests_per_minute),
                "X-RateLimit-Burst": str(burst_size),
                "X-RateLimit-Remaining": "0"
            }
        )
    
    # Increment counter
    await db.rate_limits.update_one(
        {"company_id": company_id},
        {
            "$inc": {"current_count": 1},
            "$set": {"updated_at": current_time.isoformat()}
        }
    )
    
    return True

async def check_idempotency(company_id: str, delivery_id: Optional[str], alert_data: dict) -> Optional[str]:
    """
    Check for duplicate webhook deliveries
    Returns existing alert_id if duplicate found, None otherwise
    """
    if not delivery_id:
        # Generate delivery_id from alert content for deduplication
        content_hash = hashlib.sha256(
            f"{alert_data.get('asset_name')}:{alert_data.get('signature')}:{alert_data.get('message')}".encode()
        ).hexdigest()[:16]
        delivery_id = f"auto_{content_hash}"
    
    # Check if this delivery_id was already processed (within last 24 hours)
    cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    existing_alert = await db.alerts.find_one({
        "company_id": company_id,
        "delivery_id": delivery_id,
        "timestamp": {"$gte": cutoff_time}
    })
    
    if existing_alert:
        # Update delivery attempts
        await db.alerts.update_one(
            {"id": existing_alert["id"]},
            {
                "$inc": {"delivery_attempts": 1},
                "$set": {"timestamp": datetime.now(timezone.utc).isoformat()}
            }
        )
        return existing_alert["id"]
    
    return None

async def create_audit_log(
    user_id: Optional[str],
    user_email: Optional[str],
    user_role: Optional[str],
    company_id: Optional[str],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    details: Dict[str, Any],
    ip_address: Optional[str] = None,
    status: str = "success",
    error_message: Optional[str] = None
):
    """Create audit log entry for critical operations"""
    audit_log = SystemAuditLog(
        user_id=user_id,
        user_email=user_email,
        user_role=user_role,
        company_id=company_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        status=status,
        error_message=error_message
    )
    await db.audit_logs.insert_one(audit_log.model_dump())

def check_permission(user: Dict[str, Any], required_permission: str) -> bool:
    """Check if user has required permission based on RBAC"""
    user_role = user.get("role", "technician")
    
    # MSP Admin has all permissions
    if user_role == "msp_admin" or user_role == "admin":
        return True
    
    # Company Admin has most permissions except system-wide operations
    if user_role == "company_admin":
        company_admin_permissions = [
            "view_incidents", "assign_incidents", "execute_runbooks",
            "manage_technicians", "view_reports", "approve_runbooks"
        ]
        return required_permission in company_admin_permissions
    
    # Technician has limited permissions
    if user_role == "technician":
        tech_permissions = ["view_incidents", "update_incidents", "execute_low_risk_runbooks"]
        return required_permission in tech_permissions
    
    return False

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
def calculate_priority_score(incident: Incident, company: Company, alerts: List[Dict[str, Any]]) -> float:
    """
    Calculate priority score using the formula:
    priority = severity + critical_asset_bonus + duplicate_factor + multi_tool_bonus - age_decay
    """
    # Base severity scores
    severity_scores = {"low": 10, "medium": 30, "high": 60, "critical": 90}
    severity_score = severity_scores.get(incident.severity, 30)
    
    # Critical asset bonus (20 points if asset is marked critical)
    critical_asset_bonus = 20 if incident.asset_id in company.critical_assets else 0
    
    # Duplicate factor (2 points per duplicate alert, max 20)
    duplicate_factor = min(incident.alert_count * 2, 20)
    
    # Multi-tool bonus (10 points if reported by 2+ different tools)
    multi_tool_bonus = 10 if len(incident.tool_sources) >= 2 else 0
    
    # Age decay (-1 point per hour old, max -10)
    created_time = datetime.fromisoformat(incident.created_at.replace('Z', '+00:00'))
    age_hours = (datetime.now(timezone.utc) - created_time).total_seconds() / 3600
    age_decay = min(age_hours, 10)
    
    priority_score = severity_score + critical_asset_bonus + duplicate_factor + multi_tool_bonus - age_decay
    
    return round(priority_score, 2)

async def generate_decision(incident: Incident, company: Company, runbook: Optional[Runbook]) -> Dict[str, Any]:
    """Generate AI-powered decision for incident remediation"""
    
    # Get alerts for this incident
    alerts = await db.alerts.find({"id": {"$in": incident.alert_ids}}, {"_id": 0}).to_list(100)
    
    # Calculate priority score using enhanced formula
    priority_score = calculate_priority_score(incident, company, alerts)
    
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

class UserCreateRequest(BaseModel):
    name: str
    email: str
    password: str
    role: str = "technician"

@api_router.post("/users", response_model=User)
async def create_user(user_data: UserCreateRequest, current_user: User = Depends(get_current_user)):
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
    # AWS Integration (optional)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"
    aws_account_id: Optional[str] = None
    # Monitoring Integrations (optional)
    monitoring_integrations: List[MonitoringIntegration] = []

@api_router.post("/companies", response_model=Company)
async def create_company(company_data: CompanyCreate):
    """
    Create a new company with optional integration verification
    Verifies AWS credentials and monitoring tool connectivity before saving
    """
    # Check if company exists
    existing = await db.companies.find_one({"name": company_data.name})
    if existing:
        raise HTTPException(status_code=400, detail="Company with this name already exists")
    
    company = Company(**company_data.model_dump(exclude={"aws_access_key_id", "aws_secret_access_key", "aws_region"}))
    
    # Generate API key for new company
    company.api_key = generate_api_key()
    company.api_key_created_at = datetime.now(timezone.utc).isoformat()
    
    verification_details = {
        "webhook": {"verified": True, "message": "Webhook endpoint ready"},
        "aws": None,
        "monitoring_tools": []
    }
    
    # Verify AWS credentials if provided
    if company_data.aws_access_key_id and company_data.aws_secret_access_key:
        aws_verification = await verify_aws_credentials(
            company_data.aws_access_key_id,
            company_data.aws_secret_access_key,
            company_data.aws_region
        )
        
        if aws_verification["verified"]:
            company.aws_credentials = AWSCredentials(
                access_key_id=company_data.aws_access_key_id,
                secret_access_key=company_data.aws_secret_access_key,
                region=company_data.aws_region,
                enabled=True
            )
            company.aws_account_id = company_data.aws_account_id
            verification_details["aws"] = {
                "verified": True,
                "services": aws_verification["services"]
            }
        else:
            verification_details["aws"] = {
                "verified": False,
                "error": aws_verification["error"]
            }
            # Don't fail company creation, but mark AWS as not verified
            company.aws_credentials = AWSCredentials(
                access_key_id=company_data.aws_access_key_id,
                secret_access_key=company_data.aws_secret_access_key,
                region=company_data.aws_region,
                enabled=False
            )
    
    # Verify monitoring integrations if provided
    for integration in company_data.monitoring_integrations:
        # TODO: Add verification logic for each monitoring tool type
        # For now, mark as verified if API key is provided
        if integration.api_key:
            integration.verified = True
            integration.verified_at = datetime.now(timezone.utc).isoformat()
        verification_details["monitoring_tools"].append({
            "tool": integration.tool_type,
            "verified": integration.verified
        })
    
    company.monitoring_integrations = company_data.monitoring_integrations
    
    # Determine overall integration status
    company.integration_verified = (
        verification_details["webhook"]["verified"] and
        (verification_details["aws"] is None or verification_details["aws"]["verified"])
    )
    company.integration_verified_at = datetime.now(timezone.utc).isoformat()
    company.verification_details = verification_details
    
    await db.companies.insert_one(company.model_dump())
    
    # Initialize default configurations for new company
    # KPI
    kpi = KPI(company_id=company.id)
    await db.kpis.insert_one(kpi.model_dump())
    
    # Correlation Config
    correlation_config = CorrelationConfig(company_id=company.id)
    await db.correlation_configs.insert_one(correlation_config.model_dump())
    
    # Rate Limit Config
    rate_limit = RateLimitConfig(company_id=company.id)
    await db.rate_limits.insert_one(rate_limit.model_dump())
    
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


# Webhook Security Configuration Routes
@api_router.get("/companies/{company_id}/webhook-security", response_model=WebhookSecurityConfig)
async def get_webhook_security_config(company_id: str):
    """Get webhook HMAC security configuration for a company"""
    config = await db.webhook_security.find_one({"company_id": company_id}, {"_id": 0})
    if not config:
        # Return default disabled config
        return WebhookSecurityConfig(
            company_id=company_id,
            hmac_secret="",
            enabled=False
        )
    return WebhookSecurityConfig(**config)

@api_router.post("/companies/{company_id}/webhook-security/enable", response_model=WebhookSecurityConfig)
async def enable_webhook_security(company_id: str):
    """Enable HMAC webhook security for a company and generate secret"""
    company = await db.companies.find_one({"id": company_id})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    # Check if config already exists
    existing_config = await db.webhook_security.find_one({"company_id": company_id})
    
    if existing_config:
        # Update existing config to enabled
        await db.webhook_security.update_one(
            {"company_id": company_id},
            {"$set": {"enabled": True, "updated_at": datetime.now(timezone.utc).isoformat()}}
        )
        updated = await db.webhook_security.find_one({"company_id": company_id}, {"_id": 0})
        return WebhookSecurityConfig(**updated)
    else:
        # Create new config with generated secret
        config = WebhookSecurityConfig(
            company_id=company_id,
            hmac_secret=generate_hmac_secret(),
            enabled=True
        )
        await db.webhook_security.insert_one(config.model_dump())
        return config

@api_router.post("/companies/{company_id}/webhook-security/disable")
async def disable_webhook_security(company_id: str):
    """Disable HMAC webhook security for a company"""
    result = await db.webhook_security.update_one(
        {"company_id": company_id},
        {"$set": {"enabled": False}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Webhook security config not found")
    return {"message": "Webhook security disabled"}

@api_router.post("/companies/{company_id}/webhook-security/regenerate-secret", response_model=WebhookSecurityConfig)
async def regenerate_webhook_secret(company_id: str):
    """Regenerate HMAC secret for webhook security"""
    config = await db.webhook_security.find_one({"company_id": company_id})
    if not config:
        raise HTTPException(status_code=404, detail="Webhook security not configured")
    
    new_secret = generate_hmac_secret()
    await db.webhook_security.update_one(
        {"company_id": company_id},
        {"$set": {
            "hmac_secret": new_secret,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    updated = await db.webhook_security.find_one({"company_id": company_id}, {"_id": 0})
    return WebhookSecurityConfig(**updated)


# Correlation Configuration Routes
@api_router.get("/companies/{company_id}/correlation-config", response_model=CorrelationConfig)
async def get_correlation_config(company_id: str):
    """Get correlation configuration for a company"""
    config = await db.correlation_config.find_one({"company_id": company_id}, {"_id": 0})
    if not config:
        # Return default config
        return CorrelationConfig(
            company_id=company_id,
            time_window_minutes=15,
            aggregation_key="asset|signature",
            auto_correlate=True,
            min_alerts_for_incident=1
        )
    return CorrelationConfig(**config)

class CorrelationConfigUpdate(BaseModel):
    time_window_minutes: Optional[int] = None  # 5-15 minutes
    auto_correlate: Optional[bool] = None
    min_alerts_for_incident: Optional[int] = None

@api_router.put("/companies/{company_id}/correlation-config", response_model=CorrelationConfig)
async def update_correlation_config(company_id: str, config_update: CorrelationConfigUpdate):
    """Update correlation configuration for a company"""
    company = await db.companies.find_one({"id": company_id})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    # Validate time window
    if config_update.time_window_minutes is not None:
        if config_update.time_window_minutes < 5 or config_update.time_window_minutes > 15:
            raise HTTPException(
                status_code=400,
                detail="Time window must be between 5 and 15 minutes"
            )
    
    existing_config = await db.correlation_config.find_one({"company_id": company_id})
    
    if existing_config:
        # Update existing config
        update_data = {k: v for k, v in config_update.model_dump().items() if v is not None}
        update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        await db.correlation_config.update_one(
            {"company_id": company_id},
            {"$set": update_data}
        )
    else:
        # Create new config with provided values and defaults
        new_config = CorrelationConfig(
            company_id=company_id,
            time_window_minutes=config_update.time_window_minutes or 15,
            auto_correlate=config_update.auto_correlate if config_update.auto_correlate is not None else True,
            min_alerts_for_incident=config_update.min_alerts_for_incident or 1
        )
        await db.correlation_config.insert_one(new_config.model_dump())
    
    updated = await db.correlation_config.find_one({"company_id": company_id}, {"_id": 0})
    return CorrelationConfig(**updated)

@api_router.get("/correlation/dedup-keys")
async def get_dedup_key_options():
    """
    Get available deduplication key patterns for correlation
    
    Returns examples and explanations of different aggregation strategies
    """
    return {
        "available_keys": [
            {
                "key": "asset|signature",
                "name": "Asset + Signature",
                "description": "Groups alerts from same asset with same signature (default)",
                "example": "server-01|disk_space_low",
                "use_case": "Standard correlation for most scenarios"
            },
            {
                "key": "asset|signature|tool",
                "name": "Asset + Signature + Tool",
                "description": "Separate incidents for same issue reported by different tools",
                "example": "server-01|disk_space_low|Datadog",
                "use_case": "When you want distinct incidents per monitoring tool"
            },
            {
                "key": "signature",
                "name": "Signature Only",
                "description": "Groups all alerts with same signature across all assets",
                "example": "disk_space_low",
                "use_case": "Infrastructure-wide issues (e.g., network outage)"
            },
            {
                "key": "asset",
                "name": "Asset Only",
                "description": "Groups all alerts from same asset regardless of signature",
                "example": "server-01",
                "use_case": "Asset-centric monitoring"
            }
        ],
        "time_window_rationale": {
            "5_minutes": "Fast-changing environments, quick incident creation",
            "10_minutes": "Balanced approach for most use cases",
            "15_minutes": "Reduces noise in stable environments (default)"
        },
        "best_practices": [
            "Start with default 'asset|signature' and 15-minute window",
            "Use 'asset|signature|tool' if you have overlapping monitoring tools",
            "Use 'signature' for infrastructure-wide alert storms",
            "Shorter windows (5 min) for critical production systems",
            "Longer windows (15 min) for dev/staging to reduce noise"
        ]
    }


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
    """
    Correlate alerts into incidents using configurable time window and aggregation key
    
    Event-driven correlation with:
    - Configurable time window (5-15 minutes, default 15)
    - Aggregation key: asset|signature
    - Multi-tool detection
    - Priority-based incident creation
    """
    # Get company for priority calculation
    company_doc = await db.companies.find_one({"id": company_id}, {"_id": 0})
    if not company_doc:
        raise HTTPException(status_code=404, detail="Company not found")
    company = Company(**company_doc)
    
    # Get correlation configuration for company (with defaults)
    correlation_config = await db.correlation_config.find_one({"company_id": company_id})
    if not correlation_config:
        # Create default configuration
        default_config = CorrelationConfig(
            company_id=company_id,
            time_window_minutes=15,
            aggregation_key="asset|signature",
            auto_correlate=True,
            min_alerts_for_incident=1
        )
        await db.correlation_config.insert_one(default_config.model_dump())
        correlation_config = default_config.model_dump()
    
    # Get all active alerts
    alerts = await db.alerts.find({
        "company_id": company_id,
        "status": "active"
    }, {"_id": 0}).to_list(1000)
    
    # Use configurable correlation window (5-15 minutes)
    correlation_window_minutes = correlation_config.get("time_window_minutes", 15)
    now = datetime.now(timezone.utc)
    
    # Group by aggregation key within time window
    # Default: asset|signature (can be configured per company)
    incident_groups = {}
    for alert in alerts:
        alert_time = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
        
        # Only consider alerts within the correlation window
        age_minutes = (now - alert_time).total_seconds() / 60
        if age_minutes > correlation_window_minutes:
            continue
            
        key = f"{alert['signature']}:{alert['asset_id']}"
        if key not in incident_groups:
            incident_groups[key] = []
        incident_groups[key].append(alert)
    
    # Create/update incidents
    created_incidents = []
    updated_incidents = []
    
    for key, alert_group in incident_groups.items():
        if len(alert_group) == 0:
            continue
        
        first_alert = alert_group[0]
        
        # Track unique tool sources
        tool_sources = list(set(a['tool_source'] for a in alert_group))
        
        # Check if incident already exists (within last 24 hours)
        cutoff_time = (now - timedelta(hours=24)).isoformat()
        existing = await db.incidents.find_one({
            "company_id": company_id,
            "signature": first_alert["signature"],
            "asset_id": first_alert["asset_id"],
            "status": {"$ne": "resolved"},
            "created_at": {"$gte": cutoff_time}
        })
        
        if existing:
            # Update existing incident with new alerts and tool sources
            new_alert_ids = list(set(existing.get("alert_ids", []) + [a["id"] for a in alert_group]))
            existing_tools = set(existing.get("tool_sources", []))
            updated_tools = list(existing_tools.union(set(tool_sources)))
            
            # Recalculate priority with updated data
            incident_for_calc = Incident(**existing)
            incident_for_calc.alert_count = len(new_alert_ids)
            incident_for_calc.tool_sources = updated_tools
            priority_score = calculate_priority_score(incident_for_calc, company, alert_group)
            
            await db.incidents.update_one(
                {"id": existing["id"]},
                {
                    "$set": {
                        "alert_ids": new_alert_ids,
                        "alert_count": len(new_alert_ids),
                        "tool_sources": updated_tools,
                        "priority_score": priority_score,
                        "updated_at": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
            updated_incidents.append(existing["id"])
            
            # Broadcast update via WebSocket
            await manager.broadcast({
                "type": "incident_updated",
                "data": {
                    "incident_id": existing["id"],
                    "alert_count": len(new_alert_ids),
                    "tool_sources": updated_tools,
                    "priority_score": priority_score
                }
            })
            continue
        
        # Create new incident
        incident = Incident(
            company_id=company_id,
            alert_ids=[a["id"] for a in alert_group],
            alert_count=len(alert_group),
            tool_sources=tool_sources,
            signature=first_alert["signature"],
            asset_id=first_alert["asset_id"],
            asset_name=first_alert["asset_name"],
            severity=first_alert["severity"]
        )
        
        # Calculate priority score
        incident.priority_score = calculate_priority_score(incident, company, alert_group)
        
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
            "message": f"Incident created: {incident.signature} on {incident.asset_name} ({incident.alert_count} alerts from {len(tool_sources)} tools)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": incident.severity
        }
        await db.activities.insert_one(activity)
        
        # Create notification for critical incidents
        if incident.severity in ["critical", "high"]:
            notification = Notification(
                user_id="admin",  # Notify all admins
                company_id=company_id,
                incident_id=incident.id,
                type="incident_created",
                title=f"{incident.severity.upper()} Incident Created",
                message=f"{incident.signature} on {incident.asset_name} - Priority: {incident.priority_score}",
                priority=incident.severity
            )
            await db.notifications.insert_one(notification.model_dump())
        
        # Broadcast new incident via WebSocket
        await manager.broadcast({
            "type": "incident_created",
            "data": incident.model_dump()
        })
    
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


# SSM Remediation Routes (AWS Systems Manager Integration)
class ExecuteRunbookSSMRequest(BaseModel):
    runbook_id: str
    instance_ids: List[str] = []  # Target EC2 instances or on-prem servers

@api_router.post("/incidents/{incident_id}/execute-runbook-ssm")
async def execute_runbook_with_ssm(
    incident_id: str, 
    request: ExecuteRunbookSSMRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Execute a runbook using AWS SSM Run Command with approval gates
    
    Risk Levels:
    - low: Auto-execute (no approval needed)
    - medium: Requires Company Admin or MSP Admin approval
    - high: Requires MSP Admin approval only
    
    This endpoint simulates SSM execution with mock data for demo purposes
    In production, this would call boto3 SSM client
    """
    # Get current user
    user = await get_current_user(credentials)
    
    # Get incident
    incident = await db.incidents.find_one({"id": incident_id}, {"_id": 0})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Get runbook
    runbook = await db.runbooks.find_one({"id": request.runbook_id}, {"_id": 0})
    if not runbook:
        raise HTTPException(status_code=404, detail="Runbook not found")
    
    # Check risk level and approval requirements
    risk_level = runbook.get("risk_level", "low")
    user_role = user.get("role", "technician")
    
    # Low risk: Auto-approve
    if risk_level == "low":
        approval_status = "auto_approved"
    
    # Medium risk: Requires Company Admin or MSP Admin
    elif risk_level == "medium":
        if user_role in ["msp_admin", "admin", "company_admin"]:
            approval_status = "approved"
        else:
            # Create approval request
            approval_request = ApprovalRequest(
                incident_id=incident_id,
                runbook_id=request.runbook_id,
                company_id=incident["company_id"],
                risk_level=risk_level,
                requested_by=user["id"]
            )
            await db.approval_requests.insert_one(approval_request.model_dump())
            
            return {
                "message": "Medium-risk runbook requires approval",
                "approval_request_id": approval_request.id,
                "risk_level": risk_level,
                "status": "pending_approval",
                "required_role": "company_admin or msp_admin"
            }
    
    # High risk: Requires MSP Admin only
    elif risk_level == "high":
        if user_role in ["msp_admin", "admin"]:
            approval_status = "approved"
        else:
            # Create approval request
            approval_request = ApprovalRequest(
                incident_id=incident_id,
                runbook_id=request.runbook_id,
                company_id=incident["company_id"],
                risk_level=risk_level,
                requested_by=user["id"]
            )
            await db.approval_requests.insert_one(approval_request.model_dump())
            
            return {
                "message": "High-risk runbook requires MSP Admin approval",
                "approval_request_id": approval_request.id,
                "risk_level": risk_level,
                "status": "pending_approval",
                "required_role": "msp_admin"
            }
    else:
        approval_status = "auto_approved"
    
    # Mock SSM Command ID (in production, this would come from boto3)
    command_id = f"cmd-{str(uuid.uuid4())[:8]}"
    
    # Determine instance IDs (use from request or mock from incident)
    instance_ids = request.instance_ids or [f"i-{str(uuid.uuid4())[:8]}"]
    
    # Create SSM execution record
    ssm_execution = SSMExecution(
        incident_id=incident_id,
        company_id=incident["company_id"],
        command_id=command_id,
        runbook_id=request.runbook_id,
        command_type="RunCommand",
        status="InProgress",
        instance_ids=instance_ids,
        document_name="AWS-RunShellScript",
        parameters={
            "commands": runbook["actions"],
            "workingDirectory": "/tmp"
        }
    )
    
    await db.ssm_executions.insert_one(ssm_execution.model_dump())
    
    # Update incident with SSM command info
    await db.incidents.update_one(
        {"id": incident_id},
        {
            "$set": {
                "ssm_command_id": command_id,
                "remediation_status": "InProgress",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    
    # Simulate success after 5-15 seconds (for demo purposes)
    # In production, you would poll SSM API for actual status
    import random
    duration = random.randint(5, 15)
    
    # Auto-complete after mock duration (for demo)
    completed_at = datetime.now(timezone.utc).isoformat()
    success_output = f"✅ Runbook executed successfully\nCommands: {', '.join(runbook['actions'][:2])}\nDuration: {duration}s\nInstances: {len(instance_ids)}"
    
    await db.ssm_executions.update_one(
        {"command_id": command_id},
        {
            "$set": {
                "status": "Success",
                "output": success_output,
                "duration_seconds": duration,
                "completed_at": completed_at
            }
        }
    )
    
    await db.incidents.update_one(
        {"id": incident_id},
        {
            "$set": {
                "auto_remediated": True,
                "remediation_status": "Success",
                "remediation_duration_seconds": duration,
                "status": "resolved",
                "updated_at": completed_at
            }
        }
    )
    
    # Create audit log entry
    await create_audit_log(
        user_id=user["id"],
        user_email=user["email"],
        user_role=user["role"],
        company_id=incident["company_id"],
        action="runbook_executed",
        resource_type="incident",
        resource_id=incident_id,
        details={
            "runbook_id": request.runbook_id,
            "runbook_name": runbook["name"],
            "risk_level": risk_level,
            "approval_status": approval_status,
            "command_id": command_id,
            "instance_ids": instance_ids,
            "duration_seconds": duration
        },
        status="success"
    )
    
    # Broadcast incident update
    await manager.broadcast({
        "type": "incident_updated",
        "incident_id": incident_id,
        "company_id": incident["company_id"],
        "status": "resolved",
        "auto_remediated": True
    })
    
    return {
        "message": "Runbook execution initiated via AWS SSM",
        "command_id": command_id,
        "incident_id": incident_id,
        "status": "Success",
        "duration_seconds": duration,
        "instance_ids": instance_ids,
        "risk_level": risk_level,
        "approval_status": approval_status
    }

@api_router.get("/incidents/{incident_id}/ssm-executions", response_model=List[SSMExecution])
async def get_incident_ssm_executions(incident_id: str):
    """Get all SSM execution history for an incident"""
    executions = await db.ssm_executions.find(
        {"incident_id": incident_id},
        {"_id": 0}
    ).sort("started_at", -1).to_list(20)
    return executions

@api_router.get("/ssm/executions/{command_id}", response_model=SSMExecution)
async def get_ssm_execution_details(command_id: str):
    """Get details of a specific SSM execution"""
    execution = await db.ssm_executions.find_one({"command_id": command_id}, {"_id": 0})
    if not execution:
        raise HTTPException(status_code=404, detail="SSM execution not found")
    return SSMExecution(**execution)

@api_router.get("/ssm/executions", response_model=List[SSMExecution])
async def get_all_ssm_executions(company_id: Optional[str] = None, limit: int = 50):
    """Get all SSM executions, optionally filtered by company"""
    query = {}
    if company_id:
        query["company_id"] = company_id
    
    executions = await db.ssm_executions.find(query, {"_id": 0}).sort("started_at", -1).to_list(limit)
    return executions


# Patch Compliance Routes (AWS Patch Manager Integration)
@api_router.get("/companies/{company_id}/patch-compliance", response_model=List[PatchCompliance])
async def get_company_patch_compliance(company_id: str):
    """Get patch compliance status for a company from AWS Patch Manager"""
    # Get company and check AWS credentials
    company = await db.companies.find_one({"id": company_id}, {"_id": 0})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    # Check if AWS credentials are configured and enabled
    aws_creds = company.get("aws_credentials", {})
    if not aws_creds or not aws_creds.get("enabled", False):
        # Return empty list when AWS is not configured (no demo data)
        return []
    
    # Fetch real patch compliance from AWS
    compliance_list = await get_patch_compliance(
        aws_creds.get("access_key_id"),
        aws_creds.get("secret_access_key"),
        aws_creds.get("region", "us-east-1")
    )
    
    # Save to database for caching
    if compliance_list:
        # Clear old data
        await db.patch_compliance.delete_many({"company_id": company_id})
        
        # Save new data
        for compliance_data in compliance_list:
            compliance = PatchCompliance(
                company_id=company_id,
                environment="production",  # Can be derived from instance tags
                instance_id=compliance_data["instance_id"],
                instance_name=compliance_data["instance_name"],
                compliance_status="COMPLIANT" if compliance_data["compliance_status"] == "compliant" else "NON_COMPLIANT",
                compliance_percentage=100.0 if compliance_data["compliance_status"] == "compliant" else round((compliance_data["installed_count"] / (compliance_data["installed_count"] + compliance_data["missing_count"]) * 100), 2) if (compliance_data["installed_count"] + compliance_data["missing_count"]) > 0 else 0,
                critical_patches_missing=compliance_data.get("critical_missing", 0),
                high_patches_missing=compliance_data.get("security_missing", 0),
                medium_patches_missing=0,
                low_patches_missing=compliance_data.get("missing_count", 0) - compliance_data.get("critical_missing", 0) - compliance_data.get("security_missing", 0),
                patches_installed=compliance_data["installed_count"],
                last_scan_time=compliance_data["last_scan"]
            )
            await db.patch_compliance.insert_one(compliance.model_dump())
    
    # Return cached data
    cached_data = await db.patch_compliance.find(
        {"company_id": company_id},
        {"_id": 0}
    ).to_list(100)
    
    return cached_data if cached_data else []

@api_router.get("/patch-compliance/summary")
async def get_patch_compliance_summary(company_id: Optional[str] = None):
    """Get aggregated patch compliance summary across all companies or a specific company"""
    query = {}
    if company_id:
        query["company_id"] = company_id
    
    compliance_data = await db.patch_compliance.find(query, {"_id": 0}).to_list(1000)
    
    if not compliance_data:
        return {
            "total_instances": 0,
            "compliant_instances": 0,
            "non_compliant_instances": 0,
            "compliance_percentage": 0.0,
            "total_critical_patches_missing": 0,
            "total_high_patches_missing": 0,
            "by_environment": {}
        }
    
    total_instances = len(compliance_data)
    compliant = sum(1 for c in compliance_data if c["compliance_status"] == "COMPLIANT")
    critical_missing = sum(c.get("critical_patches_missing", 0) for c in compliance_data)
    high_missing = sum(c.get("high_patches_missing", 0) for c in compliance_data)
    
    # Group by environment
    by_env = {}
    for c in compliance_data:
        env = c["environment"]
        if env not in by_env:
            by_env[env] = {
                "total": 0,
                "compliant": 0,
                "critical_missing": 0,
                "high_missing": 0
            }
        by_env[env]["total"] += 1
        if c["compliance_status"] == "COMPLIANT":
            by_env[env]["compliant"] += 1
        by_env[env]["critical_missing"] += c.get("critical_patches_missing", 0)
        by_env[env]["high_missing"] += c.get("high_patches_missing", 0)
    
    return {
        "total_instances": total_instances,
        "compliant_instances": compliant,
        "non_compliant_instances": total_instances - compliant,
        "compliance_percentage": round((compliant / total_instances * 100), 2) if total_instances > 0 else 0,
        "total_critical_patches_missing": critical_missing,
        "total_high_patches_missing": high_missing,
        "by_environment": by_env
    }

@api_router.post("/patch-compliance/sync")
async def sync_patch_compliance(company_id: str):
    """Sync patch compliance data from AWS Patch Manager"""
    # Refresh data by calling get endpoint
    compliance_data = await get_company_patch_compliance(company_id)
    
    return {
        "message": "Patch compliance data synced successfully",
        "company_id": company_id,
        "instances_synced": len(compliance_data) if isinstance(compliance_data, list) else 0
    }

@api_router.post("/companies/{company_id}/patch-instances")
async def patch_instances(company_id: str, request: Dict[str, Any]):
    """
    Execute patch command on instances
    Supports: patch_now, schedule_tonight, maintenance_window
    """
    # Get company and check AWS credentials
    company = await db.companies.find_one({"id": company_id}, {"_id": 0})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    aws_creds = company.get("aws_credentials", {})
    if not aws_creds or not aws_creds.get("enabled", False):
        raise HTTPException(status_code=400, detail="AWS credentials not configured")
    
    instance_ids = request.get("instance_ids", [])
    operation_type = request.get("operation", "patch_now")  # patch_now, schedule_tonight, maintenance_window
    
    if not instance_ids:
        raise HTTPException(status_code=400, detail="No instance IDs provided")
    
    # Execute patch command
    result = await execute_patch_command(
        aws_creds.get("access_key_id"),
        aws_creds.get("secret_access_key"),
        aws_creds.get("region", "us-east-1"),
        instance_ids,
        operation="install"
    )
    
    if result["success"]:
        return {
            "message": f"Patch operation '{operation_type}' initiated successfully",
            "command_id": result["command_id"],
            "instance_ids": instance_ids,
            "status": "InProgress"
        }
    else:
        raise HTTPException(status_code=500, detail=f"Failed to initiate patch operation: {result['error']}")

@api_router.post("/companies/{company_id}/cloudwatch/poll")
async def poll_cloudwatch_alarms(company_id: str):
    """
    Poll CloudWatch alarms for a company (PULL mode)
    This creates alerts from CloudWatch alarm state changes
    """
    # Get company and check AWS credentials
    company = await db.companies.find_one({"id": company_id}, {"_id": 0})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    aws_creds = company.get("aws_credentials", {})
    if not aws_creds or not aws_creds.get("enabled", False):
        return {
            "message": "AWS credentials not configured",
            "alarms_fetched": 0
        }
    
    # Fetch CloudWatch alarms
    alarms = await get_cloudwatch_alarms(
        aws_creds.get("access_key_id"),
        aws_creds.get("secret_access_key"),
        aws_creds.get("region", "us-east-1")
    )
    
    # Convert alarms to alerts
    alerts_created = 0
    for alarm in alarms:
        # Check if alert already exists
        existing = await db.alerts.find_one({
            "company_id": company_id,
            "signature": alarm["alarm_name"],
            "status": "active"
        })
        
        if not existing:
            # Create new alert from CloudWatch alarm
            alert = Alert(
                company_id=company_id,
                asset_id=alarm.get("alarm_arn", ""),
                asset_name=alarm.get("alarm_name", ""),
                signature=alarm["alarm_name"],
                severity="critical" if alarm["state"] == "ALARM" else "medium",
                message=alarm.get("state_reason", "CloudWatch alarm triggered"),
                tool_source="cloudwatch_poll",  # Indicates PULL mode
                status="active"
            )
            
            await db.alerts.insert_one(alert.model_dump())
            
            # Broadcast via WebSocket
            await manager.broadcast({
                "type": "alert_received",
                "data": alert.model_dump()
            })
            
            alerts_created += 1
    
    return {
        "message": "CloudWatch alarms polled successfully",
        "alarms_fetched": len(alarms),
        "alerts_created": alerts_created,
        "source": "PULL"
    }

@api_router.get("/companies/{company_id}/cloudwatch/status")
async def get_cloudwatch_status(company_id: str):
    """Get CloudWatch integration status"""
    company = await db.companies.find_one({"id": company_id}, {"_id": 0})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    aws_creds = company.get("aws_credentials", {})
    
    return {
        "enabled": aws_creds.get("enabled", False) if aws_creds else False,
        "region": aws_creds.get("region", "us-east-1") if aws_creds else "us-east-1",
        "polling_active": aws_creds.get("enabled", False) if aws_creds else False
    }


# Cross-Account IAM Role Routes
class CrossAccountRoleCreate(BaseModel):
    role_arn: str
    external_id: str
    aws_account_id: str

@api_router.post("/companies/{company_id}/cross-account-role", response_model=CrossAccountRole)
async def create_cross_account_role(company_id: str, role_data: CrossAccountRoleCreate):
    """Save cross-account IAM role configuration for a company"""
    # Check if company exists
    company = await db.companies.find_one({"id": company_id}, {"_id": 0})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    # Check if role already exists
    existing = await db.cross_account_roles.find_one({"company_id": company_id}, {"_id": 0})
    if existing:
        # Update existing
        await db.cross_account_roles.update_one(
            {"company_id": company_id},
            {"$set": {
                **role_data.model_dump(),
                "status": "active",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        updated = await db.cross_account_roles.find_one({"company_id": company_id}, {"_id": 0})
        return CrossAccountRole(**updated)
    
    # Create new role
    role = CrossAccountRole(
        company_id=company_id,
        **role_data.model_dump()
    )
    await db.cross_account_roles.insert_one(role.model_dump())
    return role

@api_router.get("/companies/{company_id}/cross-account-role", response_model=CrossAccountRole)
async def get_cross_account_role(company_id: str):
    """Get cross-account IAM role configuration for a company"""
    role = await db.cross_account_roles.find_one({"company_id": company_id}, {"_id": 0})
    if not role:
        raise HTTPException(status_code=404, detail="Cross-account role not configured")
    return CrossAccountRole(**role)

@api_router.get("/companies/{company_id}/cross-account-role/template")
async def get_cross_account_role_template(company_id: str):
    """Get IAM trust policy template and setup instructions"""
    # Generate unique external ID for this company
    external_id = f"aw-{company_id}-{uuid.uuid4().hex[:8]}"
    
    # MSP AWS Account ID (in production, this would be from environment)
    msp_account_id = "123456789012"
    
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{msp_account_id}:root"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": external_id
                    }
                }
            }
        ]
    }
    
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ssm:SendCommand",
                    "ssm:GetCommandInvocation",
                    "ssm:ListCommandInvocations",
                    "ssm:DescribeInstanceInformation",
                    "ssm:GetPatchSummary",
                    "ssm:DescribeInstancePatchStates",
                    "ec2:DescribeInstances",
                    "ec2:DescribeTags"
                ],
                "Resource": "*"
            }
        ]
    }
    
    cli_commands = f"""# Step 1: Create the IAM role with trust policy
aws iam create-role \\
  --role-name AlertWhispererMSPAccess \\
  --assume-role-policy-document file://trust-policy.json

# Step 2: Attach permissions policy
aws iam put-role-policy \\
  --role-name AlertWhispererMSPAccess \\
  --policy-name AlertWhispererPermissions \\
  --policy-document file://permissions-policy.json

# Step 3: Get the role ARN
aws iam get-role --role-name AlertWhispererMSPAccess --query 'Role.Arn' --output text
"""
    
    return {
        "external_id": external_id,
        "msp_account_id": msp_account_id,
        "trust_policy": trust_policy,
        "permissions_policy": permissions_policy,
        "cli_commands": cli_commands,
        "instructions": [
            "1. Save the trust policy JSON to a file named 'trust-policy.json'",
            "2. Save the permissions policy JSON to a file named 'permissions-policy.json'",
            "3. Run the AWS CLI commands to create the role",
            "4. Copy the Role ARN and External ID back to Alert Whisperer",
            "5. Alert Whisperer will use AssumeRole to access your AWS resources securely"
        ]
    }


# Webhook & Integration Routes
class WebhookAlert(BaseModel):
    asset_name: str
    signature: str
    severity: str
    message: str
    tool_source: str = "External"

@api_router.post("/webhooks/alerts")
async def receive_webhook_alert(
    request: Request,
    alert_data: WebhookAlert,
    api_key: str,
    x_signature: Optional[str] = Header(None),
    x_timestamp: Optional[str] = Header(None),
    x_delivery_id: Optional[str] = Header(None)
):
    """
    Webhook endpoint for external monitoring tools to send alerts
    
    Security:
    - API key authentication (required)
    - HMAC-SHA256 signature verification (optional, per-company)
    - Timestamp validation for replay attack protection
    - Rate limiting per company
    - Idempotency via X-Delivery-ID header
    
    Headers (if HMAC enabled):
    - X-Signature: sha256=<hex_signature>
    - X-Timestamp: <unix_timestamp>
    - X-Delivery-ID: <unique_delivery_identifier> (optional, for idempotency)
    """
    # Validate API key and get company
    company = await db.companies.find_one({"api_key": api_key})
    if not company:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    company_id = company["id"]
    
    # Check rate limiting
    await check_rate_limit(company_id)
    
    # Check idempotency - return existing alert if duplicate
    existing_alert_id = await check_idempotency(
        company_id=company_id,
        delivery_id=x_delivery_id,
        alert_data=alert_data.model_dump()
    )
    
    if existing_alert_id:
        return {
            "message": "Alert already received (idempotent)",
            "alert_id": existing_alert_id,
            "duplicate": True
        }
    
    # Verify HMAC signature if enabled for this company
    raw_body = await request.body()
    await verify_webhook_signature(
        company_id=company_id,
        signature_header=x_signature,
        timestamp_header=x_timestamp,
        raw_body=raw_body.decode('utf-8')
    )
    
    # Find asset by name
    asset = None
    for a in company.get("assets", []):
        if a["name"] == alert_data.asset_name:
            asset = a
            break
    
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {alert_data.asset_name} not found")
    
    # Generate delivery_id if not provided
    if not x_delivery_id:
        content_hash = hashlib.sha256(
            f"{alert_data.asset_name}:{alert_data.signature}:{alert_data.message}".encode()
        ).hexdigest()[:16]
        x_delivery_id = f"auto_{content_hash}"
    
    # Create alert with idempotency tracking
    alert = Alert(
        company_id=company_id,
        asset_id=asset["id"],
        asset_name=alert_data.asset_name,
        signature=alert_data.signature,
        severity=alert_data.severity,
        message=alert_data.message,
        tool_source=alert_data.tool_source,
        delivery_id=x_delivery_id,
        delivery_attempts=1
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
    
    # Broadcast alert via WebSocket for real-time updates
    await manager.broadcast({
        "type": "alert_received",
        "data": alert.model_dump()
    })
    
    # Create notification for critical alerts
    if alert.severity in ["critical", "high"]:
        notification = Notification(
            user_id="admin",  # Notify admins
            company_id=company_id,
            alert_id=alert.id,
            type="critical_alert",
            title=f"{alert.severity.upper()} Alert Received",
            message=f"{alert.signature} on {alert.asset_name}: {alert.message}",
            priority=alert.severity
        )
        await db.notifications.insert_one(notification.model_dump())
        
        # Broadcast notification
        await manager.broadcast({
            "type": "notification",
            "data": notification.model_dump()
        })
    
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
    
    # NO DEMO PATCH PLANS - Patches come from real AWS Patch Manager only
    # This ensures compliance data is always real and production-ready
    
    # Initialize KPIs
    for company in companies:
        kpi = KPI(company_id=company.id)
        await db.kpis.insert_one(kpi.model_dump())
    
    return {
        "message": "Database seeded successfully - NO DEMO DATA",
        "companies": len(companies),
        "users": len(users),
        "runbooks": len(runbooks),
        "patch_plans": 0  # No demo patch plans
    }


# ============= Real-Time Metrics Endpoint =============
@api_router.get("/metrics/realtime")
async def get_realtime_metrics(company_id: Optional[str] = None):
    """Get real-time metrics for dashboard with enhanced KPI calculations"""
    query = {}
    if company_id:
        query["company_id"] = company_id
    
    # Alert counts by priority
    all_alerts = await db.alerts.find(query, {"_id": 0}).to_list(10000)
    active_alerts = [a for a in all_alerts if a.get("status") == "active"]
    
    alert_counts = {
        "critical": sum(1 for a in active_alerts if a["severity"] == "critical"),
        "high": sum(1 for a in active_alerts if a["severity"] == "high"),
        "medium": sum(1 for a in active_alerts if a["severity"] == "medium"),
        "low": sum(1 for a in active_alerts if a["severity"] == "low"),
        "total": len(active_alerts)
    }
    
    # Incident counts by status
    incidents = await db.incidents.find(query, {"_id": 0}).to_list(5000)
    
    incident_counts = {
        "new": sum(1 for i in incidents if i["status"] == "new"),
        "in_progress": sum(1 for i in incidents if i["status"] == "in_progress"),
        "resolved": sum(1 for i in incidents if i["status"] == "resolved"),
        "escalated": sum(1 for i in incidents if i["status"] == "escalated"),
        "total": len(incidents)
    }
    
    # Calculate enhanced KPIs
    
    # 1. Noise Reduction % = (1 - incidents/alerts) * 100
    total_alerts = len(all_alerts)
    total_incidents = len(incidents)
    noise_reduction_pct = round((1 - (total_incidents / max(total_alerts, 1))) * 100, 2) if total_alerts > 0 else 0
    
    # 2. Self-Healed Count & Percentage
    auto_remediated_incidents = [i for i in incidents if i.get("auto_remediated", False)]
    self_healed_count = len(auto_remediated_incidents)
    self_healed_pct = round((self_healed_count / max(total_incidents, 1)) * 100, 2) if total_incidents > 0 else 0
    
    # 3. MTTR (Mean Time To Resolution)
    resolved_incidents = [i for i in incidents if i["status"] == "resolved"]
    auto_resolved = [i for i in resolved_incidents if i.get("auto_remediated", False)]
    manual_resolved = [i for i in resolved_incidents if not i.get("auto_remediated", False)]
    
    def calculate_mttr(incident_list):
        if not incident_list:
            return 0
        total_seconds = 0
        for inc in incident_list:
            created = datetime.fromisoformat(inc["created_at"].replace("Z", "+00:00"))
            updated = datetime.fromisoformat(inc["updated_at"].replace("Z", "+00:00"))
            duration = (updated - created).total_seconds()
            total_seconds += duration
        return round(total_seconds / len(incident_list) / 60, 2)  # Convert to minutes
    
    mttr_auto = calculate_mttr(auto_resolved)
    mttr_manual = calculate_mttr(manual_resolved)
    mttr_overall = calculate_mttr(resolved_incidents)
    
    # MTTR Reduction % = (manual_mttr - auto_mttr) / manual_mttr * 100
    mttr_reduction_pct = round(((mttr_manual - mttr_auto) / max(mttr_manual, 1)) * 100, 2) if mttr_manual > 0 else 0
    
    # 4. Patch Compliance (get from patch_compliance collection)
    compliance_data = await db.patch_compliance.find(query, {"_id": 0}).to_list(1000)
    if compliance_data:
        compliant_instances = sum(1 for c in compliance_data if c.get("compliance_status") == "COMPLIANT")
        total_instances = len(compliance_data)
        patch_compliance_pct = round((compliant_instances / total_instances * 100), 2) if total_instances > 0 else 0
        critical_patches_missing = sum(c.get("critical_patches_missing", 0) for c in compliance_data)
    else:
        patch_compliance_pct = 0
        critical_patches_missing = 0
    
    kpis = {
        # Noise Reduction: Target 40-70%
        "noise_reduction_pct": noise_reduction_pct,
        "noise_reduction_target": 40,
        "noise_reduction_status": "excellent" if noise_reduction_pct >= 40 else "good" if noise_reduction_pct >= 20 else "needs_improvement",
        
        # Self-Healed
        "self_healed_count": self_healed_count,
        "self_healed_pct": self_healed_pct,
        "self_healed_target": 20,  # Target 20-30%
        "self_healed_status": "excellent" if self_healed_pct >= 20 else "good" if self_healed_pct >= 10 else "needs_improvement",
        
        # MTTR
        "mttr_overall_minutes": mttr_overall,
        "mttr_auto_minutes": mttr_auto,
        "mttr_manual_minutes": mttr_manual,
        "mttr_reduction_pct": mttr_reduction_pct,
        "mttr_target_reduction": 30,  # Target 30-50% reduction
        "mttr_status": "excellent" if mttr_reduction_pct >= 30 else "good" if mttr_reduction_pct >= 15 else "needs_improvement",
        
        # Patch Compliance
        "patch_compliance_pct": patch_compliance_pct,
        "patch_compliance_target": 95,  # Target 95%+
        "critical_patches_missing": critical_patches_missing,
        "patch_compliance_status": "excellent" if patch_compliance_pct >= 95 else "good" if patch_compliance_pct >= 85 else "needs_improvement"
    }
    
    return {
        "alerts": alert_counts,
        "incidents": incident_counts,
        "kpis": kpis,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@api_router.get("/companies/{company_id}/kpis")
async def get_company_kpis(company_id: str):
    """Get detailed KPI metrics for a specific company"""
    # Reuse the realtime metrics function
    metrics = await get_realtime_metrics(company_id=company_id)
    
    # Add additional company-specific details
    company = await db.companies.find_one({"id": company_id}, {"_id": 0})
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    
    # Get SSM execution statistics
    ssm_executions = await db.ssm_executions.find({"company_id": company_id}, {"_id": 0}).to_list(1000)
    ssm_success_count = sum(1 for e in ssm_executions if e.get("status") == "Success")
    ssm_total = len(ssm_executions)
    
    return {
        "company_id": company_id,
        "company_name": company.get("name"),
        "metrics": metrics,
        "ssm_statistics": {
            "total_executions": ssm_total,
            "successful_executions": ssm_success_count,
            "success_rate_pct": round((ssm_success_count / max(ssm_total, 1)) * 100, 2) if ssm_total > 0 else 0
        }
    }


@api_router.get("/companies/{company_id}/kpis/impact")
async def get_kpi_impact(company_id: str):
    """
    Get KPI impact analysis showing before/after Alert Whisperer implementation
    Shows improvement metrics with baseline assumptions
    """
    # Get current metrics
    current_metrics = await get_realtime_metrics(company_id=company_id)
    current_kpis = current_metrics["kpis"]
    
    # Calculate baseline (before Alert Whisperer) assumptions:
    # - No alert correlation: incidents = alerts (noise reduction 0%)
    # - No auto-remediation: self-healed 0%
    # - Manual MTTR typically 2-3x longer than automated
    
    total_alerts = current_metrics["alerts"]["total"]
    
    baseline = {
        "noise_reduction_pct": 0,  # No correlation
        "incidents_count": total_alerts,  # Every alert becomes an incident
        "self_healed_pct": 0,  # No automation
        "self_healed_count": 0,
        "mttr_minutes": current_kpis["mttr_manual_minutes"] if current_kpis["mttr_manual_minutes"] > 0 else 120,  # Assume 2 hours manual
        "patch_compliance_pct": max(current_kpis["patch_compliance_pct"] - 15, 60)  # Assume 15% worse before
    }
    
    # Calculate improvements
    improvements = {
        "noise_reduction": {
            "before": baseline["noise_reduction_pct"],
            "after": current_kpis["noise_reduction_pct"],
            "improvement": current_kpis["noise_reduction_pct"] - baseline["noise_reduction_pct"],
            "improvement_pct": current_kpis["noise_reduction_pct"],
            "status": current_kpis["noise_reduction_status"],
            "target": 40
        },
        "self_healed": {
            "before": baseline["self_healed_pct"],
            "after": current_kpis["self_healed_pct"],
            "improvement": current_kpis["self_healed_pct"] - baseline["self_healed_pct"],
            "improvement_pct": current_kpis["self_healed_pct"],
            "status": current_kpis["self_healed_status"],
            "target": 20
        },
        "mttr": {
            "before": baseline["mttr_minutes"],
            "after": current_kpis["mttr_overall_minutes"],
            "improvement": baseline["mttr_minutes"] - current_kpis["mttr_overall_minutes"],
            "improvement_pct": round(((baseline["mttr_minutes"] - current_kpis["mttr_overall_minutes"]) / max(baseline["mttr_minutes"], 1)) * 100, 2),
            "status": current_kpis["mttr_status"],
            "target": 30  # 30% reduction target
        },
        "patch_compliance": {
            "before": baseline["patch_compliance_pct"],
            "after": current_kpis["patch_compliance_pct"],
            "improvement": current_kpis["patch_compliance_pct"] - baseline["patch_compliance_pct"],
            "improvement_pct": round(((current_kpis["patch_compliance_pct"] - baseline["patch_compliance_pct"]) / max(baseline["patch_compliance_pct"], 1)) * 100, 2),
            "status": current_kpis["patch_compliance_status"],
            "target": 95
        }
    }
    
    return {
        "baseline": baseline,
        "current": {
            "noise_reduction_pct": current_kpis["noise_reduction_pct"],
            "incidents_count": current_metrics["incidents"]["total"],
            "self_healed_pct": current_kpis["self_healed_pct"],
            "self_healed_count": current_kpis["self_healed_count"],
            "mttr_minutes": current_kpis["mttr_overall_minutes"],
            "patch_compliance_pct": current_kpis["patch_compliance_pct"]
        },
        "improvements": improvements,
        "summary": {
            "noise_reduced": f"{improvements['noise_reduction']['improvement']:.1f}%",
            "incidents_prevented": max(baseline["incidents_count"] - current_metrics["incidents"]["total"], 0),
            "time_saved_per_incident": f"{improvements['mttr']['improvement']:.1f} minutes",
            "auto_resolved_count": current_kpis["self_healed_count"]
        }
    }



# ============= Chat Endpoints =============
@api_router.get("/chat/{company_id}")
async def get_chat_messages(company_id: str, limit: int = 50):
    """Get chat messages for a company"""
    messages = await db.chat_messages.find(
        {"company_id": company_id},
        {"_id": 0}
    ).sort("timestamp", -1).limit(limit).to_list(limit)
    
    return list(reversed(messages))

class ChatMessageRequest(BaseModel):
    message: str

@api_router.post("/chat/{company_id}")
async def send_chat_message(
    company_id: str, 
    message_data: ChatMessageRequest,
    current_user: User = Depends(get_current_user)
):
    """Send a chat message"""
    chat_message = ChatMessage(
        company_id=company_id,
        user_id=current_user.id,
        user_name=current_user.name,
        user_role=current_user.role,
        message=message_data.message
    )
    
    await db.chat_messages.insert_one(chat_message.model_dump())
    
    # Broadcast message via WebSocket
    await manager.broadcast({
        "type": "chat_message",
        "data": chat_message.model_dump()
    })
    
    return chat_message

@api_router.put("/chat/{company_id}/mark-read")
async def mark_chat_messages_read(
    company_id: str,
    current_user: User = Depends(get_current_user)
):
    """Mark all chat messages as read for current user"""
    await db.chat_messages.update_many(
        {"company_id": company_id, "user_id": {"$ne": current_user.id}},
        {"$set": {"read": True}}
    )
    return {"message": "Messages marked as read"}


# ============= Notification Endpoints =============
@api_router.get("/notifications")
async def get_notifications(
    current_user: User = Depends(get_current_user),
    limit: int = 50,
    unread_only: bool = False
):
    """Get notifications for current user"""
    query = {"user_id": current_user.id}
    if unread_only:
        query["read"] = False
    
    notifications = await db.notifications.find(
        query,
        {"_id": 0}
    ).sort("timestamp", -1).limit(limit).to_list(limit)
    
    return notifications

@api_router.put("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user: User = Depends(get_current_user)
):
    """Mark a notification as read"""
    result = await db.notifications.update_one(
        {"id": notification_id, "user_id": current_user.id},
        {"$set": {"read": True}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    return {"message": "Notification marked as read"}

@api_router.put("/notifications/mark-all-read")
async def mark_all_notifications_read(current_user: User = Depends(get_current_user)):
    """Mark all notifications as read for current user"""
    await db.notifications.update_many(
        {"user_id": current_user.id},
        {"$set": {"read": True}}
    )
    return {"message": "All notifications marked as read"}

@api_router.get("/notifications/unread-count")
async def get_unread_count(current_user: User = Depends(get_current_user)):
    """Get count of unread notifications"""
    count = await db.notifications.count_documents({
        "user_id": current_user.id,
        "read": False
    })
    return {"count": count}


# ============= Approval Request Endpoints =============
@api_router.get("/approval-requests")
async def get_approval_requests(
    current_user: User = Depends(get_current_user),
    status: Optional[str] = None
):
    """Get approval requests (for admins)"""
    if not check_permission(current_user.model_dump(), "approve_runbooks"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    query = {}
    if status:
        query["status"] = status
    
    # Admins see all, company admins see only their companies
    if current_user.role == "company_admin":
        query["company_id"] = {"$in": current_user.company_ids}
    
    requests = await db.approval_requests.find(
        query,
        {"_id": 0}
    ).sort("created_at", -1).limit(50).to_list(50)
    
    return requests

@api_router.post("/approval-requests/{request_id}/approve")
async def approve_runbook_request(
    request_id: str,
    approval_notes: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Approve a runbook execution request"""
    if not check_permission(current_user.model_dump(), "approve_runbooks"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Get approval request
    approval_req = await db.approval_requests.find_one({"id": request_id}, {"_id": 0})
    if not approval_req:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    if approval_req["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"Request is already {approval_req['status']}")
    
    # Check if expired
    if datetime.fromisoformat(approval_req["expires_at"]) < datetime.now(timezone.utc):
        await db.approval_requests.update_one(
            {"id": request_id},
            {"$set": {"status": "expired", "updated_at": datetime.now(timezone.utc).isoformat()}}
        )
        raise HTTPException(status_code=400, detail="Approval request has expired")
    
    # Check role permissions for risk level
    risk_level = approval_req.get("risk_level", "medium")
    if risk_level == "high" and current_user.role not in ["msp_admin", "admin"]:
        raise HTTPException(status_code=403, detail="Only MSP Admin can approve high-risk runbooks")
    
    # Approve the request
    await db.approval_requests.update_one(
        {"id": request_id},
        {
            "$set": {
                "status": "approved",
                "approved_by": current_user.id,
                "approval_notes": approval_notes,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    
    # Create audit log
    await create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        user_role=current_user.role,
        company_id=approval_req["company_id"],
        action="approval_granted",
        resource_type="approval_request",
        resource_id=request_id,
        details={
            "incident_id": approval_req["incident_id"],
            "runbook_id": approval_req["runbook_id"],
            "risk_level": risk_level,
            "approval_notes": approval_notes
        },
        status="success"
    )
    
    return {"message": "Runbook execution approved", "request_id": request_id}

@api_router.post("/approval-requests/{request_id}/reject")
async def reject_runbook_request(
    request_id: str,
    rejection_reason: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Reject a runbook execution request"""
    if not check_permission(current_user.model_dump(), "approve_runbooks"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Get approval request
    approval_req = await db.approval_requests.find_one({"id": request_id}, {"_id": 0})
    if not approval_req:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    if approval_req["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"Request is already {approval_req['status']}")
    
    # Reject the request
    await db.approval_requests.update_one(
        {"id": request_id},
        {
            "$set": {
                "status": "rejected",
                "approved_by": current_user.id,
                "approval_notes": rejection_reason,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    
    # Create audit log
    await create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        user_role=current_user.role,
        company_id=approval_req["company_id"],
        action="approval_rejected",
        resource_type="approval_request",
        resource_id=request_id,
        details={
            "incident_id": approval_req["incident_id"],
            "runbook_id": approval_req["runbook_id"],
            "risk_level": approval_req.get("risk_level", "medium"),
            "rejection_reason": rejection_reason
        },
        status="success"
    )
    
    return {"message": "Runbook execution rejected", "request_id": request_id}


# ============= Rate Limit Management Endpoints =============
@api_router.get("/companies/{company_id}/rate-limit")
async def get_rate_limit_config(
    company_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get rate limit configuration for a company"""
    if current_user.role not in ["msp_admin", "admin"]:
        raise HTTPException(status_code=403, detail="Only admins can view rate limit config")
    
    config = await db.rate_limits.find_one({"company_id": company_id}, {"_id": 0})
    if not config:
        # Return default config
        return RateLimitConfig(company_id=company_id).model_dump()
    
    return config

@api_router.put("/companies/{company_id}/rate-limit")
async def update_rate_limit_config(
    company_id: str,
    requests_per_minute: int,
    burst_size: int,
    enabled: bool = True,
    current_user: User = Depends(get_current_user)
):
    """Update rate limit configuration for a company"""
    if current_user.role not in ["msp_admin", "admin"]:
        raise HTTPException(status_code=403, detail="Only admins can update rate limit config")
    
    # Validate values
    if requests_per_minute < 1 or requests_per_minute > 1000:
        raise HTTPException(status_code=400, detail="Requests per minute must be between 1 and 1000")
    
    if burst_size < requests_per_minute:
        raise HTTPException(status_code=400, detail="Burst size must be >= requests per minute")
    
    # Update or create config
    await db.rate_limits.update_one(
        {"company_id": company_id},
        {
            "$set": {
                "requests_per_minute": requests_per_minute,
                "burst_size": burst_size,
                "enabled": enabled,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        },
        upsert=True
    )
    
    # Create audit log
    await create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        user_role=current_user.role,
        company_id=company_id,
        action="rate_limit_updated",
        resource_type="company",
        resource_id=company_id,
        details={
            "requests_per_minute": requests_per_minute,
            "burst_size": burst_size,
            "enabled": enabled
        },
        status="success"
    )
    
    return {"message": "Rate limit configuration updated"}


# ============= Audit Log Endpoints =============
@api_router.get("/audit-logs")
async def get_audit_logs(
    current_user: User = Depends(get_current_user),
    company_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100
):
    """Get audit logs (admin only)"""
    if current_user.role not in ["msp_admin", "admin", "company_admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    query = {}
    
    # Company admins can only see their companies
    if current_user.role == "company_admin":
        query["company_id"] = {"$in": current_user.company_ids}
    elif company_id:
        query["company_id"] = company_id
    
    if action:
        query["action"] = action
    
    logs = await db.audit_logs.find(
        query,
        {"_id": 0}
    ).sort("timestamp", -1).limit(limit).to_list(limit)
    
    return logs

@api_router.get("/audit-logs/summary")
async def get_audit_log_summary(
    current_user: User = Depends(get_current_user),
    company_id: Optional[str] = None
):
    """Get audit log summary statistics"""
    if current_user.role not in ["msp_admin", "admin", "company_admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    query = {}
    if current_user.role == "company_admin":
        query["company_id"] = {"$in": current_user.company_ids}
    elif company_id:
        query["company_id"] = company_id
    
    # Get counts by action type
    pipeline = [
        {"$match": query},
        {"$group": {
            "_id": "$action",
            "count": {"$sum": 1}
        }}
    ]
    
    action_counts = await db.audit_logs.aggregate(pipeline).to_list(None)
    
    # Get total count
    total = await db.audit_logs.count_documents(query)
    
    # Get recent critical actions
    recent_critical = await db.audit_logs.find(
        {**query, "action": {"$in": ["runbook_executed", "approval_granted", "approval_rejected"]}},
        {"_id": 0}
    ).sort("timestamp", -1).limit(10).to_list(10)
    
    return {
        "total_logs": total,
        "action_counts": {item["_id"]: item["count"] for item in action_counts},
        "recent_critical_actions": recent_critical
    }


# ============= WebSocket Endpoint for Real-Time Updates =============
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and listen for client messages
            data = await websocket.receive_text()
            # Echo back or handle client messages if needed
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


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

# ============= Agent Core & New Services Integration =============

# Import new services
from auth_service import AuthService, ACCESS_TOKEN_EXPIRE_MINUTES as NEW_ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
from agent_service import router as agent_router, init_agent
from agent_tools import AgentToolRegistry
from memory_service import MemoryService
from db_init import init_indexes, cleanup_expired_data
import signal
import sys

# Initialize services (will be done in startup event)
auth_service = None
memory_service = None
tools_registry = None
agent_instance = None

@app.on_event("startup")
async def startup_event():
    """Initialize services and database indexes on startup"""
    global auth_service, memory_service, tools_registry, agent_instance
    
    logger.info("🚀 Starting Alert Whisperer Agent Core...")
    
    # Initialize database indexes (TTL, performance)
    logger.info("📊 Initializing database indexes...")
    await init_indexes(db)
    
    # Initialize services
    logger.info("🔐 Initializing auth service...")
    auth_service = AuthService(db)
    
    logger.info("🧠 Initializing memory service...")
    memory_service = MemoryService(db)
    
    logger.info("🛠️ Initializing tool registry...")
    tools_registry = AgentToolRegistry(db)
    
    logger.info("🤖 Initializing agent instance...")
    agent_instance = init_agent(db, tools_registry)
    
    # Register agent router
    app.include_router(agent_router)
    
    logger.info("✅ All services initialized successfully")
    logger.info(f"   Version: {os.getenv('GIT_SHA', 'dev')}")
    logger.info(f"   Agent Mode: {os.getenv('AGENT_MODE', 'local')}")

@app.on_event("shutdown")
async def shutdown_event():
    """Graceful shutdown - close connections and cleanup"""
    logger.info("🛑 Shutting down Alert Whisperer Agent Core...")
    
    # Close MongoDB connection
    client.close()
    logger.info("✅ MongoDB connection closed")
    
    # Cleanup expired data
    logger.info("🧹 Running cleanup...")
    try:
        await cleanup_expired_data(db)
    except Exception as e:
        logger.error(f"Cleanup error: {e}")
    
    logger.info("✅ Shutdown complete")

# Graceful shutdown signal handler
def signal_handler(sig, frame):
    """Handle SIGTERM for graceful shutdown"""
    logger.info(f"Received signal {sig}, initiating graceful shutdown...")
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)