"""Enhanced MSP Models for Complete MSP Platform
Includes runbook library, execution tracking, auto-assignment, escalation, and more
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid


# ============= Enhanced Runbook Models =============

class EnhancedRunbook(BaseModel):
    """Enhanced runbook with cloud execution support"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    category: str  # disk, memory, cpu, network, application, database, security
    script_content: str  # Actual script to execute
    script_type: str  # bash, powershell, python
    cloud_provider: str  # aws, azure, gcp, multi
    risk_level: str  # low, medium, high
    auto_approve: bool = False
    parameters: List[Dict[str, Any]] = []  # {name, type, default, required, description}
    tags: List[str] = []
    company_id: Optional[str] = None  # None for global runbooks
    is_global: bool = True  # Global runbooks available to all companies
    created_by: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    execution_count: int = 0
    success_rate: float = 0.0


class RunbookExecution(BaseModel):
    """Runbook execution tracking"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    runbook_id: str
    incident_id: Optional[str] = None
    company_id: str
    executed_by: str  # user_id
    cloud_provider: str
    target_config: Dict[str, Any]  # Cloud-specific config (instance_ids, resource_group, etc.)
    status: str  # pending, running, success, failed, partial_success
    command_id: Optional[str] = None  # Cloud provider's command ID
    logs: List[Dict[str, str]] = []  # [{timestamp, message, level}]
    output: Optional[str] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None


# ============= Auto-Assignment Models =============

class TechnicianSkills(BaseModel):
    """Technician skills for auto-assignment"""
    model_config = ConfigDict(extra="ignore")
    user_id: str
    skills: List[str] = []  # database, network, application, security, cloud_aws, cloud_azure
    workload_current: int = 0  # Current number of assigned incidents
    workload_max: int = 10  # Maximum concurrent incidents
    availability: str = "available"  # available, busy, offline
    shift_hours: Optional[Dict[str, str]] = None  # {start: "09:00", end: "17:00", timezone: "UTC"}
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AutoAssignmentRule(BaseModel):
    """Auto-assignment rules configuration"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    enabled: bool = True
    priority: int = 1  # Rule priority (higher number = higher priority)
    conditions: Dict[str, Any] = {}  # {severity: "critical", category: "database"}
    assignment_strategy: str = "round_robin"  # round_robin, skill_match, load_balance, least_loaded
    required_skills: List[str] = []
    target_technicians: List[str] = []  # Specific technician user_ids (if empty, use all available)
    escalation_time_minutes: int = 30  # Auto-escalate if not acknowledged in X minutes
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ============= Escalation Models =============

class EscalationPolicy(BaseModel):
    """Escalation policy configuration"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    name: str
    enabled: bool = True
    trigger_conditions: Dict[str, Any] = {}  # {unacknowledged_minutes: 30, priority_min: 80}
    escalation_levels: List[Dict[str, Any]] = []  
    # [{level: 1, delay_minutes: 15, notify_roles: ["technician"], notify_users: []}]
    sla_breach_action: str = "escalate"  # escalate, notify_manager, auto_remediate
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class IncidentEscalation(BaseModel):
    """Incident escalation tracking"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    company_id: str
    escalation_level: int = 1
    reason: str
    escalated_from: Optional[str] = None  # user_id
    escalated_to: Optional[str] = None  # user_id
    escalated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    acknowledged: bool = False
    acknowledged_at: Optional[str] = None


# ============= SLA Models =============

class SLAPolicy(BaseModel):
    """SLA policy for incident resolution"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    name: str
    enabled: bool = True
    priority_slas: Dict[str, int] = {}  # {critical: 60, high: 240, medium: 480, low: 1440} minutes
    acknowledgment_sla_minutes: int = 15  # Must acknowledge within X minutes
    breach_notification_enabled: bool = True
    breach_notification_recipients: List[str] = []  # user_ids or emails
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SLATracking(BaseModel):
    """SLA tracking for incidents"""
    model_config = ConfigDict(extra="ignore")
    incident_id: str
    company_id: str
    sla_policy_id: str
    target_resolution_minutes: int
    target_acknowledgment_minutes: int
    created_at: str
    acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None
    acknowledgment_breached: bool = False
    resolution_breached: bool = False
    time_to_acknowledge_minutes: Optional[float] = None
    time_to_resolve_minutes: Optional[float] = None


# ============= Company Onboarding Models =============

class CompanyOnboardingStatus(BaseModel):
    """Track company onboarding progress"""
    model_config = ConfigDict(extra="ignore")
    company_id: str
    steps_completed: List[str] = []  # api_key_generated, webhook_configured, ssm_agent_installed, first_alert_received
    agent_status: Dict[str, Any] = {}  # {aws_ssm: {connected: True, last_seen: "...", instance_count: 5}}
    asset_inventory: List[Dict[str, Any]] = []  # [{instance_id, name, platform, status, ip_address}]
    first_alert_at: Optional[str] = None
    setup_complete: bool = False
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ============= Email Notification Models =============

class EmailNotificationSettings(BaseModel):
    """Email notification settings per company"""
    model_config = ConfigDict(extra="ignore")
    company_id: str
    enabled: bool = True
    notify_on_assignment: bool = True
    notify_on_escalation: bool = True
    notify_on_sla_breach: bool = True
    notify_on_resolution: bool = False
    notification_recipients: List[str] = []  # Additional email addresses
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EmailNotificationLog(BaseModel):
    """Track sent email notifications"""
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: Optional[str] = None
    recipient: str
    notification_type: str  # assignment, escalation, sla_breach, resolution
    subject: str
    success: bool
    error: Optional[str] = None
    message_id: Optional[str] = None
    sent_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ============= Request/Response Models =============

class ExecuteRunbookRequest(BaseModel):
    """Request to execute a runbook"""
    runbook_id: str
    target_config: Dict[str, Any]  # Cloud-specific config
    parameters: Optional[Dict[str, Any]] = {}  # Parameter values for runbook


class CreateAutoAssignmentRuleRequest(BaseModel):
    """Create auto-assignment rule"""
    company_id: str
    enabled: bool = True
    conditions: Dict[str, Any]
    assignment_strategy: str
    required_skills: List[str] = []
    target_technicians: List[str] = []
    escalation_time_minutes: int = 30


class UpdateTechnicianSkillsRequest(BaseModel):
    """Update technician skills"""
    skills: List[str]
    workload_max: Optional[int] = None
    availability: Optional[str] = None
    shift_hours: Optional[Dict[str, str]] = None


class CreateEscalationPolicyRequest(BaseModel):
    """Create escalation policy"""
    company_id: str
    name: str
    enabled: bool = True
    trigger_conditions: Dict[str, Any]
    escalation_levels: List[Dict[str, Any]]
    sla_breach_action: str = "escalate"


class CreateSLAPolicyRequest(BaseModel):
    """Create SLA policy"""
    company_id: str
    name: str
    enabled: bool = True
    priority_slas: Dict[str, int]
    acknowledgment_sla_minutes: int = 15
    breach_notification_enabled: bool = True
    breach_notification_recipients: List[str] = []
