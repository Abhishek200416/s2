"""MSP Platform API Endpoints
Complete MSP automation endpoints for runbook execution, auto-assignment, escalation, SLA tracking
"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
import os

# Import models
from msp_models import (
    EnhancedRunbook, RunbookExecution, TechnicianSkills, AutoAssignmentRule,
    EscalationPolicy, IncidentEscalation, SLAPolicy, SLATracking,
    CompanyOnboardingStatus, EmailNotificationSettings, EmailNotificationLog,
    ExecuteRunbookRequest, CreateAutoAssignmentRuleRequest, UpdateTechnicianSkillsRequest,
    CreateEscalationPolicyRequest, CreateSLAPolicyRequest
)

# Import services
from cloud_execution_service import cloud_execution_service
from email_service import email_service
from auto_assignment_service import AutoAssignmentEngine, initialize_technician_skills
from escalation_service import EscalationEngine
from runbook_library import get_global_runbooks

# Database connection (will be set by server.py)
db = None

def set_database(database):
    """Set the database instance"""
    global db
    db = database

# Create API router
msp_router = APIRouter(prefix="/api/msp")


# ============= Runbook Execution Endpoints =============

@msp_router.get("/runbooks", response_model=List[EnhancedRunbook])
async def get_enhanced_runbooks(
    company_id: Optional[str] = None,
    category: Optional[str] = None,
    cloud_provider: Optional[str] = None
):
    """Get runbooks with optional filtering"""
    query = {}
    
    if company_id:
        query["$or"] = [
            {"company_id": company_id},
            {"is_global": True}
        ]
    else:
        query["is_global"] = True
    
    if category:
        query["category"] = category
    
    if cloud_provider:
        query["cloud_provider"] = {"$in": [cloud_provider, "multi"]}
    
    runbooks = await db.enhanced_runbooks.find(query, {"_id": 0}).to_list(200)
    return runbooks


@msp_router.post("/runbooks/{runbook_id}/execute", response_model=RunbookExecution)
async def execute_runbook(
    db,
    runbook_id: str,
    request: ExecuteRunbookRequest,
    credentials: HTTPAuthorizationCredentials
):
    """Execute a runbook on cloud infrastructure
    
    This endpoint executes the runbook script via AWS SSM or Azure Run Command
    """
    # Get current user (assuming get_current_user function exists)
    # user = await get_current_user(credentials)
    user_id = "temp_user_id"  # Placeholder
    
    # Get runbook
    runbook = await db.enhanced_runbooks.find_one({"id": runbook_id}, {"_id": 0})
    if not runbook:
        raise HTTPException(status_code=404, detail="Runbook not found")
    
    # Check approval requirements
    risk_level = runbook.get("risk_level", "low")
    if risk_level == "high" or (risk_level == "medium" and not runbook.get("auto_approve")):
        # Would need approval check here
        pass
    
    # Execute runbook via cloud service
    execution_result = await cloud_execution_service.execute_runbook(
        cloud_provider=runbook["cloud_provider"],
        runbook_script=runbook["script_content"],
        target_config=request.target_config,
        script_type=runbook["script_type"]
    )
    
    # Create execution record
    execution = RunbookExecution(
        runbook_id=runbook_id,
        incident_id=request.target_config.get("incident_id"),
        company_id=request.target_config.get("company_id", "unknown"),
        executed_by=user_id,
        cloud_provider=runbook["cloud_provider"],
        target_config=request.target_config,
        status="running" if execution_result.get("success") else "failed",
        command_id=execution_result.get("command_id"),
        logs=[{
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": execution_result.get("error", "Execution started"),
            "level": "error" if not execution_result.get("success") else "info"
        }]
    )
    
    await db.runbook_executions.insert_one(execution.model_dump())
    
    # Update runbook execution count
    await db.enhanced_runbooks.update_one(
        {"id": runbook_id},
        {"$inc": {"execution_count": 1}}
    )
    
    return execution


@msp_router.get("/runbooks/executions/{execution_id}", response_model=RunbookExecution)
async def get_execution_status(execution_id: str):
    """Get runbook execution status and logs"""
    execution = await db.runbook_executions.find_one({"id": execution_id}, {"_id": 0})
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    
    # If still running, check cloud provider status
    if execution["status"] == "running" and execution.get("command_id"):
        status_result = await cloud_execution_service.get_execution_status(
            cloud_provider=execution["cloud_provider"],
            command_id=execution["command_id"],
            instance_id=execution["target_config"].get("instance_ids", [None])[0]
        )
        
        if status_result.get("success"):
            # Update execution record
            status = status_result.get("status", "running")
            if status in ["Success", "success"]:
                execution["status"] = "success"
                execution["completed_at"] = datetime.now(timezone.utc).isoformat()
            elif status in ["Failed", "failed"]:
                execution["status"] = "failed"
                execution["completed_at"] = datetime.now(timezone.utc).isoformat()
            
            execution["output"] = status_result.get("output", "")
            execution["error"] = status_result.get("error", "")
            execution["exit_code"] = status_result.get("exit_code")
            
            await db.runbook_executions.update_one(
                {"id": execution_id},
                {"$set": execution}
            )
    
    return RunbookExecution(**execution)


# ============= Auto-Assignment Endpoints =============

@msp_router.post("/auto-assignment/rules", response_model=AutoAssignmentRule)
async def create_auto_assignment_rule(request: CreateAutoAssignmentRuleRequest):
    """Create auto-assignment rule for a company"""
    rule = AutoAssignmentRule(**request.model_dump())
    await db.auto_assignment_rules.insert_one(rule.model_dump())
    return rule


@msp_router.get("/auto-assignment/rules/{company_id}", response_model=List[AutoAssignmentRule])
async def get_auto_assignment_rules(company_id: str):
    """Get auto-assignment rules for a company"""
    rules = await db.auto_assignment_rules.find(
        {"company_id": company_id},
        {"_id": 0}
    ).to_list(100)
    return rules


@msp_router.put("/technicians/{user_id}/skills", response_model=TechnicianSkills)
async def update_technician_skills(user_id: str, request: UpdateTechnicianSkillsRequest):
    """Update technician skills and availability"""
    # Initialize if doesn't exist
    await initialize_technician_skills(db, user_id, request.skills)
    
    # Update skills
    update_data = {"skills": request.skills, "updated_at": datetime.now(timezone.utc).isoformat()}
    if request.workload_max is not None:
        update_data["workload_max"] = request.workload_max
    if request.availability is not None:
        update_data["availability"] = request.availability
    if request.shift_hours is not None:
        update_data["shift_hours"] = request.shift_hours
    
    await db.technician_skills.update_one(
        {"user_id": user_id},
        {"$set": update_data}
    )
    
    skills = await db.technician_skills.find_one({"user_id": user_id}, {"_id": 0})
    return TechnicianSkills(**skills)


@msp_router.get("/technicians/{user_id}/skills", response_model=TechnicianSkills)
async def get_technician_skills(user_id: str):
    """Get technician skills and workload"""
    skills = await db.technician_skills.find_one({"user_id": user_id}, {"_id": 0})
    if not skills:
        # Initialize with defaults
        await initialize_technician_skills(db, user_id)
        skills = await db.technician_skills.find_one({"user_id": user_id}, {"_id": 0})
    
    return TechnicianSkills(**skills)


# ============= Escalation Endpoints =============

@msp_router.post("/escalation/policies", response_model=EscalationPolicy)
async def create_escalation_policy(request: CreateEscalationPolicyRequest):
    """Create escalation policy for a company"""
    policy = EscalationPolicy(**request.model_dump())
    await db.escalation_policies.insert_one(policy.model_dump())
    return policy


@msp_router.get("/escalation/policies/{company_id}", response_model=List[EscalationPolicy])
async def get_escalation_policies(company_id: str):
    """Get escalation policies for a company"""
    policies = await db.escalation_policies.find(
        {"company_id": company_id},
        {"_id": 0}
    ).to_list(100)
    return policies


@msp_router.post("/incidents/{incident_id}/escalate")
async def manual_escalate_incident(
    db,
    incident_id: str,
    reason: str,
    escalated_to: Optional[str] = None
):
    """Manually escalate an incident"""
    escalation_engine = EscalationEngine(db, email_service)
    result = await escalation_engine.escalate_incident(
        incident_id=incident_id,
        reason=reason,
        escalated_to=escalated_to,
        auto_escalation=False
    )
    
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Escalation failed"))
    
    return result


# ============= SLA Endpoints =============

@msp_router.post("/sla/policies", response_model=SLAPolicy)
async def create_sla_policy(request: CreateSLAPolicyRequest):
    """Create SLA policy for a company"""
    policy = SLAPolicy(**request.model_dump())
    await db.sla_policies.insert_one(policy.model_dump())
    return policy


@msp_router.get("/sla/policies/{company_id}", response_model=List[SLAPolicy])
async def get_sla_policies(company_id: str):
    """Get SLA policies for a company"""
    policies = await db.sla_policies.find(
        {"company_id": company_id},
        {"_id": 0}
    ).to_list(100)
    return policies


@msp_router.get("/sla/tracking/{incident_id}", response_model=SLATracking)
async def get_sla_tracking(incident_id: str):
    """Get SLA tracking for an incident"""
    tracking = await db.sla_tracking.find_one({"incident_id": incident_id}, {"_id": 0})
    if not tracking:
        raise HTTPException(status_code=404, detail="SLA tracking not found")
    
    return SLATracking(**tracking)


# ============= Email Notification Endpoints =============

@msp_router.post("/notifications/test-email")
async def send_test_email(recipient_email: str):
    """Send test email to verify AWS SES configuration"""
    if not email_service.is_available():
        raise HTTPException(status_code=503, detail="Email service not available")
    
    result = await email_service.send_test_email(recipient_email)
    
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to send email"))
    
    return result


@msp_router.put("/notifications/settings/{company_id}", response_model=EmailNotificationSettings)
async def update_email_notification_settings(
    db,
    company_id: str,
    settings: EmailNotificationSettings
):
    """Update email notification settings for a company"""
    settings.company_id = company_id
    settings.updated_at = datetime.now(timezone.utc).isoformat()
    
    await db.email_notification_settings.update_one(
        {"company_id": company_id},
        {"$set": settings.model_dump()},
        upsert=True
    )
    
    return settings


@msp_router.get("/notifications/settings/{company_id}", response_model=EmailNotificationSettings)
async def get_email_notification_settings(company_id: str):
    """Get email notification settings for a company"""
    settings = await db.email_notification_settings.find_one({"company_id": company_id}, {"_id": 0})
    if not settings:
        # Return defaults
        settings = EmailNotificationSettings(company_id=company_id)
        await db.email_notification_settings.insert_one(settings.model_dump())
    
    return EmailNotificationSettings(**settings)


# ============= Company Onboarding Endpoints =============

@msp_router.get("/onboarding/status/{company_id}", response_model=CompanyOnboardingStatus)
async def get_onboarding_status(company_id: str):
    """Get onboarding status for a company"""
    status = await db.company_onboarding_status.find_one({"company_id": company_id}, {"_id": 0})
    if not status:
        status = CompanyOnboardingStatus(company_id=company_id)
        await db.company_onboarding_status.insert_one(status.model_dump())
    
    return CompanyOnboardingStatus(**status)


@msp_router.post("/onboarding/complete-step/{company_id}")
async def complete_onboarding_step(company_id: str, step: str):
    """Mark an onboarding step as complete"""
    await db.company_onboarding_status.update_one(
        {"company_id": company_id},
        {
            "$addToSet": {"steps_completed": step},
            "$set": {"updated_at": datetime.now(timezone.utc).isoformat()}
        },
        upsert=True
    )
    
    # Check if all steps complete
    status = await db.company_onboarding_status.find_one({"company_id": company_id}, {"_id": 0})
    if status:
        required_steps = ["api_key_generated", "webhook_configured", "ssm_agent_installed", "first_alert_received"]
        if all(step in status.get("steps_completed", []) for step in required_steps):
            await db.company_onboarding_status.update_one(
                {"company_id": company_id},
                {"$set": {"setup_complete": True}}
            )
    
    return {"message": "Step completed", "step": step}


# ============= System Health Endpoints =============

@msp_router.get("/system/health")
async def get_system_health():
    """Get system health status"""
    return {
        "status": "healthy",
        "services": {
            "cloud_execution": {
                "aws_ssm": cloud_execution_service.aws_executor.is_available(),
                "azure_run_command": cloud_execution_service.azure_executor.is_available()
            },
            "email_service": email_service.is_available()
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
