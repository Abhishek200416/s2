"""Escalation Service for MSP Platform
Handles incident escalation based on SLA breaches, priority, and policies
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
import asyncio


class EscalationEngine:
    """Engine for automatic incident escalation"""
    
    def __init__(self, db, email_service=None):
        self.db = db
        self.email_service = email_service
        print("✅ Escalation Engine initialized")
    
    async def check_and_escalate_incidents(self):
        """Check all active incidents for escalation conditions
        This should be called periodically (e.g., every 5 minutes)
        """
        # Get all active incidents
        incidents = await self.db.incidents.find(
            {"status": {"$in": ["new", "in_progress"]}},
            {"_id": 0}
        ).to_list(1000)
        
        escalated_count = 0
        
        for incident in incidents:
            should_escalate, reason = await self._should_escalate(incident)
            
            if should_escalate:
                result = await self.escalate_incident(
                    incident_id=incident["id"],
                    reason=reason,
                    auto_escalation=True
                )
                if result.get("success"):
                    escalated_count += 1
        
        return {
            "checked": len(incidents),
            "escalated": escalated_count
        }
    
    async def _should_escalate(self, incident: Dict[str, Any]) -> tuple[bool, str]:
        """Check if incident should be escalated
        
        Args:
            incident: Incident record
        
        Returns:
            Tuple of (should_escalate: bool, reason: str)
        """
        incident_id = incident["id"]
        company_id = incident["company_id"]
        
        # Get escalation policies for this company
        policies = await self.db.escalation_policies.find(
            {"company_id": company_id, "enabled": True},
            {"_id": 0}
        ).to_list(100)
        
        if not policies:
            return False, ""
        
        # Check if already escalated recently
        existing_escalation = await self.db.incident_escalations.find_one({
            "incident_id": incident_id
        })
        if existing_escalation:
            # Don't escalate twice
            return False, ""
        
        created_at = datetime.fromisoformat(incident["created_at"].replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        age_minutes = (now - created_at).total_seconds() / 60
        
        # Check each policy
        for policy in policies:
            trigger_conditions = policy.get("trigger_conditions", {})
            
            # Check unacknowledged time
            if "unacknowledged_minutes" in trigger_conditions:
                threshold = trigger_conditions["unacknowledged_minutes"]
                if incident.get("status") == "new" and age_minutes >= threshold:
                    return True, f"Unacknowledged for {int(age_minutes)} minutes (threshold: {threshold})"
            
            # Check priority
            if "priority_min" in trigger_conditions:
                priority_min = trigger_conditions["priority_min"]
                if incident.get("priority_score", 0) >= priority_min:
                    return True, f"High priority incident ({incident.get('priority_score')})"
            
            # Check SLA breach
            sla_tracking = await self.db.sla_tracking.find_one({"incident_id": incident_id})
            if sla_tracking:
                if sla_tracking.get("acknowledgment_breached") or sla_tracking.get("resolution_breached"):
                    return True, "SLA breach detected"
        
        return False, ""
    
    async def escalate_incident(
        self,
        incident_id: str,
        reason: str,
        escalated_from: Optional[str] = None,
        escalated_to: Optional[str] = None,
        auto_escalation: bool = False
    ) -> Dict[str, Any]:
        """Escalate an incident
        
        Args:
            incident_id: Incident ID to escalate
            reason: Reason for escalation
            escalated_from: User ID who escalated (if manual)
            escalated_to: User ID to escalate to (if specified)
            auto_escalation: Whether this is automatic escalation
        
        Returns:
            Dict with success status and escalation details
        """
        # Get incident
        incident = await self.db.incidents.find_one({"id": incident_id}, {"_id": 0})
        if not incident:
            return {
                "success": False,
                "error": "Incident not found"
            }
        
        company_id = incident["company_id"]
        
        # Get escalation level
        current_escalations = await self.db.incident_escalations.find(
            {"incident_id": incident_id},
            {"_id": 0}
        ).to_list(100)
        escalation_level = len(current_escalations) + 1
        
        # If escalated_to not specified, find appropriate technician/admin
        if not escalated_to:
            escalated_to = await self._find_escalation_target(
                company_id=company_id,
                escalation_level=escalation_level,
                incident=incident
            )
        
        if not escalated_to:
            return {
                "success": False,
                "error": "No escalation target found"
            }
        
        # Create escalation record
        from msp_models import IncidentEscalation
        escalation = IncidentEscalation(
            incident_id=incident_id,
            company_id=company_id,
            escalation_level=escalation_level,
            reason=reason,
            escalated_from=escalated_from,
            escalated_to=escalated_to
        )
        
        await self.db.incident_escalations.insert_one(escalation.model_dump())
        
        # Update incident status
        await self.db.incidents.update_one(
            {"id": incident_id},
            {
                "$set": {
                    "status": "escalated",
                    "assigned_to": escalated_to,
                    "escalation_level": escalation_level,
                    "escalated_at": datetime.now(timezone.utc).isoformat()
                }
            }
        )
        
        # Send escalation email notification
        if self.email_service and self.email_service.is_available():
            # Get escalated user details
            escalated_user = await self.db.users.find_one({"id": escalated_to}, {"_id": 0})
            if escalated_user:
                company = await self.db.companies.find_one({"id": company_id}, {"_id": 0})
                
                incident_data = {
                    "id": incident_id,
                    "title": incident.get("description", "Escalated Incident"),
                    "description": incident.get("description", ""),
                    "company_name": company.get("name", "Unknown") if company else "Unknown",
                    "priority_score": incident.get("priority_score", 0),
                    "severity": incident.get("severity", "medium"),
                    "affected_assets": incident.get("affected_assets", []),
                    "created_at": incident.get("created_at", "")
                }
                
                email_result = await self.email_service.send_escalation_email(
                    recipient_email=escalated_user["email"],
                    technician_name=escalated_user["name"],
                    incident_data=incident_data,
                    escalation_reason=reason
                )
                
                # Log email notification
                if email_result.get("success"):
                    print(f"✅ Escalation email sent to {escalated_user['email']}")
        
        return {
            "success": True,
            "escalation_id": escalation.id,
            "escalation_level": escalation_level,
            "escalated_to": escalated_to,
            "reason": reason
        }
    
    async def _find_escalation_target(
        self,
        company_id: str,
        escalation_level: int,
        incident: Dict[str, Any]
    ) -> Optional[str]:
        """Find appropriate escalation target
        
        Args:
            company_id: Company ID
            escalation_level: Current escalation level
            incident: Incident details
        
        Returns:
            User ID to escalate to or None
        """
        # Get escalation policy
        policy = await self.db.escalation_policies.find_one(
            {"company_id": company_id, "enabled": True},
            {"_id": 0}
        )
        
        if not policy:
            # Default: Escalate to MSP admin
            admin = await self.db.users.find_one(
                {"role": "msp_admin"},
                {"_id": 0}
            )
            return admin["id"] if admin else None
        
        # Get escalation level configuration
        escalation_levels = policy.get("escalation_levels", [])
        level_config = None
        
        for level in escalation_levels:
            if level.get("level") == escalation_level:
                level_config = level
                break
        
        if not level_config:
            # Use last level or default to admin
            if escalation_levels:
                level_config = escalation_levels[-1]
            else:
                admin = await self.db.users.find_one(
                    {"role": "msp_admin"},
                    {"_id": 0}
                )
                return admin["id"] if admin else None
        
        # Get target users based on roles
        notify_roles = level_config.get("notify_roles", [])
        notify_users = level_config.get("notify_users", [])
        
        # Prioritize specific users
        if notify_users:
            return notify_users[0]
        
        # Find user with specified role
        if notify_roles:
            for role in notify_roles:
                user = await self.db.users.find_one(
                    {"role": role, "company_ids": company_id},
                    {"_id": 0}
                )
                if user:
                    return user["id"]
        
        # Default to MSP admin
        admin = await self.db.users.find_one(
            {"role": "msp_admin"},
            {"_id": 0}
        )
        return admin["id"] if admin else None


async def start_escalation_monitor(db, email_service=None, interval_minutes: int = 5):
    """Start background task to monitor and escalate incidents
    
    Args:
        db: Database instance
        email_service: Email service instance
        interval_minutes: Check interval in minutes
    """
    escalation_engine = EscalationEngine(db, email_service)
    
    while True:
        try:
            result = await escalation_engine.check_and_escalate_incidents()
            if result["escalated"] > 0:
                print(f"🔥 Auto-escalated {result['escalated']} incidents")
        except Exception as e:
            print(f"❌ Escalation monitor error: {e}")
        
        # Wait for next check
        await asyncio.sleep(interval_minutes * 60)
