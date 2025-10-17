"""SLA Management Service for MSP Platform
Tracks SLA compliance, calculates deadlines, and triggers escalations
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
import asyncio
from email_service import email_service


class SLAService:
    """Service for managing SLA tracking, compliance, and escalations"""
    
    def __init__(self, db):
        self.db = db
        print("✅ SLA Service initialized")
    
    async def get_sla_config(self, company_id: str) -> Dict[str, Any]:
        """Get SLA configuration for a company
        
        Returns default config if none exists
        """
        config = await self.db.sla_configs.find_one({"company_id": company_id}, {"_id": 0})
        
        if not config:
            # Return default SLA configuration
            return {
                "company_id": company_id,
                "enabled": True,
                "business_hours_only": False,  # 24/7 support
                "business_hours": {
                    "start": "09:00",
                    "end": "17:00",
                    "timezone": "UTC",
                    "working_days": [1, 2, 3, 4, 5]  # Monday-Friday
                },
                "response_time_minutes": {
                    "critical": 30,   # 30 minutes
                    "high": 120,      # 2 hours
                    "medium": 480,    # 8 hours
                    "low": 1440       # 24 hours
                },
                "resolution_time_minutes": {
                    "critical": 240,   # 4 hours
                    "high": 480,       # 8 hours
                    "medium": 1440,    # 24 hours
                    "low": 2880        # 48 hours
                },
                "escalation_enabled": True,
                "escalation_before_breach_minutes": 30,  # Warn 30 min before breach
                "escalation_chain": [
                    {"level": 1, "role": "technician", "notify_on": "response_sla_warning"},
                    {"level": 2, "role": "company_admin", "notify_on": "response_sla_breach"},
                    {"level": 3, "role": "msp_admin", "notify_on": "resolution_sla_breach"}
                ]
            }
        
        return config
    
    async def save_sla_config(self, company_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Save or update SLA configuration for a company"""
        config["company_id"] = company_id
        
        await self.db.sla_configs.update_one(
            {"company_id": company_id},
            {"$set": config},
            upsert=True
        )
        
        return config
    
    async def calculate_sla_deadlines(
        self,
        company_id: str,
        severity: str,
        created_at: datetime
    ) -> Dict[str, Any]:
        """Calculate SLA deadlines for an incident
        
        Args:
            company_id: Company ID
            severity: Incident severity (critical, high, medium, low)
            created_at: Incident creation time
        
        Returns:
            Dict with response_deadline, resolution_deadline, and time remaining
        """
        config = await self.get_sla_config(company_id)
        
        if not config["enabled"]:
            return {
                "enabled": False,
                "response_deadline": None,
                "resolution_deadline": None
            }
        
        # Get SLA times for this severity
        response_minutes = config["response_time_minutes"].get(severity, 1440)
        resolution_minutes = config["resolution_time_minutes"].get(severity, 2880)
        
        # Calculate deadlines
        if config["business_hours_only"]:
            # Complex calculation considering business hours
            response_deadline = self._add_business_time(
                created_at,
                response_minutes,
                config["business_hours"]
            )
            resolution_deadline = self._add_business_time(
                created_at,
                resolution_minutes,
                config["business_hours"]
            )
        else:
            # Simple calendar time calculation (24/7 support)
            response_deadline = created_at + timedelta(minutes=response_minutes)
            resolution_deadline = created_at + timedelta(minutes=resolution_minutes)
        
        # Calculate time remaining
        now = datetime.now(timezone.utc)
        response_remaining_minutes = max(0, (response_deadline - now).total_seconds() / 60)
        resolution_remaining_minutes = max(0, (resolution_deadline - now).total_seconds() / 60)
        
        return {
            "enabled": True,
            "response_deadline": response_deadline.isoformat(),
            "resolution_deadline": resolution_deadline.isoformat(),
            "response_remaining_minutes": int(response_remaining_minutes),
            "resolution_remaining_minutes": int(resolution_remaining_minutes),
            "response_sla_breached": response_remaining_minutes <= 0,
            "resolution_sla_breached": resolution_remaining_minutes <= 0,
            "response_time_minutes": response_minutes,
            "resolution_time_minutes": resolution_minutes
        }
    
    def _add_business_time(
        self,
        start_time: datetime,
        minutes_to_add: int,
        business_hours: Dict[str, Any]
    ) -> datetime:
        """Add business time to a datetime (skip weekends and non-business hours)"""
        # Simplified implementation - add calendar time for now
        # Full implementation would skip weekends/nights
        return start_time + timedelta(minutes=minutes_to_add)
    
    async def check_sla_status(self, incident_id: str) -> Dict[str, Any]:
        """Check current SLA status for an incident
        
        Returns:
            Dict with SLA status, deadlines, and whether action is needed
        """
        incident = await self.db.incidents.find_one({"id": incident_id})
        
        if not incident:
            return {"error": "Incident not found"}
        
        # If incident is resolved, calculate actual times
        if incident.get("status") == "resolved":
            created_at = datetime.fromisoformat(incident["created_at"])
            resolved_at = datetime.fromisoformat(incident.get("resolved_at", incident["created_at"]))
            first_response_at = datetime.fromisoformat(incident.get("assigned_at", incident["created_at"]))
            
            actual_response_minutes = (first_response_at - created_at).total_seconds() / 60
            actual_resolution_minutes = (resolved_at - created_at).total_seconds() / 60
            
            sla_data = incident.get("sla", {})
            
            return {
                "status": "resolved",
                "actual_response_minutes": int(actual_response_minutes),
                "actual_resolution_minutes": int(actual_resolution_minutes),
                "response_sla_met": actual_response_minutes <= sla_data.get("response_time_minutes", 0),
                "resolution_sla_met": actual_resolution_minutes <= sla_data.get("resolution_time_minutes", 0),
                "sla_config": sla_data
            }
        
        # For active incidents, calculate remaining time
        sla_data = incident.get("sla", {})
        
        if not sla_data or not sla_data.get("enabled"):
            return {"enabled": False, "message": "SLA tracking not enabled for this incident"}
        
        now = datetime.now(timezone.utc)
        response_deadline = datetime.fromisoformat(sla_data["response_deadline"])
        resolution_deadline = datetime.fromisoformat(sla_data["resolution_deadline"])
        
        response_remaining = max(0, (response_deadline - now).total_seconds() / 60)
        resolution_remaining = max(0, (resolution_deadline - now).total_seconds() / 60)
        
        # Determine status
        status = "on_track"
        if response_remaining <= 0 and not incident.get("assigned_to"):
            status = "response_breached"
        elif resolution_remaining <= 0:
            status = "resolution_breached"
        elif response_remaining <= 30:  # Warning 30 min before breach
            status = "response_warning"
        elif resolution_remaining <= 30:
            status = "resolution_warning"
        
        return {
            "enabled": True,
            "status": status,
            "incident_id": incident_id,
            "severity": incident.get("severity"),
            "response_deadline": sla_data["response_deadline"],
            "resolution_deadline": sla_data["resolution_deadline"],
            "response_remaining_minutes": int(response_remaining),
            "resolution_remaining_minutes": int(resolution_remaining),
            "response_sla_breached": response_remaining <= 0,
            "resolution_sla_breached": resolution_remaining <= 0,
            "assigned_to": incident.get("assigned_to"),
            "escalated": incident.get("escalated", False)
        }
    
    async def handle_sla_breach(
        self,
        incident_id: str,
        breach_type: str  # "response" or "resolution"
    ) -> Dict[str, Any]:
        """Handle SLA breach - escalate incident and send notifications
        
        Args:
            incident_id: Incident ID
            breach_type: Type of breach ("response" or "resolution")
        
        Returns:
            Dict with escalation actions taken
        """
        incident = await self.db.incidents.find_one({"id": incident_id})
        
        if not incident:
            return {"error": "Incident not found"}
        
        company_id = incident["company_id"]
        config = await self.get_sla_config(company_id)
        
        if not config.get("escalation_enabled"):
            return {"escalated": False, "reason": "Escalation not enabled"}
        
        # Mark incident as escalated
        await self.db.incidents.update_one(
            {"id": incident_id},
            {
                "$set": {
                    "escalated": True,
                    "escalated_at": datetime.now(timezone.utc).isoformat(),
                    "escalation_reason": f"{breach_type}_sla_breach",
                    "status": "escalated"
                }
            }
        )
        
        # Get escalation chain
        escalation_chain = config.get("escalation_chain", [])
        
        # Determine who to notify based on breach type
        notification_recipients = []
        
        for level in escalation_chain:
            if breach_type == "response" and level.get("notify_on") in ["response_sla_warning", "response_sla_breach"]:
                notification_recipients.append(level)
            elif breach_type == "resolution" and level.get("notify_on") == "resolution_sla_breach":
                notification_recipients.append(level)
        
        # Send escalation notifications
        notifications_sent = []
        
        for recipient_config in notification_recipients:
            role = recipient_config["role"]
            
            # Get users with this role for this company
            if role == "msp_admin":
                users = await self.db.users.find({"role": "msp_admin"}).to_list(100)
            else:
                users = await self.db.users.find({
                    "role": role,
                    "company_ids": company_id
                }).to_list(100)
            
            for user in users:
                # Send escalation email
                if email_service.is_available():
                    incident_data = {
                        "id": incident_id,
                        "title": incident.get("title", "Unknown Incident"),
                        "company_name": incident.get("company_name", "Unknown"),
                        "priority_score": incident.get("priority_score", 0),
                        "severity": incident.get("severity", "unknown"),
                        "description": incident.get("description", "No description"),
                        "affected_assets": incident.get("affected_assets", []),
                        "created_at": incident.get("created_at", "Unknown")
                    }
                    
                    escalation_reason = f"{breach_type.upper()} SLA BREACHED - Immediate attention required"
                    
                    result = await email_service.send_escalation_email(
                        recipient_email=user["email"],
                        technician_name=user["name"],
                        incident_data=incident_data,
                        escalation_reason=escalation_reason
                    )
                    
                    if result.get("success"):
                        notifications_sent.append({
                            "user": user["name"],
                            "email": user["email"],
                            "role": role,
                            "level": recipient_config["level"]
                        })
                
                # Create in-app notification
                await self.db.notifications.insert_one({
                    "user_id": user["id"],
                    "company_id": company_id,
                    "type": "sla_breach",
                    "title": f"🔥 SLA BREACH: {incident.get('title')}",
                    "message": f"{breach_type.upper()} SLA breached. Incident escalated.",
                    "severity": "critical",
                    "read": False,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "metadata": {
                        "incident_id": incident_id,
                        "breach_type": breach_type
                    }
                })
        
        # Create audit log
        await self.db.system_audit_logs.insert_one({
            "action": "sla_breach_escalation",
            "user_id": "system",
            "company_id": company_id,
            "details": {
                "incident_id": incident_id,
                "breach_type": breach_type,
                "notifications_sent": len(notifications_sent)
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        return {
            "escalated": True,
            "breach_type": breach_type,
            "notifications_sent": notifications_sent,
            "incident_status": "escalated"
        }
    
    async def get_sla_compliance_report(
        self,
        company_id: str,
        days: int = 30
    ) -> Dict[str, Any]:
        """Generate SLA compliance report for a company
        
        Args:
            company_id: Company ID
            days: Number of days to look back (default: 30)
        
        Returns:
            Dict with SLA compliance metrics
        """
        # Calculate start date
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Get all resolved incidents in time period
        incidents = await self.db.incidents.find({
            "company_id": company_id,
            "status": "resolved",
            "created_at": {"$gte": start_date.isoformat()}
        }).to_list(1000)
        
        if not incidents:
            return {
                "company_id": company_id,
                "period_days": days,
                "total_incidents": 0,
                "message": "No incidents found in this period"
            }
        
        # Calculate metrics
        total = len(incidents)
        response_sla_met = 0
        resolution_sla_met = 0
        total_response_time = 0
        total_resolution_time = 0
        
        by_severity = {
            "critical": {"total": 0, "response_met": 0, "resolution_met": 0},
            "high": {"total": 0, "response_met": 0, "resolution_met": 0},
            "medium": {"total": 0, "response_met": 0, "resolution_met": 0},
            "low": {"total": 0, "response_met": 0, "resolution_met": 0}
        }
        
        for incident in incidents:
            severity = incident.get("severity", "medium")
            sla = incident.get("sla", {})
            
            created_at = datetime.fromisoformat(incident["created_at"])
            resolved_at = datetime.fromisoformat(incident.get("resolved_at", incident["created_at"]))
            assigned_at = datetime.fromisoformat(incident.get("assigned_at", incident["created_at"]))
            
            actual_response = (assigned_at - created_at).total_seconds() / 60
            actual_resolution = (resolved_at - created_at).total_seconds() / 60
            
            total_response_time += actual_response
            total_resolution_time += actual_resolution
            
            # Check if SLA was met
            if sla.get("enabled"):
                response_target = sla.get("response_time_minutes", 0)
                resolution_target = sla.get("resolution_time_minutes", 0)
                
                if actual_response <= response_target:
                    response_sla_met += 1
                    by_severity[severity]["response_met"] += 1
                
                if actual_resolution <= resolution_target:
                    resolution_sla_met += 1
                    by_severity[severity]["resolution_met"] += 1
            
            by_severity[severity]["total"] += 1
        
        # Calculate percentages
        response_compliance_pct = (response_sla_met / total * 100) if total > 0 else 0
        resolution_compliance_pct = (resolution_sla_met / total * 100) if total > 0 else 0
        avg_response_minutes = total_response_time / total if total > 0 else 0
        avg_resolution_minutes = total_resolution_time / total if total > 0 else 0
        
        return {
            "company_id": company_id,
            "period_days": days,
            "total_incidents": total,
            "response_sla_compliance_pct": round(response_compliance_pct, 1),
            "resolution_sla_compliance_pct": round(resolution_compliance_pct, 1),
            "response_sla_met": response_sla_met,
            "resolution_sla_met": resolution_sla_met,
            "avg_response_minutes": round(avg_response_minutes, 1),
            "avg_resolution_minutes": round(avg_resolution_minutes, 1),
            "by_severity": by_severity
        }


# Global SLA service instance (initialized in server.py)
sla_service = None
