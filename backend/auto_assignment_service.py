"""Auto-Assignment Service for MSP Platform
Automatically assigns incidents to technicians based on skills, workload, and availability
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import random


class AutoAssignmentEngine:
    """Engine for automatic incident assignment to technicians"""
    
    def __init__(self, db):
        self.db = db
        print("✅ Auto-Assignment Engine initialized")
    
    async def assign_incident(
        self,
        incident_id: str,
        company_id: str,
        incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Automatically assign incident to best available technician
        
        Args:
            incident_id: Incident ID
            company_id: Company ID
            incident_data: Incident details (severity, category, priority_score, etc.)
        
        Returns:
            Dict with assigned_to user_id and assignment_reason
        """
        # Get auto-assignment rules for this company
        rules = await self.db.auto_assignment_rules.find(
            {"company_id": company_id, "enabled": True},
            {"_id": 0}
        ).sort("priority", -1).to_list(100)
        
        if not rules:
            return {
                "success": False,
                "reason": "No auto-assignment rules configured for this company"
            }
        
        # Find matching rule
        matching_rule = None
        for rule in rules:
            if self._matches_conditions(incident_data, rule.get("conditions", {})):
                matching_rule = rule
                break
        
        if not matching_rule:
            return {
                "success": False,
                "reason": "No auto-assignment rule matches this incident"
            }
        
        # Get available technicians
        technicians = await self._get_available_technicians(
            company_id=company_id,
            required_skills=matching_rule.get("required_skills", []),
            target_technicians=matching_rule.get("target_technicians", [])
        )
        
        if not technicians:
            # OVERFLOW QUEUE: No available technicians
            # Add to queue and notify managers
            await self._add_to_overflow_queue(incident_id, company_id, incident_data)
            return {
                "success": False,
                "reason": "All technicians busy - added to overflow queue",
                "queued": True
            }
        
        # Select technician based on strategy
        strategy = matching_rule.get("assignment_strategy", "round_robin")
        selected_technician = await self._select_technician(
            technicians=technicians,
            strategy=strategy,
            incident_data=incident_data
        )
        
        if not selected_technician:
            return {
                "success": False,
                "reason": "Failed to select technician"
            }
        
        # Update incident with assignment
        await self.db.incidents.update_one(
            {"id": incident_id},
            {
                "$set": {
                    "assigned_to": selected_technician["user_id"],
                    "assigned_at": datetime.now(timezone.utc).isoformat(),
                    "status": "in_progress",
                    "assignment_method": "auto",
                    "assignment_strategy": strategy
                }
            }
        )
        
        # Update technician workload
        await self.db.technician_skills.update_one(
            {"user_id": selected_technician["user_id"]},
            {"$inc": {"workload_current": 1}}
        )
        
        return {
            "success": True,
            "assigned_to": selected_technician["user_id"],
            "assignment_strategy": strategy,
            "reason": f"Auto-assigned using {strategy} strategy"
        }
    
    def _matches_conditions(self, incident_data: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Check if incident matches rule conditions
        
        Args:
            incident_data: Incident details
            conditions: Rule conditions to match
        
        Returns:
            True if incident matches all conditions
        """
        if not conditions:
            return True  # Empty conditions match all
        
        for key, value in conditions.items():
            if key == "severity":
                if incident_data.get("severity") != value:
                    return False
            elif key == "priority_min":
                if incident_data.get("priority_score", 0) < value:
                    return False
            elif key == "priority_max":
                if incident_data.get("priority_score", 0) > value:
                    return False
            elif key == "category":
                # Match against incident description or signature
                description = incident_data.get("description", "").lower()
                if value.lower() not in description:
                    return False
            elif key == "tool_source":
                tool_sources = incident_data.get("tool_sources", [])
                if value not in tool_sources:
                    return False
        
        return True
    
    async def _get_available_technicians(
        self,
        company_id: str,
        required_skills: List[str],
        target_technicians: List[str]
    ) -> List[Dict[str, Any]]:
        """Get available technicians matching criteria
        
        Priority:
        1. Check if anyone is on-call right now
        2. Get available technicians with required skills
        3. Filter by workload capacity
        
        Args:
            company_id: Company ID
            required_skills: Required skills
            target_technicians: Specific technician IDs (if any)
        
        Returns:
            List of available technician records
        """
        # PRIORITY 1: Check if anyone is on-call right now
        try:
            from oncall_service import oncall_service
            if oncall_service:
                on_call_tech = await oncall_service.get_current_on_call_technician(company_id)
                if on_call_tech:
                    # Check if on-call technician has capacity
                    tech_skills = await self.db.technician_skills.find_one(
                        {"user_id": on_call_tech["id"]},
                        {"_id": 0}
                    )
                    if tech_skills:
                        workload_current = tech_skills.get("workload_current", 0)
                        workload_max = tech_skills.get("workload_max", 10)
                        if workload_current < workload_max:
                            # On-call tech has capacity - prioritize them
                            print(f"✅ Assigning to on-call technician: {on_call_tech.get('name')}")
                            return [tech_skills]
        except Exception as e:
            print(f"⚠️ Error checking on-call schedule: {e}")
        
        # PRIORITY 2: Get available technicians normally
        query = {"availability": "available"}
        
        # Filter by specific technicians if provided
        if target_technicians:
            query["user_id"] = {"$in": target_technicians}
        
        # Get all technician skills
        all_technicians = await self.db.technician_skills.find(query, {"_id": 0}).to_list(100)
        
        # Filter by required skills and workload
        available = []
        for tech in all_technicians:
            # Check if technician has required skills
            if required_skills:
                tech_skills = set(tech.get("skills", []))
                if not all(skill in tech_skills for skill in required_skills):
                    continue
            
            # Check if technician has capacity
            workload_current = tech.get("workload_current", 0)
            workload_max = tech.get("workload_max", 10)
            if workload_current >= workload_max:
                continue
            
            available.append(tech)
        
        return available
    
    async def _select_technician(
        self,
        technicians: List[Dict[str, Any]],
        strategy: str,
        incident_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Select best technician based on strategy
        
        Args:
            technicians: List of available technicians
            strategy: Assignment strategy
            incident_data: Incident details
        
        Returns:
            Selected technician record or None
        """
        if not technicians:
            return None
        
        if strategy == "round_robin":
            # Simple round-robin (could be enhanced with persistent counter)
            return random.choice(technicians)
        
        elif strategy == "least_loaded":
            # Assign to technician with lowest workload
            return min(technicians, key=lambda t: t.get("workload_current", 0))
        
        elif strategy == "skill_match":
            # Assign to technician with most matching skills
            incident_keywords = incident_data.get("description", "").lower()
            best_score = -1
            best_tech = technicians[0]
            
            for tech in technicians:
                score = 0
                for skill in tech.get("skills", []):
                    if skill.lower() in incident_keywords:
                        score += 1
                
                if score > best_score:
                    best_score = score
                    best_tech = tech
            
            return best_tech
        
        elif strategy == "load_balance":
            # Balance between skill match and workload
            scores = []
            for tech in technicians:
                # Skill match score
                skill_score = 0
                incident_keywords = incident_data.get("description", "").lower()
                for skill in tech.get("skills", []):
                    if skill.lower() in incident_keywords:
                        skill_score += 1
                
                # Workload score (inverted - lower workload = higher score)
                workload_current = tech.get("workload_current", 0)
                workload_max = tech.get("workload_max", 10)
                workload_score = (workload_max - workload_current) / workload_max
                
                # Combined score
                total_score = skill_score * 2 + workload_score
                scores.append((total_score, tech))
            
            # Return technician with highest score
            return max(scores, key=lambda x: x[0])[1]
        
        else:
            # Default to random
            return random.choice(technicians)


# Helper function to initialize technician skills for a user
async def initialize_technician_skills(db, user_id: str, skills: List[str] = None):
    """Initialize technician skills record
    
    Args:
        db: Database instance
        user_id: User ID
        skills: Initial skills (default: empty list)
    """
    from msp_models import TechnicianSkills
    
    existing = await db.technician_skills.find_one({"user_id": user_id})
    if existing:
        return  # Already initialized
    
    tech_skills = TechnicianSkills(
        user_id=user_id,
        skills=skills or [],
        workload_current=0,
        workload_max=10,
        availability="available"
    )
    
    await db.technician_skills.insert_one(tech_skills.model_dump())

    
    async def _add_to_overflow_queue(
        self,
        incident_id: str,
        company_id: str,
        incident_data: Dict[str, Any]
    ) -> None:
        """Add incident to overflow queue when all technicians are busy
        
        Args:
            incident_id: Incident ID
            company_id: Company ID
            incident_data: Incident details
        """
        # Create queue entry
        queue_entry = {
            "id": f"queue-{incident_id}",
            "incident_id": incident_id,
            "company_id": company_id,
            "priority_score": incident_data.get("priority_score", 50),
            "severity": incident_data.get("severity", "medium"),
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "status": "queued",
            "notified": False
        }
        
        await self.db.incident_overflow_queue.insert_one(queue_entry)
        
        # Update incident status
        await self.db.incidents.update_one(
            {"id": incident_id},
            {
                "$set": {
                    "status": "queued",
                    "queued_at": datetime.now(timezone.utc).isoformat(),
                    "queue_reason": "All technicians at capacity"
                }
            }
        )
        
        # Send notification to managers
        try:
            from email_service import email_service
            
            # Get company managers
            managers = await self.db.users.find({
                "role": {"$in": ["msp_admin", "company_admin"]},
                "company_ids": company_id
            }, {"_id": 0}).to_list(100)
            
            for manager in managers:
                email_body = f"""
                <h2>⚠️ Incident Queue Alert</h2>
                <p>A high-priority incident has been added to the overflow queue because all technicians are at capacity.</p>
                
                <h3>Incident Details:</h3>
                <ul>
                    <li><strong>Priority:</strong> {incident_data.get('priority_score', 'N/A')}</li>
                    <li><strong>Severity:</strong> {incident_data.get('severity', 'N/A')}</li>
                    <li><strong>Asset:</strong> {incident_data.get('asset_name', 'N/A')}</li>
                    <li><strong>Issue:</strong> {incident_data.get('signature', 'N/A')}</li>
                </ul>
                
                <p>The incident will be automatically assigned when a technician becomes available.</p>
                <p><strong>Action Required:</strong> Consider adding more technicians or manually assigning this incident.</p>
                """
                
                await email_service.send_email(
                    to_email=manager.get("email"),
                    subject=f"🚨 Overflow Queue Alert - Incident {incident_id}",
                    body=email_body
                )
            
            # Mark as notified
            await self.db.incident_overflow_queue.update_one(
                {"id": queue_entry["id"]},
                {"$set": {"notified": True}}
            )
            
        except Exception as e:
            print(f"❌ Failed to send overflow notification: {e}")
    
    async def process_overflow_queue(self, company_id: str) -> Dict[str, Any]:
        """Process queued incidents when technicians become available
        
        Called when:
        - A technician resolves an incident
        - A technician's status changes to available
        
        Args:
            company_id: Company ID
        
        Returns:
            Dict with processed count and results
        """
        # Get queued incidents (highest priority first)
        queued = await self.db.incident_overflow_queue.find(
            {"company_id": company_id, "status": "queued"},
            {"_id": 0}
        ).sort("priority_score", -1).to_list(100)
        
        if not queued:
            return {"success": True, "processed": 0, "message": "No queued incidents"}
        
        processed = 0
        results = []
        
        for queue_entry in queued:
            incident_id = queue_entry["incident_id"]
            
            # Try to assign
            incident = await self.db.incidents.find_one({"id": incident_id}, {"_id": 0})
            if not incident:
                # Remove from queue if incident doesn't exist
                await self.db.incident_overflow_queue.delete_one({"id": queue_entry["id"]})
                continue
            
            result = await self.assign_incident(
                incident_id=incident_id,
                company_id=company_id,
                incident_data=incident
            )
            
            if result.get("success"):
                # Successfully assigned - remove from queue
                await self.db.incident_overflow_queue.delete_one({"id": queue_entry["id"]})
                processed += 1
                results.append({
                    "incident_id": incident_id,
                    "assigned_to": result.get("assigned_to"),
                    "status": "assigned"
                })
            else:
                # Still no available techs - stop processing
                break
        
        return {
            "success": True,
            "processed": processed,
            "remaining_in_queue": len(queued) - processed,
            "results": results
        }

