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
            return {
                "success": False,
                "reason": "No available technicians match the requirements"
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
        
        Args:
            company_id: Company ID
            required_skills: Required skills
            target_technicians: Specific technician IDs (if any)
        
        Returns:
            List of available technician records
        """
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
