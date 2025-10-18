"""On-Call Scheduling Service for MSP Technicians"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from motor.motor_asyncio import AsyncIOMotorClient
import os


class OnCallService:
    """Service for managing on-call schedules for MSP technicians"""
    
    def __init__(self, db):
        self.db = db
        print("✅ On-Call Service initialized")
    
    async def get_current_on_call_technician(self, company_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get the technician who is currently on-call
        
        Args:
            company_id: Optional company filter (for company-specific schedules)
        
        Returns:
            Technician dict or None
        """
        now = datetime.now(timezone.utc)
        current_weekday = now.weekday()  # 0=Monday, 6=Sunday
        current_time = now.time()
        current_iso = now.isoformat()
        
        # Build query for active schedules
        query = {
            "enabled": True,
            "$or": [
                # One-time schedules
                {
                    "schedule_type": "one_time",
                    "start_time": {"$lte": current_iso},
                    "end_time": {"$gte": current_iso}
                },
                # Recurring daily schedules
                {
                    "schedule_type": "daily",
                    "$expr": {
                        "$and": [
                            {"$lte": [{"$substr": ["$start_time", 11, 8]}, current_time.strftime("%H:%M:%S")]},
                            {"$gte": [{"$substr": ["$end_time", 11, 8]}, current_time.strftime("%H:%M:%S")]}
                        ]
                    }
                },
                # Recurring weekly schedules
                {
                    "schedule_type": "weekly",
                    "days_of_week": current_weekday,
                    "$expr": {
                        "$and": [
                            {"$lte": [{"$substr": ["$start_time", 11, 8]}, current_time.strftime("%H:%M:%S")]},
                            {"$gte": [{"$substr": ["$end_time", 11, 8]}, current_time.strftime("%H:%M:%S")]}
                        ]
                    }
                }
            ]
        }
        
        # Add company filter if provided
        if company_id:
            query["company_id"] = company_id
        
        # Find matching schedule with highest priority
        schedule = await self.db.on_call_schedules.find_one(
            query,
            {"_id": 0},
            sort=[("priority", -1)]  # Higher priority schedules take precedence
        )
        
        if not schedule:
            return None
        
        # Get the technician
        technician = await self.db.users.find_one(
            {"id": schedule["technician_id"]},
            {"_id": 0, "password_hash": 0}
        )
        
        if technician:
            technician["schedule_id"] = schedule["id"]
            technician["schedule_name"] = schedule.get("name", "On-Call")
        
        return technician
    
    async def get_on_call_schedule(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Get on-call schedule for a date range
        
        Args:
            start_date: Start of date range
            end_date: End of date range
        
        Returns:
            List of schedule entries
        """
        schedules = await self.db.on_call_schedules.find(
            {
                "enabled": True,
                "$or": [
                    # One-time schedules in range
                    {
                        "schedule_type": "one_time",
                        "start_time": {"$lte": end_date.isoformat()},
                        "end_time": {"$gte": start_date.isoformat()}
                    },
                    # Recurring schedules (always show if enabled)
                    {
                        "schedule_type": {"$in": ["daily", "weekly"]}
                    }
                ]
            },
            {"_id": 0}
        ).to_list(1000)
        
        # Enrich with technician info
        for schedule in schedules:
            technician = await self.db.users.find_one(
                {"id": schedule["technician_id"]},
                {"_id": 0, "password_hash": 0}
            )
            if technician:
                schedule["technician_name"] = technician.get("name")
                schedule["technician_email"] = technician.get("email")
        
        return schedules
    
    async def is_technician_available(self, technician_id: str, start_time: datetime, end_time: datetime) -> bool:
        """Check if a technician has no conflicting schedules
        
        Args:
            technician_id: Technician user ID
            start_time: Schedule start time
            end_time: Schedule end time
        
        Returns:
            True if available, False if conflict exists
        """
        conflict = await self.db.on_call_schedules.find_one({
            "technician_id": technician_id,
            "enabled": True,
            "$or": [
                # Overlapping one-time schedules
                {
                    "schedule_type": "one_time",
                    "start_time": {"$lt": end_time.isoformat()},
                    "end_time": {"$gt": start_time.isoformat()}
                },
                # Daily schedules always conflict during their time window
                {"schedule_type": "daily"},
                # Weekly schedules on same day
                {
                    "schedule_type": "weekly",
                    "days_of_week": start_time.weekday()
                }
            ]
        })
        
        return conflict is None


# Global on-call service instance (will be initialized with db)
oncall_service = None


def init_oncall_service(db):
    """Initialize on-call service with database connection"""
    global oncall_service
    oncall_service = OnCallService(db)
    return oncall_service
