"""
Client Activity Tracking Service
Tracks all client activities, logins, and actions for MSP transparency
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field
import uuid


class ClientActivity(BaseModel):
    """Client activity log entry"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    activity_type: str  # login, logout, view_incident, view_alert, approve_runbook, etc.
    resource_type: Optional[str] = None  # incident, alert, runbook, report
    resource_id: Optional[str] = None
    description: str
    metadata: Dict[str, Any] = {}
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ClientSession(BaseModel):
    """Client login session tracking"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    company_id: str
    user_id: str
    user_email: str
    login_time: str
    logout_time: Optional[str] = None
    session_duration_minutes: Optional[int] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    active: bool = True


class ClientMetrics(BaseModel):
    """Client-specific metrics for tracking and reporting"""
    company_id: str
    total_logins: int = 0
    unique_users: int = 0
    active_sessions: int = 0
    incidents_viewed: int = 0
    incidents_updated: int = 0
    alerts_viewed: int = 0
    runbooks_approved: int = 0
    runbooks_rejected: int = 0
    reports_downloaded: int = 0
    average_session_duration_minutes: float = 0
    last_activity: Optional[str] = None
    period_start: str
    period_end: str


class ClientTrackingService:
    """Service for tracking all client activities and generating reports"""
    
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.activities = db.client_activities
        self.sessions = db.client_sessions
        
    async def log_activity(
        self,
        company_id: str,
        activity_type: str,
        description: str,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        user_name: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> ClientActivity:
        """Log a client activity"""
        activity = ClientActivity(
            company_id=company_id,
            user_id=user_id,
            user_email=user_email,
            user_name=user_name,
            activity_type=activity_type,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            metadata=metadata or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        await self.activities.insert_one(activity.model_dump())
        return activity
    
    async def start_session(
        self,
        company_id: str,
        user_id: str,
        user_email: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> ClientSession:
        """Start a new client session"""
        session = ClientSession(
            company_id=company_id,
            user_id=user_id,
            user_email=user_email,
            login_time=datetime.now(timezone.utc).isoformat(),
            ip_address=ip_address,
            user_agent=user_agent,
            active=True
        )
        
        await self.sessions.insert_one(session.model_dump())
        
        # Log login activity
        await self.log_activity(
            company_id=company_id,
            user_id=user_id,
            user_email=user_email,
            activity_type="login",
            description=f"User {user_email} logged in",
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return session
    
    async def end_session(self, session_id: str) -> Optional[ClientSession]:
        """End a client session"""
        session = await self.sessions.find_one({"id": session_id, "active": True})
        if not session:
            return None
        
        logout_time = datetime.now(timezone.utc)
        login_time = datetime.fromisoformat(session["login_time"])
        duration = (logout_time - login_time).total_seconds() / 60
        
        await self.sessions.update_one(
            {"id": session_id},
            {"$set": {
                "logout_time": logout_time.isoformat(),
                "session_duration_minutes": int(duration),
                "active": False
            }}
        )
        
        # Log logout activity
        await self.log_activity(
            company_id=session["company_id"],
            user_id=session["user_id"],
            user_email=session["user_email"],
            activity_type="logout",
            description=f"User {session['user_email']} logged out (session duration: {int(duration)} min)"
        )
        
        return await self.sessions.find_one({"id": session_id})
    
    async def get_activities(
        self,
        company_id: str,
        activity_type: Optional[str] = None,
        user_id: Optional[str] = None,
        days: int = 30,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get client activities with filters"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        query = {
            "company_id": company_id,
            "timestamp": {"$gte": cutoff.isoformat()}
        }
        
        if activity_type:
            query["activity_type"] = activity_type
        if user_id:
            query["user_id"] = user_id
        
        activities = await self.activities.find(query).sort("timestamp", -1).limit(limit).to_list(limit)
        return activities
    
    async def get_sessions(
        self,
        company_id: str,
        active_only: bool = False,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """Get client sessions"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        query = {
            "company_id": company_id,
            "login_time": {"$gte": cutoff.isoformat()}
        }
        
        if active_only:
            query["active"] = True
        
        sessions = await self.sessions.find(query).sort("login_time", -1).to_list(1000)
        return sessions
    
    async def get_metrics(self, company_id: str, days: int = 30) -> ClientMetrics:
        """Get client metrics for reporting"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        period_start = cutoff.isoformat()
        period_end = datetime.now(timezone.utc).isoformat()
        
        # Get sessions
        sessions = await self.sessions.find({
            "company_id": company_id,
            "login_time": {"$gte": period_start}
        }).to_list(10000)
        
        # Get activities
        activities = await self.activities.find({
            "company_id": company_id,
            "timestamp": {"$gte": period_start}
        }).to_list(10000)
        
        # Calculate metrics
        total_logins = len([s for s in sessions])
        unique_users = len(set([s["user_id"] for s in sessions]))
        active_sessions = len([s for s in sessions if s.get("active", False)])
        
        incidents_viewed = len([a for a in activities if a["activity_type"] == "view_incident"])
        incidents_updated = len([a for a in activities if a["activity_type"] == "update_incident"])
        alerts_viewed = len([a for a in activities if a["activity_type"] == "view_alert"])
        runbooks_approved = len([a for a in activities if a["activity_type"] == "approve_runbook"])
        runbooks_rejected = len([a for a in activities if a["activity_type"] == "reject_runbook"])
        reports_downloaded = len([a for a in activities if a["activity_type"] == "download_report"])
        
        # Average session duration
        completed_sessions = [s for s in sessions if s.get("session_duration_minutes")]
        avg_duration = sum([s["session_duration_minutes"] for s in completed_sessions]) / len(completed_sessions) if completed_sessions else 0
        
        # Last activity
        last_activity = activities[0]["timestamp"] if activities else None
        
        return ClientMetrics(
            company_id=company_id,
            total_logins=total_logins,
            unique_users=unique_users,
            active_sessions=active_sessions,
            incidents_viewed=incidents_viewed,
            incidents_updated=incidents_updated,
            alerts_viewed=alerts_viewed,
            runbooks_approved=runbooks_approved,
            runbooks_rejected=runbooks_rejected,
            reports_downloaded=reports_downloaded,
            average_session_duration_minutes=round(avg_duration, 1),
            last_activity=last_activity,
            period_start=period_start,
            period_end=period_end
        )
    
    async def get_user_activity_summary(self, company_id: str, user_id: str, days: int = 30) -> Dict[str, Any]:
        """Get activity summary for a specific user"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        activities = await self.activities.find({
            "company_id": company_id,
            "user_id": user_id,
            "timestamp": {"$gte": cutoff.isoformat()}
        }).to_list(10000)
        
        sessions = await self.sessions.find({
            "company_id": company_id,
            "user_id": user_id,
            "login_time": {"$gte": cutoff.isoformat()}
        }).to_list(10000)
        
        # Activity breakdown
        activity_counts = {}
        for activity in activities:
            activity_type = activity["activity_type"]
            activity_counts[activity_type] = activity_counts.get(activity_type, 0) + 1
        
        # Session stats
        total_sessions = len(sessions)
        completed_sessions = [s for s in sessions if s.get("session_duration_minutes")]
        avg_session_duration = sum([s["session_duration_minutes"] for s in completed_sessions]) / len(completed_sessions) if completed_sessions else 0
        
        return {
            "user_id": user_id,
            "company_id": company_id,
            "total_activities": len(activities),
            "activity_breakdown": activity_counts,
            "total_sessions": total_sessions,
            "average_session_duration_minutes": round(avg_session_duration, 1),
            "last_activity": activities[0]["timestamp"] if activities else None,
            "period_days": days
        }


# Initialize tracking service (will be set in server.py)
tracking_service: Optional[ClientTrackingService] = None
