"""Memory Service for Agent Core

Bedrock-Compatible Memory Pattern:
- sessionId: Short-term memory key (per incident/conversation)
- memoryId: Long-term memory key (per company/signature pattern)

This aligns with AWS Bedrock Agent Runtime memory model where:
- sessionId tracks individual incident conversations
- memoryId tracks company-wide resolution patterns
"""
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import uuid

class MemoryMessage(BaseModel):
    """Single message in conversation memory"""
    role: str  # user, agent, system
    content: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ShortTermMemory(BaseModel):
    """Short-term conversational memory (TTL 24-48h)
    
    Maps to Bedrock sessionId pattern:
    - session_id: incident_id (unique per incident conversation)
    - Used for tracking single incident resolution flow
    """
    session_id: str  # Bedrock-compatible: incident_id
    incident_id: str  # Legacy field for compatibility
    company_id: str
    memory_id: Optional[str] = None  # Link to long-term memory
    messages: List[MemoryMessage] = []
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class LongTermMemory(BaseModel):
    """Long-term resolution memory (indexed, searchable)
    
    Maps to Bedrock memoryId pattern:
    - memory_id: company_id or company_id|signature (pattern-based)
    - Used for retrieving similar past resolutions
    """
    memory_id: str  # Bedrock-compatible: company_id or company_id|signature
    company_id: str
    signature: str  # Alert signature for matching
    tags: List[str] = []  # Searchable tags
    resolution: str  # What was done
    outcome: str  # success, partial, failed
    runbook_used: Optional[str] = None
    incident_id: str
    session_id: Optional[str] = None  # Link to short-term memory
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class MemoryService:
    """Service for managing agent memory (short-term + long-term)"""
    
    def __init__(self, db):
        self.db = db
        self.short_memory = db["short_memory"]
        self.long_memory = db["long_memory"]
    
    async def add_short_term(self, incident_id: str, company_id: str, message: MemoryMessage):
        """Add message to short-term memory"""
        expires_at = datetime.now(timezone.utc) + timedelta(hours=48)
        
        await self.short_memory.update_one(
            {"incident_id": incident_id},
            {
                "$push": {"messages": message.dict()},
                "$set": {
                    "company_id": company_id,
                    "expires_at": expires_at
                },
                "$setOnInsert": {
                    "created_at": datetime.now(timezone.utc)
                }
            },
            upsert=True
        )
    
    async def get_short_term(self, incident_id: str) -> Optional[ShortTermMemory]:
        """Get short-term memory for incident"""
        doc = await self.short_memory.find_one({"incident_id": incident_id})
        if not doc:
            return None
        
        return ShortTermMemory(**doc)
    
    async def add_long_term(self, memory: LongTermMemory):
        """Add to long-term memory (indexed for search)"""
        await self.long_memory.insert_one(memory.dict())
    
    async def search_long_term(
        self,
        company_id: str,
        signature: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 10
    ) -> List[LongTermMemory]:
        """Search long-term memory"""
        query = {"company_id": company_id}
        
        if signature:
            query["signature"] = {"$regex": signature, "$options": "i"}
        
        if tags:
            query["tags"] = {"$in": tags}
        
        docs = await self.long_memory.find(query).sort(
            "created_at", -1
        ).limit(limit).to_list(length=limit)
        
        return [LongTermMemory(**doc) for doc in docs]
    
    async def get_recent_resolutions(
        self,
        company_id: str,
        limit: int = 5
    ) -> List[LongTermMemory]:
        """Get recent successful resolutions for context"""
        docs = await self.long_memory.find({
            "company_id": company_id,
            "outcome": "success"
        }).sort("created_at", -1).limit(limit).to_list(length=limit)
        
        return [LongTermMemory(**doc) for doc in docs]
    
    async def create_post_mortem(self, incident_id: str, company_id: str) -> LongTermMemory:
        """Create a post-mortem from incident and store in long-term memory"""
        # Get incident details
        incident = await self.db["incidents"].find_one({"id": incident_id})
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        
        # Get short-term memory (conversation)
        short_term = await self.get_short_term(incident_id)
        
        # Build resolution summary
        resolution = f"Resolved {incident.get('signature')} affecting {len(incident.get('alert_ids', []))} alerts. "
        
        if incident.get("auto_remediated"):
            resolution += f"Auto-remediated using runbook. "
        else:
            resolution += f"Manual resolution by technician. "
        
        # Extract tags
        tags = []
        signature = incident.get("signature", "unknown")
        if "disk" in signature.lower():
            tags.append("disk")
        if "memory" in signature.lower():
            tags.append("memory")
        if "cpu" in signature.lower():
            tags.append("cpu")
        tags.append(incident.get("severity", "unknown"))
        
        # Create long-term memory
        memory = LongTermMemory(
            company_id=company_id,
            signature=signature,
            tags=tags,
            resolution=resolution,
            outcome="success" if incident.get("status") == "resolved" else "partial",
            runbook_used=incident.get("runbook_id"),
            incident_id=incident_id
        )
        
        await self.add_long_term(memory)
        return memory
    
    async def clear_short_term(self, incident_id: str):
        """Clear short-term memory for incident"""
        await self.short_memory.delete_one({"incident_id": incident_id})
    
    async def get_memory_stats(self, company_id: str) -> Dict[str, Any]:
        """Get memory statistics for a company"""
        short_count = await self.short_memory.count_documents({"company_id": company_id})
        long_count = await self.long_memory.count_documents({"company_id": company_id})
        
        # Get outcome distribution
        pipeline = [
            {"$match": {"company_id": company_id}},
            {"$group": {"_id": "$outcome", "count": {"$sum": 1}}}
        ]
        outcomes = await self.long_memory.aggregate(pipeline).to_list(length=10)
        
        return {
            "short_term_count": short_count,
            "long_term_count": long_count,
            "outcomes": {o["_id"]: o["count"] for o in outcomes}
        }
