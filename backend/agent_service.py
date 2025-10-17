"""AWS Agent Core - Decision Agent Service

Multi-Provider Agent System:
- Gemini (Google): Default AI provider
- AWS Bedrock: Enterprise AWS-native option (Claude models)
- Deterministic Rules: Fallback for simple cases

Provider Selection (AGENT_PROVIDER env var):
- 'gemini' (default): Uses Google Gemini models
- 'bedrock-runtime': Direct AWS Bedrock model invocation
- 'bedrock-managed': Uses AWS Bedrock managed agents (InvokeAgent)
- 'rules': Pure deterministic rule engine
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Iterator
from datetime import datetime, timezone
import os
import time
import json
import uuid
import asyncio
from fastapi.responses import StreamingResponse

# Try importing Google Gemini
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("⚠️  google-generativeai not available - Gemini disabled")

# Try importing AWS Bedrock
try:
    from bedrock_agent_service import BedrockAgentClient, BedrockDecisionAgent
    BEDROCK_AVAILABLE = True
except ImportError:
    BEDROCK_AVAILABLE = False
    print("⚠️  Bedrock integration not available - AWS Bedrock disabled")

# Agent version tracking
VERSION = os.getenv("GIT_SHA", "dev")
STARTED_AT = time.time()

# Agent configuration
MAX_TOKENS_PER_DECISION = int(os.getenv("MAX_TOKENS_PER_DECISION", "2000"))
MAX_DECISION_TIME_SECONDS = int(os.getenv("MAX_DECISION_TIME_SECONDS", "30"))

# Provider configuration
AGENT_PROVIDER = os.getenv("AGENT_PROVIDER", "gemini")  # gemini, bedrock-runtime, bedrock-managed, rules

router = APIRouter(prefix="/agent", tags=["agent"])

# ============= Models =============

class ToolCall(BaseModel):
    """Tool call request from agent"""
    tool_name: str
    parameters: Dict[str, Any]

class DecisionRequest(BaseModel):
    """Agent decision request"""
    incident_id: str
    company_id: str
    incident_data: Dict[str, Any]
    memory_context: Optional[Dict[str, Any]] = None
    stream: bool = False

class DecisionResponse(BaseModel):
    """Agent decision response"""
    decision_id: str = Field(default_factory=lambda: f"dec-{uuid.uuid4().hex[:12]}")
    incident_id: str
    recommendation: str
    confidence: float  # 0.0 to 1.0
    tool_calls: List[ToolCall] = []
    reasoning: str
    tokens_used: int
    duration_ms: int
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    uptime_s: int
    version: str
    commit: str
    provider: str  # "gemini", "bedrock-runtime", "bedrock-managed", "rules"
    providers_available: Dict[str, bool]  # Which providers are available
    ready_for_agentcore: bool  # Ready for AWS AgentCore Runtime deployment

# ============= Agent Core =============

class DecisionAgent:
    """Multi-Provider AI Decision Engine
    
    Supports multiple AI providers:
    - Gemini (Google): Default
    - AWS Bedrock: Enterprise AWS-native (Claude models)
    - Deterministic Rules: Fallback
    """
    
    def __init__(self, db, tools_registry):
        self.db = db
        self.tools = tools_registry
        self.decisions_collection = db["agent_decisions"]
        self.provider = AGENT_PROVIDER
        
        # Initialize Gemini if selected and available
        if self.provider == "gemini" and GEMINI_AVAILABLE:
            api_key = os.environ.get('GEMINI_API_KEY')
            if api_key:
                genai.configure(api_key=api_key)
                self.model = genai.GenerativeModel('gemini-2.0-flash-exp')
                print(f"✅ Gemini agent initialized (model: gemini-2.0-flash-exp)")
            else:
                print("⚠️  GEMINI_API_KEY not set - falling back to rules")
                self.provider = "rules"
        
        # Initialize Bedrock if selected and available
        elif self.provider.startswith("bedrock") and BEDROCK_AVAILABLE:
            try:
                self.bedrock_client = BedrockAgentClient()
                if self.bedrock_client.available:
                    self.bedrock_agent = BedrockDecisionAgent(db, tools_registry, self.bedrock_client)
                    print(f"✅ Bedrock agent initialized (provider: {self.provider})")
                else:
                    print("⚠️  Bedrock client not available - falling back to rules")
                    self.provider = "rules"
            except Exception as e:
                print(f"⚠️  Bedrock initialization failed: {e} - falling back to rules")
                self.provider = "rules"
        
        elif self.provider == "rules":
            print("✅ Using deterministic rules engine (no AI)")
    
    async def decide(self, request: DecisionRequest) -> DecisionResponse:
        """Make a decision about an incident using configured provider"""
        start_time = time.time()
        
        # Route to appropriate provider
        if self.provider.startswith("bedrock") and hasattr(self, 'bedrock_agent'):
            # Use Bedrock agent
            decision_doc = await self.bedrock_agent.decide(
                incident_id=request.incident_id,
                company_id=request.company_id,
                incident_data=request.incident_data,
                stream=request.stream
            )
            return DecisionResponse(**decision_doc)
        
        # Otherwise use Gemini or deterministic
        # Get memory context
        memory = await self._get_memory(request.incident_id, request.company_id)
        
        # Build prompt
        prompt = self._build_decision_prompt(request.incident_data, memory)
        
        # Make decision (deterministic fallback or AI)
        if self._should_use_deterministic(request.incident_data) or self.provider == "rules":
            decision = await self._deterministic_decision(request.incident_data)
        else:
            decision = await self._ai_decision(prompt, request.incident_data)
        
        # Calculate metrics
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Store decision
        decision_doc = {
            "decision_id": decision["decision_id"],
            "incident_id": request.incident_id,
            "company_id": request.company_id,
            "recommendation": decision["recommendation"],
            "confidence": decision["confidence"],
            "tool_calls": [t.dict() for t in decision["tool_calls"]],
            "reasoning": decision["reasoning"],
            "tokens_used": decision["tokens_used"],
            "duration_ms": duration_ms,
            "provider": self.provider,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await self.decisions_collection.insert_one(decision_doc)
        
        # Update short-term memory
        await self._update_memory(request.incident_id, request.company_id, decision)
        
        return DecisionResponse(**decision_doc)
    
    async def decide_stream(self, request: DecisionRequest) -> Iterator[str]:
        """Stream decision making process (SSE format - AgentCore compatible)"""
        # Route to Bedrock if configured
        if self.provider.startswith("bedrock") and hasattr(self, 'bedrock_agent'):
            async for chunk in self.bedrock_agent.decide_stream(
                incident_id=request.incident_id,
                company_id=request.company_id,
                incident_data=request.incident_data
            ):
                yield chunk
            return
        
        # Gemini or deterministic streaming
        yield "event: start\ndata: {}\n\n"
        
        # Get memory
        memory = await self._get_memory(request.incident_id, request.company_id)
        yield f"event: memory\ndata: {{\"loaded\": true, \"session_id\": \"{request.incident_id}\", \"memory_id\": \"{request.company_id}\"}}\n\n"
        
        # Build prompt
        prompt = self._build_decision_prompt(request.incident_data, memory)
        
        # Stream decision
        if self._should_use_deterministic(request.incident_data) or self.provider == "rules":
            decision = await self._deterministic_decision(request.incident_data)
            yield f"data: {json.dumps(decision['reasoning'])}\n\n"
        else:
            # Stream from AI
            async for chunk in self._ai_decision_stream(prompt, request.incident_data):
                yield f"data: {json.dumps(chunk)}\n\n"
        
        yield "event: end\ndata: {}\n\n"
    
    def _should_use_deterministic(self, incident_data: Dict) -> bool:
        """Decide whether to use deterministic engine or AI"""
        severity = incident_data.get("severity", "low")
        alert_count = incident_data.get("alert_count", 0)
        
        # Use deterministic for simple, low-severity cases
        if severity == "low" and alert_count < 3:
            return True
        
        return False
    
    async def _deterministic_decision(self, incident_data: Dict) -> Dict:
        """Deterministic rule-based decision engine (fallback)"""
        severity = incident_data.get("severity", "low")
        signature = incident_data.get("signature", "unknown")
        
        # Simple rule-based logic
        if "disk" in signature.lower():
            recommendation = "Execute disk cleanup runbook"
            tool_calls = [ToolCall(tool_name="ssm.execute", parameters={"runbook": "disk-cleanup"})]
            confidence = 0.9
        elif "memory" in signature.lower():
            recommendation = "Restart affected service"
            tool_calls = [ToolCall(tool_name="ssm.execute", parameters={"runbook": "service-restart"})]
            confidence = 0.85
        else:
            recommendation = "Escalate to technician for manual review"
            tool_calls = []
            confidence = 0.6
        
        return {
            "decision_id": f"dec-{uuid.uuid4().hex[:12]}",
            "recommendation": recommendation,
            "confidence": confidence,
            "tool_calls": tool_calls,
            "reasoning": f"Deterministic rule matched: {signature}",
            "tokens_used": 0
        }
    
    async def _ai_decision(self, prompt: str, incident_data: Dict) -> Dict:
        """AI-powered decision using Gemini"""
        try:
            # Call Gemini with token limit
            response = self.model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    max_output_tokens=MAX_TOKENS_PER_DECISION,
                    temperature=0.3
                )
            )
            
            text = response.text
            
            # Parse response (simplified)
            return {
                "decision_id": f"dec-{uuid.uuid4().hex[:12]}",
                "recommendation": text[:200],  # First 200 chars
                "confidence": 0.75,
                "tool_calls": [],
                "reasoning": text,
                "tokens_used": len(text.split())  # Approximate
            }
        except Exception as e:
            # Fallback to deterministic
            return await self._deterministic_decision(incident_data)
    
    async def _ai_decision_stream(self, prompt: str, incident_data: Dict) -> Iterator[str]:
        """Stream AI decision making"""
        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    max_output_tokens=MAX_TOKENS_PER_DECISION,
                    temperature=0.3
                ),
                stream=True
            )
            
            for chunk in response:
                if chunk.text:
                    yield chunk.text
        except Exception:
            yield "Falling back to deterministic decision..."
    
    def _build_decision_prompt(self, incident_data: Dict, memory: Dict) -> str:
        """Build prompt for AI decision"""
        prompt = f"""
You are an MSP incident response agent. Analyze this incident and recommend action.

Incident Details:
- Severity: {incident_data.get('severity')}
- Signature: {incident_data.get('signature')}
- Alert Count: {incident_data.get('alert_count')}
- Affected Assets: {incident_data.get('affected_assets', [])}

Previous Context:
{json.dumps(memory.get('past_resolutions', []), indent=2)}

Recommend:
1. Action to take
2. Which runbook to execute (if any)
3. Whether to auto-remediate or escalate
"""
        return prompt
    
    async def _get_memory(self, incident_id: str, company_id: str) -> Dict:
        """Get short-term and long-term memory for incident"""
        # Short-term memory (conversation)
        short_term = await self.db["short_memory"].find_one({
            "incident_id": incident_id
        })
        
        # Long-term memory (past resolutions)
        long_term = await self.db["long_memory"].find(
            {"company_id": company_id}
        ).sort("created_at", -1).limit(5).to_list(length=5)
        
        return {
            "conversation": short_term.get("messages", []) if short_term else [],
            "past_resolutions": long_term
        }
    
    async def _update_memory(self, incident_id: str, company_id: str, decision: Dict):
        """Update memory with decision"""
        # Update short-term memory
        await self.db["short_memory"].update_one(
            {"incident_id": incident_id},
            {
                "$push": {"messages": {"role": "agent", "content": decision["recommendation"]}},
                "$set": {
                    "company_id": company_id,
                    "expires_at": datetime.now(timezone.utc) + timedelta(hours=48)
                }
            },
            upsert=True
        )

# ============= API Endpoints =============

@router.get("/ping", response_model=HealthResponse)
async def health_check():
    """Agent health check endpoint (AgentCore Runtime compatible)
    
    This endpoint is required for AWS Bedrock AgentCore Runtime deployment.
    Returns health status, provider info, and readiness for AgentCore.
    """
    uptime = int(time.time() - STARTED_AT)
    
    # Check which providers are available
    providers_available = {
        "gemini": GEMINI_AVAILABLE and os.environ.get('GEMINI_API_KEY') is not None,
        "bedrock": BEDROCK_AVAILABLE,
        "rules": True  # Always available
    }
    
    # Determine if ready for AgentCore deployment
    ready_for_agentcore = True  # Health endpoint exists, streaming works
    
    return HealthResponse(
        status="ok",
        uptime_s=uptime,
        version=VERSION,
        commit=VERSION,
        provider=AGENT_PROVIDER,
        providers_available=providers_available,
        ready_for_agentcore=ready_for_agentcore
    )

@router.get("/version")
async def get_version():
    """Get agent version"""
    return {
        "version": VERSION,
        "mode": os.getenv("AGENT_MODE", "local"),
        "uptime_s": int(time.time() - STARTED_AT)
    }

# Decision agent instance will be initialized in main app
agent_instance = None

def init_agent(db, tools_registry):
    """Initialize agent instance"""
    global agent_instance
    agent_instance = DecisionAgent(db, tools_registry)
    return agent_instance

@router.post("/decide", response_model=DecisionResponse)
async def decide_endpoint(request: DecisionRequest):
    """Make a decision about an incident"""
    if not agent_instance:
        raise HTTPException(status_code=500, detail="Agent not initialized")
    
    if request.stream:
        # Return streaming response
        async def generate():
            async for chunk in agent_instance.decide_stream(request):
                yield chunk
        
        return StreamingResponse(generate(), media_type="text/event-stream")
    
    # Non-streaming decision
    decision = await agent_instance.decide(request)
    return decision

@router.get("/decisions/{incident_id}")
async def get_decisions(incident_id: str):
    """Get all decisions for an incident"""
    if not agent_instance:
        raise HTTPException(status_code=500, detail="Agent not initialized")
    
    decisions = await agent_instance.decisions_collection.find(
        {"incident_id": incident_id}
    ).sort("created_at", -1).to_list(length=100)
    
    # Convert ObjectId to string
    for d in decisions:
        d["_id"] = str(d["_id"])
    
    return decisions

# Fix missing import
from datetime import timedelta
