"""AWS Bedrock Agent Integration Service

Provides integration with AWS Bedrock for agent runtime capabilities:
- Bedrock Agent Runtime (managed agents with InvokeAgent)
- Bedrock Runtime (direct Claude model access)
- Streaming responses compatible with AgentCore
"""

import os
import json
import time
import uuid
from typing import Dict, Any, Optional, Iterator, AsyncIterator
from datetime import datetime, timezone
import asyncio

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    print("⚠️  boto3 not available - AWS Bedrock integration disabled")


class BedrockAgentClient:
    """AWS Bedrock Agent Runtime client for managed agents"""
    
    def __init__(self):
        if not BOTO3_AVAILABLE:
            raise RuntimeError("boto3 is required for Bedrock integration")
        
        # Initialize Bedrock clients
        self.region = os.getenv("AWS_REGION", "us-east-1")
        
        try:
            # Bedrock Agent Runtime (for InvokeAgent)
            self.agent_runtime = boto3.client(
                'bedrock-agent-runtime',
                region_name=self.region
            )
            
            # Bedrock Runtime (for direct model inference)
            self.bedrock_runtime = boto3.client(
                'bedrock-runtime',
                region_name=self.region
            )
            
            self.available = True
            print(f"✅ Bedrock clients initialized (region: {self.region})")
        except Exception as e:
            self.available = False
            print(f"⚠️  Bedrock client initialization failed: {e}")
    
    async def invoke_agent(
        self,
        agent_id: str,
        agent_alias_id: str,
        session_id: str,
        input_text: str,
        memory_id: Optional[str] = None,
        enable_trace: bool = False
    ) -> Dict[str, Any]:
        """Invoke a managed Bedrock agent
        
        Args:
            agent_id: Bedrock agent ID
            agent_alias_id: Agent alias ID (e.g., 'TSTALIASID' or 'DRAFT')
            session_id: Session identifier for short-term memory
            input_text: User/system input to the agent
            memory_id: Optional memory identifier for long-term context
            enable_trace: Enable trace for debugging
        
        Returns:
            Agent response with completion, trace, and session details
        """
        if not self.available:
            raise RuntimeError("Bedrock client not available")
        
        try:
            # Prepare request parameters
            request_params = {
                'agentId': agent_id,
                'agentAliasId': agent_alias_id,
                'sessionId': session_id,
                'inputText': input_text,
                'enableTrace': enable_trace
            }
            
            # Add memory ID if provided (for long-term context)
            if memory_id:
                request_params['memoryId'] = memory_id
            
            # Invoke agent (non-streaming)
            response = self.agent_runtime.invoke_agent(**request_params)
            
            # Parse response stream
            completion = ""
            trace_data = []
            
            for event in response.get('completion', []):
                if 'chunk' in event:
                    chunk_data = event['chunk']
                    if 'bytes' in chunk_data:
                        completion += chunk_data['bytes'].decode('utf-8')
                
                if 'trace' in event and enable_trace:
                    trace_data.append(event['trace'])
            
            return {
                "completion": completion,
                "session_id": session_id,
                "trace": trace_data if enable_trace else None,
                "response_metadata": response.get('ResponseMetadata', {})
            }
        
        except (ClientError, BotoCoreError) as e:
            error_msg = f"Bedrock Agent invocation failed: {str(e)}"
            print(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
    
    async def invoke_model(
        self,
        model_id: str,
        prompt: str,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        system_prompts: Optional[list] = None
    ) -> Dict[str, Any]:
        """Invoke Bedrock model directly (e.g., Claude)
        
        Args:
            model_id: Bedrock model ID (e.g., 'anthropic.claude-3-5-sonnet-20241022-v2:0')
            prompt: User prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            system_prompts: Optional system prompts
        
        Returns:
            Model response with content and metadata
        """
        if not self.available:
            raise RuntimeError("Bedrock client not available")
        
        try:
            # Prepare request body for Claude models
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
            
            # Add system prompts if provided
            if system_prompts:
                request_body["system"] = system_prompts
            
            # Invoke model
            response = self.bedrock_runtime.invoke_model(
                modelId=model_id,
                body=json.dumps(request_body)
            )
            
            # Parse response
            response_body = json.loads(response.get('body').read())
            
            # Extract content
            content = ""
            if 'content' in response_body:
                for item in response_body['content']:
                    if item.get('type') == 'text':
                        content += item.get('text', '')
            
            return {
                "content": content,
                "stop_reason": response_body.get('stop_reason'),
                "usage": response_body.get('usage', {}),
                "model_id": response_body.get('model'),
                "response_metadata": response.get('ResponseMetadata', {})
            }
        
        except (ClientError, BotoCoreError) as e:
            error_msg = f"Bedrock model invocation failed: {str(e)}"
            print(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
    
    async def invoke_model_stream(
        self,
        model_id: str,
        prompt: str,
        max_tokens: int = 2000,
        temperature: float = 0.3,
        system_prompts: Optional[list] = None
    ) -> AsyncIterator[str]:
        """Stream model responses (for low-latency UX)
        
        Args:
            model_id: Bedrock model ID
            prompt: User prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            system_prompts: Optional system prompts
        
        Yields:
            Text chunks as they arrive
        """
        if not self.available:
            raise RuntimeError("Bedrock client not available")
        
        try:
            # Prepare request body
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
            
            if system_prompts:
                request_body["system"] = system_prompts
            
            # Invoke model with streaming
            response = self.bedrock_runtime.invoke_model_with_response_stream(
                modelId=model_id,
                body=json.dumps(request_body)
            )
            
            # Stream chunks
            for event in response.get('body'):
                chunk = event.get('chunk')
                if chunk:
                    chunk_data = json.loads(chunk.get('bytes').decode())
                    
                    if chunk_data.get('type') == 'content_block_delta':
                        delta = chunk_data.get('delta', {})
                        if delta.get('type') == 'text_delta':
                            text = delta.get('text', '')
                            if text:
                                yield text
        
        except (ClientError, BotoCoreError) as e:
            error_msg = f"Bedrock streaming failed: {str(e)}"
            print(f"❌ {error_msg}")
            yield f"[ERROR: {error_msg}]"


class BedrockDecisionAgent:
    """Decision Agent using AWS Bedrock models"""
    
    def __init__(self, db, tools_registry, bedrock_client: BedrockAgentClient):
        self.db = db
        self.tools = tools_registry
        self.bedrock = bedrock_client
        self.decisions_collection = db["agent_decisions"]
        
        # Configuration from environment
        self.model_id = os.getenv(
            "BEDROCK_MODEL_ID",
            "anthropic.claude-3-5-sonnet-20241022-v2:0"  # Claude 3.5 Sonnet v2
        )
        self.use_managed_agent = os.getenv("USE_BEDROCK_MANAGED_AGENT", "false").lower() == "true"
        self.agent_id = os.getenv("BEDROCK_AGENT_ID", "")
        self.agent_alias_id = os.getenv("BEDROCK_AGENT_ALIAS_ID", "TSTALIASID")
    
    async def decide(
        self,
        incident_id: str,
        company_id: str,
        incident_data: Dict[str, Any],
        stream: bool = False
    ) -> Dict[str, Any]:
        """Make a decision using Bedrock
        
        Args:
            incident_id: Incident identifier (becomes sessionId)
            company_id: Company identifier (becomes memoryId)
            incident_data: Incident details
            stream: Whether to stream response
        
        Returns:
            Decision response with recommendation and reasoning
        """
        start_time = time.time()
        
        # Map to Bedrock memory pattern
        session_id = incident_id  # Short-term memory
        memory_id = company_id    # Long-term memory
        
        # Get memory context
        memory = await self._get_memory(session_id, memory_id)
        
        # Build prompt
        prompt = self._build_decision_prompt(incident_data, memory)
        
        # Make decision
        if self.use_managed_agent and self.agent_id:
            # Use managed Bedrock agent
            result = await self.bedrock.invoke_agent(
                agent_id=self.agent_id,
                agent_alias_id=self.agent_alias_id,
                session_id=session_id,
                input_text=prompt,
                memory_id=memory_id,
                enable_trace=True
            )
            
            completion = result["completion"]
            tokens_used = len(completion.split())  # Approximate
        else:
            # Use direct model invocation
            result = await self.bedrock.invoke_model(
                model_id=self.model_id,
                prompt=prompt,
                max_tokens=2000,
                temperature=0.3
            )
            
            completion = result["content"]
            tokens_used = result["usage"].get("output_tokens", 0)
        
        # Parse decision
        decision = self._parse_decision_response(completion, incident_data)
        decision["tokens_used"] = tokens_used
        
        # Calculate metrics
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Store decision
        decision_doc = {
            "decision_id": decision["decision_id"],
            "incident_id": incident_id,
            "company_id": company_id,
            "session_id": session_id,
            "memory_id": memory_id,
            "recommendation": decision["recommendation"],
            "confidence": decision["confidence"],
            "reasoning": decision["reasoning"],
            "tokens_used": tokens_used,
            "duration_ms": duration_ms,
            "provider": "bedrock",
            "model_id": self.model_id,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await self.decisions_collection.insert_one(decision_doc)
        
        # Update memory
        await self._update_memory(session_id, memory_id, decision)
        
        return decision_doc
    
    async def decide_stream(self, incident_id: str, company_id: str, incident_data: Dict[str, Any]) -> AsyncIterator[str]:
        """Stream decision making (SSE format)"""
        yield "event: start\ndata: {}\n\n"
        
        # Map to Bedrock memory pattern
        session_id = incident_id
        memory_id = company_id
        
        # Get memory
        memory = await self._get_memory(session_id, memory_id)
        yield f"event: memory\ndata: {{\"session_id\": \"{session_id}\", \"memory_id\": \"{memory_id}\"}}\n\n"
        
        # Build prompt
        prompt = self._build_decision_prompt(incident_data, memory)
        
        # Stream from Bedrock
        async for chunk in self.bedrock.invoke_model_stream(
            model_id=self.model_id,
            prompt=prompt,
            max_tokens=2000,
            temperature=0.3
        ):
            yield f"data: {json.dumps(chunk)}\n\n"
        
        yield "event: end\ndata: {}\n\n"
    
    def _build_decision_prompt(self, incident_data: Dict, memory: Dict) -> str:
        """Build prompt for Bedrock model"""
        prompt = f"""You are an MSP incident response agent. Analyze this incident and recommend action.

Incident Details:
- Severity: {incident_data.get('severity')}
- Signature: {incident_data.get('signature')}
- Alert Count: {incident_data.get('alert_count')}
- Affected Assets: {incident_data.get('affected_assets', [])}
- Priority Score: {incident_data.get('priority_score', 0)}

Previous Context:
{json.dumps(memory.get('past_resolutions', []), indent=2)}

Provide a concise recommendation in this format:
1. RECOMMENDATION: [Action to take]
2. CONFIDENCE: [0.0-1.0]
3. REASONING: [Why this action]
4. RUNBOOK: [If applicable, which runbook to execute]
"""
        return prompt
    
    def _parse_decision_response(self, completion: str, incident_data: Dict) -> Dict:
        """Parse Bedrock model response into decision structure"""
        # Simple parsing - extract recommendation, confidence, reasoning
        lines = completion.split('\n')
        
        recommendation = ""
        confidence = 0.75
        reasoning = completion
        
        for line in lines:
            if 'RECOMMENDATION:' in line.upper():
                recommendation = line.split(':', 1)[1].strip()
            elif 'CONFIDENCE:' in line.upper():
                try:
                    conf_str = line.split(':', 1)[1].strip()
                    confidence = float(conf_str)
                except:
                    pass
        
        if not recommendation:
            recommendation = completion[:200]  # First 200 chars
        
        return {
            "decision_id": f"dec-{uuid.uuid4().hex[:12]}",
            "recommendation": recommendation,
            "confidence": confidence,
            "reasoning": reasoning
        }
    
    async def _get_memory(self, session_id: str, memory_id: str) -> Dict:
        """Get memory context (Bedrock-compatible format)
        
        Args:
            session_id: Short-term memory key (incident-specific)
            memory_id: Long-term memory key (company-specific)
        """
        # Short-term memory (per incident/session)
        short_term = await self.db["short_memory"].find_one({
            "session_id": session_id
        })
        
        # Long-term memory (per company)
        long_term = await self.db["long_memory"].find(
            {"memory_id": memory_id}
        ).sort("created_at", -1).limit(5).to_list(length=5)
        
        return {
            "conversation": short_term.get("messages", []) if short_term else [],
            "past_resolutions": long_term
        }
    
    async def _update_memory(self, session_id: str, memory_id: str, decision: Dict):
        """Update memory with decision"""
        from datetime import timedelta
        
        # Update short-term memory (session-based)
        await self.db["short_memory"].update_one(
            {"session_id": session_id},
            {
                "$push": {"messages": {"role": "agent", "content": decision["recommendation"]}},
                "$set": {
                    "memory_id": memory_id,
                    "expires_at": datetime.now(timezone.utc) + timedelta(hours=48)
                }
            },
            upsert=True
        )
        
        # Update long-term memory (company-based patterns)
        await self.db["long_memory"].insert_one({
            "memory_id": memory_id,
            "session_id": session_id,
            "decision_id": decision["decision_id"],
            "recommendation": decision["recommendation"],
            "confidence": decision["confidence"],
            "created_at": datetime.now(timezone.utc).isoformat()
        })
