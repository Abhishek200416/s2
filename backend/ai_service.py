"""AI Service for Alert Whisperer
Hybrid AI service with AWS Bedrock (primary) and Google Gemini (fallback)
Used for incident correlation, pattern detection, and alert classification
"""

import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import asyncio

# Import Bedrock service
from bedrock_agent_service import BedrockAgentClient, BOTO3_AVAILABLE

# Try importing Google Gemini
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("⚠️  google-generativeai not available - Gemini fallback disabled")


class HybridAIService:
    """Hybrid AI service with Bedrock primary and Gemini fallback"""
    
    def __init__(self):
        self.provider = os.getenv("AGENT_PROVIDER", "bedrock-runtime")
        self.bedrock_model_id = os.getenv("BEDROCK_MODEL_ID", "")
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "")
        
        # Initialize Bedrock
        self.bedrock_client = None
        if BOTO3_AVAILABLE and self.provider == "bedrock-runtime":
            try:
                self.bedrock_client = BedrockAgentClient()
                print("✅ AWS Bedrock initialized as primary AI provider")
            except Exception as e:
                print(f"⚠️  Bedrock initialization failed: {e}")
        
        # Initialize Gemini as fallback
        self.gemini_model = None
        if GEMINI_AVAILABLE and self.gemini_api_key:
            try:
                genai.configure(api_key=self.gemini_api_key)
                self.gemini_model = genai.GenerativeModel('gemini-1.5-pro')
                print("✅ Google Gemini initialized as fallback AI provider")
            except Exception as e:
                print(f"⚠️  Gemini initialization failed: {e}")
    
    async def analyze_with_ai(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """Analyze using AI with automatic fallback
        
        Args:
            prompt: The prompt to send to AI
            system_prompt: Optional system prompt
        
        Returns:
            Dict with 'content', 'provider', and 'success' keys
        """
        # Try Bedrock first
        if self.bedrock_client and self.bedrock_client.available:
            try:
                system_prompts = [{"text": system_prompt}] if system_prompt else None
                response = await self.bedrock_client.invoke_model(
                    model_id=self.bedrock_model_id,
                    prompt=prompt,
                    max_tokens=2000,
                    temperature=0.3,
                    system_prompts=system_prompts
                )
                return {
                    "content": response["content"],
                    "provider": "bedrock",
                    "model": self.bedrock_model_id,
                    "success": True,
                    "usage": response.get("usage", {})
                }
            except Exception as e:
                print(f"⚠️  Bedrock failed, falling back to Gemini: {e}")
        
        # Fallback to Gemini
        if self.gemini_model:
            try:
                full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
                response = await asyncio.to_thread(
                    self.gemini_model.generate_content,
                    full_prompt
                )
                return {
                    "content": response.text,
                    "provider": "gemini",
                    "model": "gemini-1.5-pro",
                    "success": True
                }
            except Exception as e:
                print(f"❌ Gemini also failed: {e}")
                return {
                    "content": "",
                    "provider": "none",
                    "success": False,
                    "error": str(e)
                }
        
        return {
            "content": "",
            "provider": "none",
            "success": False,
            "error": "No AI provider available"
        }
    
    async def classify_alert_severity(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Classify alert severity using AI (with rule-based pre-check)
        
        Args:
            alert: Alert data with message, asset_name, signature, etc.
        
        Returns:
            Dict with severity, confidence, reasoning
        """
        # Rule-based pre-classification (fast path)
        message = alert.get("message", "").lower()
        signature = alert.get("signature", "").lower()
        
        # High-confidence rule-based classification
        if any(word in message or word in signature for word in ["critical", "fatal", "disaster", "outage", "down"]):
            return {
                "severity": "critical",
                "confidence": 0.95,
                "reasoning": "Rule-based: Contains critical keywords",
                "method": "rule"
            }
        
        if any(word in message or word in signature for word in ["error", "failed", "failure", "exception"]):
            return {
                "severity": "high",
                "confidence": 0.85,
                "reasoning": "Rule-based: Contains error keywords",
                "method": "rule"
            }
        
        if any(word in message or word in signature for word in ["warning", "degraded", "slow"]):
            return {
                "severity": "medium",
                "confidence": 0.75,
                "reasoning": "Rule-based: Contains warning keywords",
                "method": "rule"
            }
        
        # If rule-based is uncertain, use AI
        system_prompt = """You are an expert MSP alert classifier. Classify the severity of alerts as: critical, high, medium, or low.

Critical: Service outages, data loss, security breaches, system failures
High: Performance degradation, errors affecting users, failed backups
Medium: Warnings, potential issues, configuration problems
Low: Informational, routine maintenance, minor issues

Respond in JSON format:
{
    "severity": "critical|high|medium|low",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}"""
        
        prompt = f"""Classify this alert:
Asset: {alert.get('asset_name', 'unknown')}
Signature: {alert.get('signature', 'unknown')}
Message: {alert.get('message', 'unknown')}
Tool: {alert.get('tool_source', 'unknown')}"""
        
        response = await self.analyze_with_ai(prompt, system_prompt)
        
        if response["success"]:
            try:
                result = json.loads(response["content"])
                result["method"] = f"ai-{response['provider']}"
                return result
            except json.JSONDecodeError:
                # Fallback if JSON parsing fails
                pass
        
        # Default fallback
        return {
            "severity": "medium",
            "confidence": 0.5,
            "reasoning": "Default: AI classification failed, using medium severity",
            "method": "fallback"
        }
    
    async def analyze_incident_patterns(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns across multiple alerts to detect incidents
        
        Args:
            alerts: List of related alerts
        
        Returns:
            Dict with pattern analysis, root cause suggestions, correlation insights
        """
        # Rule-based pattern detection (fast path)
        if len(alerts) <= 2:
            return {
                "pattern_detected": False,
                "confidence": 0.5,
                "root_cause": "Insufficient data for pattern analysis",
                "method": "rule"
            }
        
        # Group by asset and signature
        asset_groups = {}
        signature_groups = {}
        
        for alert in alerts:
            asset = alert.get("asset_name", "unknown")
            signature = alert.get("signature", "unknown")
            
            asset_groups[asset] = asset_groups.get(asset, 0) + 1
            signature_groups[signature] = signature_groups.get(signature, 0) + 1
        
        # Rule-based: Same asset + same signature = high correlation
        if len(asset_groups) == 1 and len(signature_groups) == 1:
            asset_name = list(asset_groups.keys())[0]
            return {
                "pattern_detected": True,
                "pattern_type": "single_asset_repeated",
                "confidence": 0.9,
                "root_cause": f"Repeated issue on asset '{asset_name}'",
                "recommendation": f"Investigate {asset_name} for persistent problems",
                "method": "rule"
            }
        
        # Use AI for complex pattern detection
        system_prompt = """You are an expert MSP incident analyst. Analyze multiple related alerts to:
1. Detect patterns and correlations
2. Suggest potential root causes
3. Recommend remediation actions

Respond in JSON format:
{
    "pattern_detected": true/false,
    "pattern_type": "cascade|storm|periodic|isolated",
    "confidence": 0.0-1.0,
    "root_cause": "likely root cause",
    "recommendation": "suggested action",
    "affected_assets": ["asset1", "asset2"]
}"""
        
        # Summarize alerts for AI
        alert_summary = []
        for i, alert in enumerate(alerts[:10]):  # Limit to 10 for token efficiency
            alert_summary.append(f"""
Alert {i+1}:
  Asset: {alert.get('asset_name', 'unknown')}
  Signature: {alert.get('signature', 'unknown')}
  Severity: {alert.get('severity', 'unknown')}
  Message: {alert.get('message', 'unknown')[:100]}
  Tool: {alert.get('tool_source', 'unknown')}
  Time: {alert.get('timestamp', 'unknown')}
""")
        
        prompt = f"""Analyze these {len(alerts)} correlated alerts:\n""" + "\n".join(alert_summary)
        
        response = await self.analyze_with_ai(prompt, system_prompt)
        
        if response["success"]:
            try:
                result = json.loads(response["content"])
                result["method"] = f"ai-{response['provider']}"
                return result
            except json.JSONDecodeError:
                pass
        
        # Fallback
        return {
            "pattern_detected": True,
            "pattern_type": "correlated",
            "confidence": 0.6,
            "root_cause": f"Multiple alerts detected across {len(asset_groups)} assets",
            "recommendation": "Investigate common infrastructure or dependencies",
            "method": "fallback"
        }
    
    async def suggest_remediation(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Suggest remediation actions for an incident
        
        Args:
            incident: Incident data with alerts, priority_score, etc.
        
        Returns:
            Dict with remediation suggestions, automation opportunities
        """
        # Rule-based suggestions for common patterns
        signature = incident.get("signature", "").lower()
        
        common_remediations = {
            "disk space": {
                "action": "Clean up disk space",
                "commands": ["df -h", "du -sh /* | sort -h", "docker system prune"],
                "automation": True
            },
            "high cpu": {
                "action": "Identify and kill high CPU process",
                "commands": ["top -b -n 1", "ps aux --sort=-%cpu | head -10"],
                "automation": False
            },
            "memory": {
                "action": "Check memory usage and restart services",
                "commands": ["free -m", "systemctl restart <service>"],
                "automation": True
            },
            "connection": {
                "action": "Check network connectivity",
                "commands": ["ping -c 4 8.8.8.8", "netstat -tuln"],
                "automation": False
            }
        }
        
        for pattern, remedy in common_remediations.items():
            if pattern in signature:
                return {
                    "suggestion": remedy["action"],
                    "commands": remedy["commands"],
                    "can_automate": remedy["automation"],
                    "confidence": 0.8,
                    "method": "rule"
                }
        
        # Use AI for complex remediation suggestions
        system_prompt = """You are an expert MSP technician. Suggest remediation actions for incidents.

Respond in JSON format:
{
    "suggestion": "primary remediation action",
    "commands": ["command1", "command2"],
    "can_automate": true/false,
    "risk_level": "low|medium|high",
    "estimated_time": "time estimate"
}"""
        
        prompt = f"""Suggest remediation for this incident:
Signature: {incident.get('signature', 'unknown')}
Priority Score: {incident.get('priority_score', 0)}
Tool Sources: {incident.get('tool_sources', [])}
Alert Count: {incident.get('alert_count', 0)}
Description: {incident.get('description', 'unknown')[:200]}"""
        
        response = await self.analyze_with_ai(prompt, system_prompt)
        
        if response["success"]:
            try:
                result = json.loads(response["content"])
                result["method"] = f"ai-{response['provider']}"
                return result
            except json.JSONDecodeError:
                pass
        
        # Default fallback
        return {
            "suggestion": "Manual investigation required",
            "commands": [],
            "can_automate": False,
            "risk_level": "medium",
            "method": "fallback"
        }


# Global AI service instance
ai_service = HybridAIService()
