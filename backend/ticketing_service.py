"""
Ticketing System Integration Service
Supports: ServiceNow, Jira, Zendesk
"""

import httpx
import json
from typing import Optional, Dict, Any
from datetime import datetime
import os
import base64


class TicketingService:
    """Universal ticketing integration service"""
    
    def __init__(self):
        self.timeout = 30.0
        
    async def create_ticket(
        self,
        ticket_config: Dict[str, Any],
        incident: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Create ticket in external ticketing system
        
        Args:
            ticket_config: Ticketing system configuration
            incident: Incident data
            
        Returns:
            Ticket details with external_ticket_id
        """
        system_type = ticket_config.get('system_type')
        
        if system_type == 'servicenow':
            return await self._create_servicenow_ticket(ticket_config, incident)
        elif system_type == 'jira':
            return await self._create_jira_ticket(ticket_config, incident)
        elif system_type == 'zendesk':
            return await self._create_zendesk_ticket(ticket_config, incident)
        else:
            raise ValueError(f"Unsupported ticketing system: {system_type}")
    
    async def update_ticket(
        self,
        ticket_config: Dict[str, Any],
        external_ticket_id: str,
        incident: Dict[str, Any],
        update_type: str = "status_change"
    ) -> bool:
        """
        Update ticket in external ticketing system
        
        Args:
            ticket_config: Ticketing system configuration
            external_ticket_id: External ticket ID
            incident: Updated incident data
            update_type: Type of update (status_change, comment, resolution)
            
        Returns:
            Success status
        """
        system_type = ticket_config.get('system_type')
        
        if system_type == 'servicenow':
            return await self._update_servicenow_ticket(
                ticket_config, external_ticket_id, incident, update_type
            )
        elif system_type == 'jira':
            return await self._update_jira_ticket(
                ticket_config, external_ticket_id, incident, update_type
            )
        elif system_type == 'zendesk':
            return await self._update_zendesk_ticket(
                ticket_config, external_ticket_id, incident, update_type
            )
        else:
            return False
    
    # ===== ServiceNow Integration =====
    
    async def _create_servicenow_ticket(
        self,
        config: Dict[str, Any],
        incident: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create ServiceNow incident ticket"""
        try:
            url = f"{config['instance_url']}/api/now/table/incident"
            
            # Map priority score to ServiceNow priority
            priority = self._map_priority_to_servicenow(incident.get('priority_score', 50))
            
            # Map status
            state = self._map_status_to_servicenow(incident.get('status', 'new'))
            
            payload = {
                "short_description": f"{incident.get('signature', 'Unknown')} on {incident.get('asset_name', 'Unknown')}",
                "description": self._build_servicenow_description(incident),
                "priority": priority,
                "state": state,
                "urgency": priority,
                "impact": priority,
                "category": "Infrastructure",
                "subcategory": "Alert",
                "assignment_group": config.get('assignment_group', ''),
                "caller_id": config.get('caller_id', ''),
                "u_source": "Alert Whisperer",
                "u_incident_id": incident.get('id', '')
            }
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    url,
                    json=payload,
                    auth=(config['username'], config['password']),
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code in [200, 201]:
                    result = response.json()
                    ticket_data = result.get('result', {})
                    
                    return {
                        "external_ticket_id": ticket_data.get('sys_id'),
                        "ticket_number": ticket_data.get('number'),
                        "ticket_url": f"{config['instance_url']}/nav_to.do?uri=incident.do?sys_id={ticket_data.get('sys_id')}",
                        "system_type": "servicenow",
                        "created_at": datetime.utcnow().isoformat()
                    }
                else:
                    print(f"ServiceNow ticket creation failed: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            print(f"Error creating ServiceNow ticket: {e}")
            return None
    
    async def _update_servicenow_ticket(
        self,
        config: Dict[str, Any],
        ticket_id: str,
        incident: Dict[str, Any],
        update_type: str
    ) -> bool:
        """Update ServiceNow ticket"""
        try:
            url = f"{config['instance_url']}/api/now/table/incident/{ticket_id}"
            
            payload = {}
            
            if update_type == "status_change":
                payload["state"] = self._map_status_to_servicenow(incident.get('status', 'new'))
                
                if incident.get('status') == 'resolved':
                    payload["close_code"] = "Solved (Permanently)"
                    payload["close_notes"] = incident.get('resolution_notes', 'Resolved via Alert Whisperer')
                    
            elif update_type == "comment":
                payload["comments"] = f"Update from Alert Whisperer: {incident.get('last_comment', '')}"
                
            elif update_type == "assignment":
                # Could map technician to ServiceNow user
                payload["assigned_to"] = config.get('default_assignee', '')
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.patch(
                    url,
                    json=payload,
                    auth=(config['username'], config['password']),
                    headers={"Content-Type": "application/json"}
                )
                
                return response.status_code in [200, 201]
                
        except Exception as e:
            print(f"Error updating ServiceNow ticket: {e}")
            return False
    
    def _map_priority_to_servicenow(self, priority_score: int) -> str:
        """Map Alert Whisperer priority to ServiceNow priority"""
        if priority_score >= 100:
            return "1"  # Critical
        elif priority_score >= 60:
            return "2"  # High
        elif priority_score >= 30:
            return "3"  # Moderate
        else:
            return "4"  # Low
    
    def _map_status_to_servicenow(self, status: str) -> str:
        """Map Alert Whisperer status to ServiceNow state"""
        status_map = {
            "new": "1",          # New
            "in_progress": "2",  # In Progress
            "resolved": "6",     # Resolved
            "escalated": "2"     # In Progress
        }
        return status_map.get(status, "1")
    
    def _build_servicenow_description(self, incident: Dict[str, Any]) -> str:
        """Build detailed ServiceNow description"""
        desc = f"""
Alert Whisperer Incident Details:

Incident ID: {incident.get('id', 'N/A')}
Asset: {incident.get('asset_name', 'N/A')}
Signature: {incident.get('signature', 'N/A')}
Severity: {incident.get('severity', 'N/A')}
Priority Score: {incident.get('priority_score', 'N/A')}

Alert Count: {incident.get('alert_count', 0)}
Tool Sources: {', '.join(incident.get('tool_sources', []))}

Created At: {incident.get('created_at', 'N/A')}
Status: {incident.get('status', 'N/A')}

AI Insights:
{json.dumps(incident.get('metadata', {}).get('ai_analysis', {}), indent=2)}

Correlated Alerts:
{incident.get('alert_count', 0)} alerts correlated for this incident.
"""
        return desc.strip()
    
    # ===== Jira Integration =====
    
    async def _create_jira_ticket(
        self,
        config: Dict[str, Any],
        incident: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create Jira issue"""
        try:
            url = f"{config['instance_url']}/rest/api/3/issue"
            
            # Map priority
            priority = self._map_priority_to_jira(incident.get('priority_score', 50))
            
            payload = {
                "fields": {
                    "project": {"key": config['project_key']},
                    "summary": f"{incident.get('signature', 'Unknown')} on {incident.get('asset_name', 'Unknown')}",
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": self._build_jira_description(incident)
                                    }
                                ]
                            }
                        ]
                    },
                    "issuetype": {"name": config.get('issue_type', 'Task')},
                    "priority": {"name": priority},
                    "labels": ["alert-whisperer", incident.get('severity', 'unknown')]
                }
            }
            
            # Add assignee if configured
            if config.get('default_assignee'):
                payload["fields"]["assignee"] = {"accountId": config['default_assignee']}
            
            # Create auth header
            auth = base64.b64encode(
                f"{config['username']}:{config['api_token']}".encode()
            ).decode()
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers={
                        "Authorization": f"Basic {auth}",
                        "Content-Type": "application/json"
                    }
                )
                
                if response.status_code in [200, 201]:
                    result = response.json()
                    
                    return {
                        "external_ticket_id": result.get('id'),
                        "ticket_number": result.get('key'),
                        "ticket_url": f"{config['instance_url']}/browse/{result.get('key')}",
                        "system_type": "jira",
                        "created_at": datetime.utcnow().isoformat()
                    }
                else:
                    print(f"Jira ticket creation failed: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            print(f"Error creating Jira ticket: {e}")
            return None
    
    async def _update_jira_ticket(
        self,
        config: Dict[str, Any],
        ticket_id: str,
        incident: Dict[str, Any],
        update_type: str
    ) -> bool:
        """Update Jira issue"""
        try:
            # Create auth header
            auth = base64.b64encode(
                f"{config['username']}:{config['api_token']}".encode()
            ).decode()
            
            headers = {
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/json"
            }
            
            if update_type == "status_change":
                # Transition issue to new status
                status = incident.get('status', 'new')
                transition_id = self._map_status_to_jira_transition(status, config)
                
                if transition_id:
                    url = f"{config['instance_url']}/rest/api/3/issue/{ticket_id}/transitions"
                    payload = {"transition": {"id": transition_id}}
                    
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        response = await client.post(url, json=payload, headers=headers)
                        return response.status_code in [200, 201, 204]
                        
            elif update_type == "comment":
                url = f"{config['instance_url']}/rest/api/3/issue/{ticket_id}/comment"
                payload = {
                    "body": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": f"Update from Alert Whisperer: {incident.get('last_comment', '')}"
                                    }
                                ]
                            }
                        ]
                    }
                }
                
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(url, json=payload, headers=headers)
                    return response.status_code in [200, 201]
            
            return True
                
        except Exception as e:
            print(f"Error updating Jira ticket: {e}")
            return False
    
    def _map_priority_to_jira(self, priority_score: int) -> str:
        """Map Alert Whisperer priority to Jira priority"""
        if priority_score >= 100:
            return "Highest"
        elif priority_score >= 60:
            return "High"
        elif priority_score >= 30:
            return "Medium"
        else:
            return "Low"
    
    def _map_status_to_jira_transition(self, status: str, config: Dict[str, Any]) -> Optional[str]:
        """Map status to Jira transition ID"""
        # These are typical Jira transition IDs, but they vary by workflow
        # Users should configure these in their config
        transitions = config.get('transitions', {
            "in_progress": "21",  # In Progress
            "resolved": "31",     # Done
            "escalated": "21"     # In Progress
        })
        return transitions.get(status)
    
    def _build_jira_description(self, incident: Dict[str, Any]) -> str:
        """Build Jira description"""
        return f"""Alert Whisperer Incident

Incident ID: {incident.get('id', 'N/A')}
Asset: {incident.get('asset_name', 'N/A')}
Signature: {incident.get('signature', 'N/A')}
Severity: {incident.get('severity', 'N/A')}
Priority Score: {incident.get('priority_score', 'N/A')}

Alert Count: {incident.get('alert_count', 0)}
Tool Sources: {', '.join(incident.get('tool_sources', []))}

Status: {incident.get('status', 'N/A')}
Created: {incident.get('created_at', 'N/A')}
"""
    
    # ===== Zendesk Integration =====
    
    async def _create_zendesk_ticket(
        self,
        config: Dict[str, Any],
        incident: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create Zendesk ticket"""
        try:
            url = f"{config['subdomain']}.zendesk.com/api/v2/tickets"
            
            priority = self._map_priority_to_zendesk(incident.get('priority_score', 50))
            
            payload = {
                "ticket": {
                    "subject": f"{incident.get('signature', 'Unknown')} on {incident.get('asset_name', 'Unknown')}",
                    "comment": {
                        "body": self._build_zendesk_description(incident)
                    },
                    "priority": priority,
                    "status": "new",
                    "type": "incident",
                    "tags": ["alert-whisperer", incident.get('severity', 'unknown')],
                    "custom_fields": [
                        {"id": config.get('incident_id_field', ''), "value": incident.get('id', '')}
                    ]
                }
            }
            
            # Add assignee if configured
            if config.get('default_assignee_id'):
                payload["ticket"]["assignee_id"] = config['default_assignee_id']
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"https://{url}",
                    json=payload,
                    auth=(f"{config['email']}/token", config['api_token']),
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code in [200, 201]:
                    result = response.json()
                    ticket = result.get('ticket', {})
                    
                    return {
                        "external_ticket_id": str(ticket.get('id')),
                        "ticket_number": str(ticket.get('id')),
                        "ticket_url": f"https://{config['subdomain']}.zendesk.com/agent/tickets/{ticket.get('id')}",
                        "system_type": "zendesk",
                        "created_at": datetime.utcnow().isoformat()
                    }
                else:
                    print(f"Zendesk ticket creation failed: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            print(f"Error creating Zendesk ticket: {e}")
            return None
    
    async def _update_zendesk_ticket(
        self,
        config: Dict[str, Any],
        ticket_id: str,
        incident: Dict[str, Any],
        update_type: str
    ) -> bool:
        """Update Zendesk ticket"""
        try:
            url = f"https://{config['subdomain']}.zendesk.com/api/v2/tickets/{ticket_id}"
            
            payload = {"ticket": {}}
            
            if update_type == "status_change":
                status = self._map_status_to_zendesk(incident.get('status', 'new'))
                payload["ticket"]["status"] = status
                
                if status == "solved":
                    payload["ticket"]["comment"] = {
                        "body": f"Resolved via Alert Whisperer: {incident.get('resolution_notes', '')}"
                    }
                    
            elif update_type == "comment":
                payload["ticket"]["comment"] = {
                    "body": f"Update from Alert Whisperer: {incident.get('last_comment', '')}"
                }
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.put(
                    url,
                    json=payload,
                    auth=(f"{config['email']}/token", config['api_token']),
                    headers={"Content-Type": "application/json"}
                )
                
                return response.status_code in [200, 201]
                
        except Exception as e:
            print(f"Error updating Zendesk ticket: {e}")
            return False
    
    def _map_priority_to_zendesk(self, priority_score: int) -> str:
        """Map Alert Whisperer priority to Zendesk priority"""
        if priority_score >= 100:
            return "urgent"
        elif priority_score >= 60:
            return "high"
        elif priority_score >= 30:
            return "normal"
        else:
            return "low"
    
    def _map_status_to_zendesk(self, status: str) -> str:
        """Map Alert Whisperer status to Zendesk status"""
        status_map = {
            "new": "new",
            "in_progress": "open",
            "resolved": "solved",
            "escalated": "open"
        }
        return status_map.get(status, "new")
    
    def _build_zendesk_description(self, incident: Dict[str, Any]) -> str:
        """Build Zendesk description"""
        return f"""Alert Whisperer Incident

Incident ID: {incident.get('id', 'N/A')}
Asset: {incident.get('asset_name', 'N/A')}
Signature: {incident.get('signature', 'N/A')}
Severity: {incident.get('severity', 'N/A')}
Priority Score: {incident.get('priority_score', 'N/A')}

Alert Count: {incident.get('alert_count', 0)}
Tool Sources: {', '.join(incident.get('tool_sources', []))}

Status: {incident.get('status', 'N/A')}
Created: {incident.get('created_at', 'N/A')}

View in Alert Whisperer: [Link to incident]
"""


# Global instance
ticketing_service = TicketingService()
