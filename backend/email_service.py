"""Email Service using AWS SES for Technician Notifications
Sends email notifications for incident assignments, escalations, and updates
"""

import os
import boto3
from botocore.exceptions import ClientError
from typing import Dict, Any, List, Optional
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Thread pool for blocking boto3 calls
executor = ThreadPoolExecutor(max_workers=3)


class AWSEmailService:
    """AWS SES email service for technician notifications"""
    
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "us-east-2")
        self.sender_email = os.getenv("SES_SENDER_EMAIL", "alerts@alertwhisperer.com")
        self.ses_client = None
        
        try:
            self.ses_client = boto3.client(
                'ses',
                region_name=self.region,
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                aws_session_token=os.getenv("AWS_SESSION_TOKEN")
            )
            print(f"✅ AWS SES client initialized (region: {self.region})")
        except Exception as e:
            print(f"⚠️  AWS SES initialization failed: {e}")
    
    def is_available(self) -> bool:
        """Check if SES client is available"""
        return self.ses_client is not None
    
    async def send_incident_assignment_email(
        self,
        recipient_email: str,
        technician_name: str,
        incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send incident assignment notification email
        
        Args:
            recipient_email: Technician's email address
            technician_name: Technician's name
            incident_data: Incident details (id, description, priority, company, etc.)
        
        Returns:
            Dict with success status and message_id
        """
        if not self.is_available():
            return {
                "success": False,
                "error": "AWS SES not available"
            }
        
        subject = f"🔔 New Incident Assigned: {incident_data.get('title', 'Alert Incident')}"
        
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%); 
                          color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f8fafc; padding: 20px; border: 1px solid #e2e8f0; }}
                .incident-card {{ background: white; padding: 15px; border-radius: 8px; 
                                margin: 15px 0; border-left: 4px solid #0ea5e9; }}
                .priority-badge {{ display: inline-block; padding: 4px 12px; border-radius: 4px; 
                                 font-weight: bold; font-size: 12px; }}
                .priority-critical {{ background: #fee2e2; color: #991b1b; }}
                .priority-high {{ background: #fed7aa; color: #9a3412; }}
                .priority-medium {{ background: #fef3c7; color: #92400e; }}
                .priority-low {{ background: #e0e7ff; color: #3730a3; }}
                .footer {{ text-align: center; padding: 20px; color: #64748b; font-size: 12px; }}
                .btn {{ display: inline-block; padding: 12px 24px; background: #0ea5e9; 
                      color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>🚨 Alert Whisperer - Incident Assignment</h2>
                </div>
                <div class="content">
                    <p>Hi <strong>{technician_name}</strong>,</p>
                    <p>A new incident has been assigned to you and requires your attention.</p>
                    
                    <div class="incident-card">
                        <h3>{incident_data.get('title', 'Incident')}</h3>
                        <p><strong>Incident ID:</strong> {incident_data.get('id', 'N/A')}</p>
                        <p><strong>Company:</strong> {incident_data.get('company_name', 'N/A')}</p>
                        <p><strong>Priority Score:</strong> 
                            <span class="priority-badge priority-{incident_data.get('severity', 'medium')}">
                                {incident_data.get('priority_score', 0)}
                            </span>
                        </p>
                        <p><strong>Description:</strong><br>{incident_data.get('description', 'No description available')}</p>
                        <p><strong>Affected Assets:</strong> {', '.join(incident_data.get('affected_assets', ['N/A']))}</p>
                        <p><strong>Created:</strong> {incident_data.get('created_at', 'N/A')}</p>
                    </div>
                    
                    <p><strong>Action Required:</strong></p>
                    <ul>
                        <li>Review the incident details in Alert Whisperer dashboard</li>
                        <li>Investigate the root cause</li>
                        <li>Execute remediation runbooks if available</li>
                        <li>Update incident status and add notes</li>
                    </ul>
                    
                    <center>
                        <a href="{os.getenv('REACT_APP_BACKEND_URL', 'https://alertwhisperer.com').replace('/api', '')}/dashboard" 
                           class="btn">View Incident Dashboard</a>
                    </center>
                </div>
                <div class="footer">
                    <p>This is an automated notification from Alert Whisperer MSP Platform</p>
                    <p>Please do not reply to this email</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        Alert Whisperer - Incident Assignment
        
        Hi {technician_name},
        
        A new incident has been assigned to you:
        
        Incident ID: {incident_data.get('id', 'N/A')}
        Company: {incident_data.get('company_name', 'N/A')}
        Priority: {incident_data.get('priority_score', 0)}
        Description: {incident_data.get('description', 'No description')}
        Affected Assets: {', '.join(incident_data.get('affected_assets', ['N/A']))}
        Created: {incident_data.get('created_at', 'N/A')}
        
        Please log in to Alert Whisperer to view and handle this incident.
        
        ---
        Alert Whisperer MSP Platform
        """
        
        return await self._send_email(recipient_email, subject, html_body, text_body)
    
    async def send_escalation_email(
        self,
        recipient_email: str,
        technician_name: str,
        incident_data: Dict[str, Any],
        escalation_reason: str
    ) -> Dict[str, Any]:
        """Send incident escalation notification
        
        Args:
            recipient_email: Escalated technician/admin email
            technician_name: Recipient's name
            incident_data: Incident details
            escalation_reason: Why incident was escalated
        
        Returns:
            Dict with success status
        """
        subject = f"🔥 ESCALATED: {incident_data.get('title', 'Critical Incident')}"
        
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); 
                          color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                .content {{ background: #fef2f2; padding: 20px; border: 2px solid #dc2626; }}
                .escalation-badge {{ background: #dc2626; color: white; padding: 8px 16px; 
                                    border-radius: 4px; font-weight: bold; }}
                .footer {{ text-align: center; padding: 20px; color: #64748b; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>⚠️ ESCALATED INCIDENT - Immediate Attention Required</h2>
                </div>
                <div class="content">
                    <center><span class="escalation-badge">ESCALATED</span></center>
                    <p>Hi <strong>{technician_name}</strong>,</p>
                    <p><strong>Incident ID:</strong> {incident_data.get('id', 'N/A')}</p>
                    <p><strong>Escalation Reason:</strong> {escalation_reason}</p>
                    <p><strong>Company:</strong> {incident_data.get('company_name', 'N/A')}</p>
                    <p><strong>Description:</strong> {incident_data.get('description', 'N/A')}</p>
                    <p>This incident requires immediate attention. Please review and take action.</p>
                </div>
                <div class="footer">
                    <p>Alert Whisperer MSP Platform - Escalation Notification</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        ⚠️ ESCALATED INCIDENT
        
        Hi {technician_name},
        
        Incident {incident_data.get('id', 'N/A')} has been escalated to you.
        Reason: {escalation_reason}
        Company: {incident_data.get('company_name', 'N/A')}
        
        Please review immediately in Alert Whisperer dashboard.
        """
        
        return await self._send_email(recipient_email, subject, html_body, text_body)
    
    async def send_test_email(self, recipient_email: str) -> Dict[str, Any]:
        """Send a test email to verify SES configuration
        
        Args:
            recipient_email: Email address to send test email to
        
        Returns:
            Dict with success status
        """
        subject = "✅ Alert Whisperer - Email Notifications Configured"
        
        html_body = """
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #0ea5e9;">🎉 Email Notifications Working!</h2>
            <p>This is a test email from Alert Whisperer MSP Platform.</p>
            <p>Your AWS SES email service is configured correctly and ready to send notifications.</p>
            <hr style="border: 1px solid #e2e8f0; margin: 20px 0;">
            <p style="color: #64748b; font-size: 12px;">Alert Whisperer MSP Platform</p>
        </body>
        </html>
        """
        
        text_body = "Alert Whisperer - Email notifications are working correctly!"
        
        return await self._send_email(recipient_email, subject, html_body, text_body)
    
    async def _send_email(
        self,
        recipient: str,
        subject: str,
        html_body: str,
        text_body: str
    ) -> Dict[str, Any]:
        """Internal method to send email via AWS SES
        
        Args:
            recipient: Email address
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text email body
        
        Returns:
            Dict with success status and message_id
        """
        if not self.is_available():
            return {
                "success": False,
                "error": "AWS SES not available"
            }
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: self.ses_client.send_email(
                    Source=self.sender_email,
                    Destination={'ToAddresses': [recipient]},
                    Message={
                        'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                        'Body': {
                            'Html': {'Data': html_body, 'Charset': 'UTF-8'},
                            'Text': {'Data': text_body, 'Charset': 'UTF-8'}
                        }
                    }
                )
            )
            
            return {
                "success": True,
                "message_id": response['MessageId'],
                "recipient": recipient
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            
            # Provide helpful error messages
            if error_code == "MessageRejected":
                error_detail = "Email rejected. Verify sender email is verified in AWS SES."
            elif error_code == "AccessDenied":
                error_detail = "Access denied. Check AWS SES permissions."
            else:
                error_detail = f"{error_code}: {error_msg}"
            
            return {
                "success": False,
                "error": error_detail,
                "recipient": recipient
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to send email: {str(e)}",
                "recipient": recipient
            }


# Global email service instance
email_service = AWSEmailService()
