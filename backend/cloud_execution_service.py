"""Cloud Execution Service for Multi-Cloud Remote Automation
Supports AWS Systems Manager (SSM) and Azure Run Command
"""

import os
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, List, Optional
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json

# Thread pool for blocking boto3 calls
executor = ThreadPoolExecutor(max_workers=5)


class AWSSSMExecutor:
    """AWS Systems Manager Run Command executor"""
    
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "us-east-2")
        self.ssm_client = None
        try:
            self.ssm_client = boto3.client(
                'ssm',
                region_name=self.region,
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                aws_session_token=os.getenv("AWS_SESSION_TOKEN")
            )
            print(f"✅ AWS SSM client initialized (region: {self.region})")
        except Exception as e:
            print(f"⚠️  AWS SSM initialization failed: {e}")
    
    def is_available(self) -> bool:
        """Check if SSM client is available"""
        return self.ssm_client is not None
    
    async def execute_command(
        self,
        instance_ids: List[str],
        commands: List[str],
        document_name: str = "AWS-RunShellScript",
        comment: str = "Alert Whisperer Runbook Execution"
    ) -> Dict[str, Any]:
        """Execute command on EC2 instances via SSM
        
        Args:
            instance_ids: List of EC2 instance IDs
            commands: List of shell commands to execute
            document_name: SSM document name (AWS-RunShellScript or AWS-RunPowerShellScript)
            comment: Comment for the command execution
        
        Returns:
            Dict with command_id, status, and response data
        """
        if not self.is_available():
            return {
                "success": False,
                "error": "AWS SSM client not available",
                "provider": "aws_ssm"
            }
        
        try:
            # Execute command asynchronously
            response = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: self.ssm_client.send_command(
                    InstanceIds=instance_ids,
                    DocumentName=document_name,
                    Parameters={'commands': commands},
                    Comment=comment,
                    TimeoutSeconds=3600  # 1 hour timeout
                )
            )
            
            command_id = response['Command']['CommandId']
            
            return {
                "success": True,
                "command_id": command_id,
                "status": response['Command']['Status'],
                "provider": "aws_ssm",
                "instance_ids": instance_ids,
                "requested_at": response['Command']['RequestedDateTime'].isoformat()
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            return {
                "success": False,
                "error": f"AWS SSM Error ({error_code}): {error_msg}",
                "provider": "aws_ssm"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Execution failed: {str(e)}",
                "provider": "aws_ssm"
            }
    
    async def get_command_status(self, command_id: str, instance_id: Optional[str] = None) -> Dict[str, Any]:
        """Get command execution status and output
        
        Args:
            command_id: SSM command ID
            instance_id: Optional specific instance ID
        
        Returns:
            Dict with status, output, and error information
        """
        if not self.is_available():
            return {
                "success": False,
                "error": "AWS SSM client not available"
            }
        
        try:
            # Get command invocation details
            if instance_id:
                response = await asyncio.get_event_loop().run_in_executor(
                    executor,
                    lambda: self.ssm_client.get_command_invocation(
                        CommandId=command_id,
                        InstanceId=instance_id
                    )
                )
                
                return {
                    "success": True,
                    "command_id": command_id,
                    "instance_id": instance_id,
                    "status": response['Status'],
                    "status_details": response.get('StatusDetails', ''),
                    "output": response.get('StandardOutputContent', ''),
                    "error": response.get('StandardErrorContent', ''),
                    "exit_code": response.get('ResponseCode', -1)
                }
            else:
                # Get overall command status
                response = await asyncio.get_event_loop().run_in_executor(
                    executor,
                    lambda: self.ssm_client.list_command_invocations(
                        CommandId=command_id
                    )
                )
                
                invocations = []
                for inv in response.get('CommandInvocations', []):
                    invocations.append({
                        "instance_id": inv['InstanceId'],
                        "status": inv['Status'],
                        "status_details": inv.get('StatusDetails', '')
                    })
                
                return {
                    "success": True,
                    "command_id": command_id,
                    "invocations": invocations
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get command status: {str(e)}"
            }


class AzureRunCommandExecutor:
    """Azure Run Command executor"""
    
    def __init__(self):
        self.available = False
        # Azure credentials would be loaded from environment
        # For now, this is a placeholder for Azure support
        print("ℹ️  Azure Run Command support available (requires Azure credentials)")
    
    def is_available(self) -> bool:
        """Check if Azure client is available"""
        return self.available
    
    async def execute_command(
        self,
        resource_group: str,
        vm_name: str,
        commands: List[str],
        script_type: str = "bash"
    ) -> Dict[str, Any]:
        """Execute command on Azure VM
        
        Args:
            resource_group: Azure resource group name
            vm_name: VM name
            commands: List of commands to execute
            script_type: bash or powershell
        
        Returns:
            Dict with execution results
        """
        return {
            "success": False,
            "error": "Azure Run Command not yet configured. Please configure Azure credentials.",
            "provider": "azure_run_command"
        }


class CloudExecutionService:
    """Multi-cloud execution service manager"""
    
    def __init__(self):
        self.aws_executor = AWSSSMExecutor()
        self.azure_executor = AzureRunCommandExecutor()
        print("✅ Cloud Execution Service initialized")
    
    async def execute_runbook(
        self,
        cloud_provider: str,
        runbook_script: str,
        target_config: Dict[str, Any],
        script_type: str = "bash"
    ) -> Dict[str, Any]:
        """Execute runbook on specified cloud provider
        
        Args:
            cloud_provider: 'aws' or 'azure'
            runbook_script: Script content to execute
            target_config: Cloud-specific target configuration
            script_type: bash, powershell, or python
        
        Returns:
            Dict with execution results
        """
        if cloud_provider == "aws":
            if not self.aws_executor.is_available():
                return {
                    "success": False,
                    "error": "AWS SSM not available. Please configure AWS credentials.",
                    "provider": "aws_ssm"
                }
            
            instance_ids = target_config.get("instance_ids", [])
            if not instance_ids:
                return {
                    "success": False,
                    "error": "No instance IDs provided",
                    "provider": "aws_ssm"
                }
            
            # Determine SSM document based on script type
            document_name = "AWS-RunShellScript"
            if script_type == "powershell":
                document_name = "AWS-RunPowerShellScript"
            
            # Split script into commands
            commands = [runbook_script]
            
            return await self.aws_executor.execute_command(
                instance_ids=instance_ids,
                commands=commands,
                document_name=document_name,
                comment=target_config.get("comment", "Alert Whisperer Runbook")
            )
        
        elif cloud_provider == "azure":
            if not self.azure_executor.is_available():
                return {
                    "success": False,
                    "error": "Azure Run Command not available. Please configure Azure credentials.",
                    "provider": "azure_run_command"
                }
            
            resource_group = target_config.get("resource_group", "")
            vm_name = target_config.get("vm_name", "")
            
            if not resource_group or not vm_name:
                return {
                    "success": False,
                    "error": "Missing Azure VM configuration (resource_group, vm_name)",
                    "provider": "azure_run_command"
                }
            
            commands = [runbook_script]
            
            return await self.azure_executor.execute_command(
                resource_group=resource_group,
                vm_name=vm_name,
                commands=commands,
                script_type=script_type
            )
        
        else:
            return {
                "success": False,
                "error": f"Unsupported cloud provider: {cloud_provider}. Supported: aws, azure"
            }
    
    async def get_execution_status(
        self,
        cloud_provider: str,
        command_id: str,
        instance_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get execution status for a command
        
        Args:
            cloud_provider: 'aws' or 'azure'
            command_id: Cloud provider's command ID
            instance_id: Optional specific instance/VM ID
        
        Returns:
            Dict with status and output
        """
        if cloud_provider == "aws":
            return await self.aws_executor.get_command_status(command_id, instance_id)
        elif cloud_provider == "azure":
            return {
                "success": False,
                "error": "Azure status checking not yet implemented"
            }
        else:
            return {
                "success": False,
                "error": f"Unsupported cloud provider: {cloud_provider}"
            }


# Global service instance
cloud_execution_service = CloudExecutionService()
