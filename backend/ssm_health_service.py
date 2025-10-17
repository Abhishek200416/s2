"""SSM Agent Health Monitoring and Asset Inventory Service"""

import os
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, List, Optional
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

# Thread pool for blocking boto3 calls
executor = ThreadPoolExecutor(max_workers=5)


class SSMHealthService:
    """Service for monitoring SSM agent health and EC2 asset inventory"""
    
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "us-east-2")
        self.ssm_client = None
        self.ec2_client = None
        
        try:
            # Initialize SSM client
            self.ssm_client = boto3.client(
                'ssm',
                region_name=self.region,
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                aws_session_token=os.getenv("AWS_SESSION_TOKEN")
            )
            
            # Initialize EC2 client
            self.ec2_client = boto3.client(
                'ec2',
                region_name=self.region,
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                aws_session_token=os.getenv("AWS_SESSION_TOKEN")
            )
            
            print(f"✅ SSM Health Service initialized (region: {self.region})")
        except Exception as e:
            print(f"⚠️  SSM Health Service initialization failed: {e}")
    
    def is_available(self) -> bool:
        """Check if SSM and EC2 clients are available"""
        return self.ssm_client is not None and self.ec2_client is not None
    
    async def get_agent_health(self, company_tag: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get SSM agent health status for all instances
        
        Args:
            company_tag: Optional company tag to filter instances (e.g., "Company=acme-corp")
        
        Returns:
            List of instances with SSM agent health status
        """
        if not self.is_available():
            return []
        
        try:
            # Get SSM instance information
            response = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: self.ssm_client.describe_instance_information()
            )
            
            instances = []
            for info in response.get('InstanceInformationList', []):
                instance_data = {
                    "instance_id": info.get('InstanceId'),
                    "ping_status": info.get('PingStatus'),  # Online, ConnectionLost, Inactive
                    "last_ping": info.get('LastPingDateTime', datetime.now(timezone.utc)).isoformat(),
                    "platform_type": info.get('PlatformType'),  # Linux, Windows
                    "platform_name": info.get('PlatformName'),  # Ubuntu, Amazon Linux, Windows Server
                    "platform_version": info.get('PlatformVersion'),
                    "agent_version": info.get('AgentVersion'),
                    "ip_address": info.get('IPAddress'),
                    "computer_name": info.get('ComputerName'),
                    "is_online": info.get('PingStatus') == 'Online'
                }
                instances.append(instance_data)
            
            return instances
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            print(f"❌ SSM Agent Health Error ({error_code}): {error_msg}")
            return []
        except Exception as e:
            print(f"❌ SSM Agent Health Error: {str(e)}")
            return []
    
    async def get_asset_inventory(self, company_tag: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get EC2 asset inventory with SSM agent status
        
        Args:
            company_tag: Optional company tag to filter instances
        
        Returns:
            List of EC2 instances with detailed information
        """
        if not self.is_available():
            return []
        
        try:
            # Get all EC2 instances
            ec2_response = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: self.ec2_client.describe_instances()
            )
            
            # Get SSM agent status
            ssm_instances = await self.get_agent_health(company_tag)
            ssm_status_map = {inst['instance_id']: inst for inst in ssm_instances}
            
            assets = []
            for reservation in ec2_response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance.get('InstanceId')
                    
                    # Get tags
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    
                    # Check if SSM agent is installed and online
                    ssm_status = ssm_status_map.get(instance_id)
                    
                    asset_data = {
                        "instance_id": instance_id,
                        "instance_name": tags.get('Name', 'Unnamed'),
                        "instance_type": instance.get('InstanceType'),
                        "state": instance.get('State', {}).get('Name'),
                        "platform": instance.get('Platform', 'linux'),
                        "private_ip": instance.get('PrivateIpAddress'),
                        "public_ip": instance.get('PublicIpAddress'),
                        "availability_zone": instance.get('Placement', {}).get('AvailabilityZone'),
                        "launch_time": instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                        "tags": tags,
                        "ssm_agent_installed": ssm_status is not None,
                        "ssm_agent_online": ssm_status.get('is_online', False) if ssm_status else False,
                        "ssm_agent_version": ssm_status.get('agent_version') if ssm_status else None,
                        "ssm_last_ping": ssm_status.get('last_ping') if ssm_status else None,
                        "ssm_platform": ssm_status.get('platform_name') if ssm_status else None
                    }
                    assets.append(asset_data)
            
            return assets
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            print(f"❌ Asset Inventory Error ({error_code}): {error_msg}")
            return []
        except Exception as e:
            print(f"❌ Asset Inventory Error: {str(e)}")
            return []
    
    async def get_all_ssm_instances(self) -> List[Dict[str, Any]]:
        """Get all SSM-managed instances (used during onboarding)
        
        Returns:
            List of all instances with SSM agent
        """
        return await self.get_agent_health(company_tag=None)
    
    async def test_ssm_connection(self, instance_id: str) -> Dict[str, Any]:
        """Test SSM connection to a specific instance
        
        Args:
            instance_id: EC2 instance ID
        
        Returns:
            Connection test result
        """
        if not self.is_available():
            return {
                "success": False,
                "error": "SSM client not available"
            }
        
        try:
            # Try to send a simple test command
            response = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: self.ssm_client.send_command(
                    InstanceIds=[instance_id],
                    DocumentName="AWS-RunShellScript",
                    Parameters={'commands': ['echo "SSM Connection Test Successful"']},
                    Comment="Alert Whisperer SSM Connection Test",
                    TimeoutSeconds=60
                )
            )
            
            command_id = response['Command']['CommandId']
            
            return {
                "success": True,
                "instance_id": instance_id,
                "command_id": command_id,
                "status": response['Command']['Status'],
                "message": "SSM connection successful! Test command sent."
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            return {
                "success": False,
                "instance_id": instance_id,
                "error_code": error_code,
                "error": error_msg,
                "suggestion": self._get_error_suggestion(error_code)
            }
        except Exception as e:
            return {
                "success": False,
                "instance_id": instance_id,
                "error": str(e)
            }
    
    def _get_error_suggestion(self, error_code: str) -> str:
        """Get helpful suggestion based on error code"""
        suggestions = {
            "InvalidInstanceId": "Instance ID not found. Verify the instance exists and is in the correct region.",
            "InvalidInstanceInformationFilterValue": "Instance is not managed by SSM. Ensure SSM agent is installed and running.",
            "UnsupportedPlatformType": "Instance platform is not supported. SSM requires compatible OS.",
            "AccessDeniedException": "IAM permissions missing. Ensure the MSP IAM role has SSM permissions.",
            "ThrottlingException": "Too many requests. Wait a moment and try again."
        }
        return suggestions.get(error_code, "Check SSM agent installation and IAM permissions.")
    
    async def get_connection_setup_guide(self, platform: str = "linux") -> Dict[str, Any]:
        """Get step-by-step setup guide for SSM agent
        
        Args:
            platform: 'linux', 'windows', 'ubuntu', 'amazon-linux'
        
        Returns:
            Setup guide with commands and instructions
        """
        guides = {
            "ubuntu": {
                "platform": "Ubuntu",
                "install_commands": [
                    "sudo snap install amazon-ssm-agent --classic",
                    "sudo systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service",
                    "sudo systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service"
                ],
                "verify_commands": [
                    "sudo systemctl status snap.amazon-ssm-agent.amazon-ssm-agent.service"
                ],
                "iam_role_policy": self._get_iam_trust_policy(),
                "iam_permissions": self._get_iam_permissions_policy()
            },
            "amazon-linux": {
                "platform": "Amazon Linux",
                "install_commands": [
                    "sudo yum install -y amazon-ssm-agent",
                    "sudo systemctl enable amazon-ssm-agent",
                    "sudo systemctl start amazon-ssm-agent"
                ],
                "verify_commands": [
                    "sudo systemctl status amazon-ssm-agent"
                ],
                "iam_role_policy": self._get_iam_trust_policy(),
                "iam_permissions": self._get_iam_permissions_policy()
            },
            "windows": {
                "platform": "Windows Server",
                "install_commands": [
                    "Download SSM Agent installer from:",
                    "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe",
                    "Run the installer with Administrator privileges"
                ],
                "verify_commands": [
                    "Get-Service AmazonSSMAgent"
                ],
                "iam_role_policy": self._get_iam_trust_policy(),
                "iam_permissions": self._get_iam_permissions_policy()
            }
        }
        
        return guides.get(platform, guides["ubuntu"])
    
    def _get_iam_trust_policy(self) -> Dict[str, Any]:
        """Get IAM trust policy for EC2 instances"""
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
    
    def _get_iam_permissions_policy(self) -> Dict[str, Any]:
        """Get IAM permissions policy for SSM"""
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ssm:UpdateInstanceInformation",
                        "ssmmessages:CreateControlChannel",
                        "ssmmessages:CreateDataChannel",
                        "ssmmessages:OpenControlChannel",
                        "ssmmessages:OpenDataChannel",
                        "s3:GetEncryptionConfiguration"
                    ],
                    "Resource": "*"
                }
            ]
        }


# Initialize the service
ssm_health_service = SSMHealthService()
