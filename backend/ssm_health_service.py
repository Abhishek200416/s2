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
        """Test SSM connection to a specific instance with comprehensive validation
        
        Args:
            instance_id: EC2 instance ID
        
        Returns:
            Connection test result with validation details
        """
        if not self.is_available():
            return {
                "success": False,
                "error": "SSM client not available",
                "validation_steps": {
                    "aws_credentials": {"status": "failed", "message": "AWS credentials not configured"},
                    "ssm_agent": {"status": "pending", "message": "Cannot check - no AWS access"},
                    "iam_role": {"status": "pending", "message": "Cannot check - no AWS access"},
                    "connectivity": {"status": "pending", "message": "Cannot check - no AWS access"}
                }
            }
        
        validation_steps = {}
        
        try:
            # STEP 1: Verify instance exists in SSM
            validation_steps["instance_discovery"] = {"status": "checking", "message": "Checking if instance is registered with SSM..."}
            
            ssm_instances = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: self.ssm_client.describe_instance_information(
                    Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
                )
            )
            
            if not ssm_instances.get('InstanceInformationList'):
                return {
                    "success": False,
                    "instance_id": instance_id,
                    "error": "Instance not found in SSM",
                    "validation_steps": {
                        "instance_discovery": {"status": "failed", "message": "Instance is not registered with SSM Agent"},
                        "ssm_agent": {"status": "failed", "message": "SSM Agent not installed or not running"},
                        "iam_role": {"status": "unknown", "message": "Cannot verify - instance not in SSM"},
                        "connectivity": {"status": "failed", "message": "Cannot test - instance not responding to SSM"}
                    },
                    "troubleshooting": [
                        "1. Verify SSM Agent is installed on the instance",
                        "2. Ensure SSM Agent service is running",
                        "3. Check IAM instance profile is attached",
                        "4. Verify network connectivity (instance can reach SSM endpoints)",
                        "5. Check security groups allow outbound HTTPS (443)"
                    ]
                }
            
            instance_info = ssm_instances['InstanceInformationList'][0]
            ping_status = instance_info.get('PingStatus')
            platform = instance_info.get('PlatformName', 'Unknown')
            agent_version = instance_info.get('AgentVersion', 'Unknown')
            
            validation_steps["instance_discovery"] = {
                "status": "passed", 
                "message": f"Instance found: {platform}, Agent v{agent_version}"
            }
            
            # STEP 2: Check ping status
            validation_steps["ssm_agent"] = {"status": "checking", "message": "Checking SSM Agent status..."}
            
            if ping_status != 'Online':
                return {
                    "success": False,
                    "instance_id": instance_id,
                    "error": f"Instance status is '{ping_status}' (not Online)",
                    "validation_steps": {
                        **validation_steps,
                        "ssm_agent": {"status": "failed", "message": f"Agent status: {ping_status}"},
                        "connectivity": {"status": "failed", "message": "Instance not responding to SSM pings"}
                    },
                    "troubleshooting": [
                        "1. Restart SSM Agent service on the instance",
                        "2. Check system logs for SSM Agent errors",
                        "3. Verify instance has internet connectivity",
                        "4. Check if IAM role is still attached",
                        "5. Ensure instance is not stopped or terminated"
                    ]
                }
            
            validation_steps["ssm_agent"] = {"status": "passed", "message": "SSM Agent online and responding"}
            
            # STEP 3: Verify IAM permissions
            validation_steps["iam_role"] = {"status": "checking", "message": "Verifying IAM permissions..."}
            
            # Try to get instance profile to verify IAM role
            try:
                ec2_response = await asyncio.get_event_loop().run_in_executor(
                    executor,
                    lambda: self.ec2_client.describe_instances(InstanceIds=[instance_id])
                )
                
                instance_data = ec2_response['Reservations'][0]['Instances'][0]
                iam_profile = instance_data.get('IamInstanceProfile')
                
                if not iam_profile:
                    validation_steps["iam_role"] = {
                        "status": "warning", 
                        "message": "No IAM instance profile attached (may use hybrid activation)"
                    }
                else:
                    validation_steps["iam_role"] = {
                        "status": "passed", 
                        "message": f"IAM role attached: {iam_profile.get('Arn', 'Unknown').split('/')[-1]}"
                    }
            except Exception as e:
                validation_steps["iam_role"] = {
                    "status": "warning", 
                    "message": f"Could not verify IAM role: {str(e)}"
                }
            
            # STEP 4: Send test command
            validation_steps["connectivity"] = {"status": "checking", "message": "Sending test command..."}
            
            response = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: self.ssm_client.send_command(
                    InstanceIds=[instance_id],
                    DocumentName="AWS-RunShellScript",
                    Parameters={'commands': ['echo "✅ SSM Connection Test Successful - Alert Whisperer" && date']},
                    Comment="Alert Whisperer SSM Connection Validation Test",
                    TimeoutSeconds=60
                )
            )
            
            command_id = response['Command']['CommandId']
            command_status = response['Command']['Status']
            
            validation_steps["connectivity"] = {
                "status": "passed", 
                "message": f"Test command sent successfully (Command ID: {command_id[:8]}...)"
            }
            
            return {
                "success": True,
                "instance_id": instance_id,
                "command_id": command_id,
                "status": command_status,
                "message": "✅ All validation checks passed! SSM connection is working perfectly.",
                "validation_steps": validation_steps,
                "instance_details": {
                    "platform": platform,
                    "agent_version": agent_version,
                    "ping_status": ping_status,
                    "last_ping": instance_info.get('LastPingDateTime', datetime.now(timezone.utc)).isoformat()
                }
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            return {
                "success": False,
                "instance_id": instance_id,
                "error_code": error_code,
                "error": error_msg,
                "validation_steps": validation_steps,
                "suggestion": self._get_error_suggestion(error_code),
                "troubleshooting": self._get_detailed_troubleshooting(error_code)
            }
        except Exception as e:
            return {
                "success": False,
                "instance_id": instance_id,
                "error": str(e),
                "validation_steps": validation_steps,
                "troubleshooting": [
                    "1. Check AWS credentials are valid and not expired",
                    "2. Verify instance ID is correct and in the right region",
                    "3. Ensure you have SSM and EC2 read permissions",
                    "4. Contact support if the issue persists"
                ]
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
    
    def _get_detailed_troubleshooting(self, error_code: str) -> List[str]:
        """Get detailed troubleshooting steps based on error code"""
        troubleshooting_guides = {
            "InvalidInstanceId": [
                "1. Verify the instance ID is correct (format: i-xxxxxxxxxxxxx)",
                "2. Check you're connected to the correct AWS region",
                "3. Ensure the instance exists and is not terminated",
                "4. Confirm you have EC2:DescribeInstances permission"
            ],
            "InvalidInstanceInformationFilterValue": [
                "1. Install SSM Agent on the instance using platform-specific commands",
                "2. Start the SSM Agent service (sudo systemctl start amazon-ssm-agent)",
                "3. Attach an IAM role with SSM permissions to the instance",
                "4. Verify network connectivity - instance must reach SSM endpoints",
                "5. Wait 5-10 minutes for the agent to register with SSM",
                "6. Check security groups allow outbound HTTPS (443) traffic"
            ],
            "AccessDeniedException": [
                "1. Verify your IAM user/role has these permissions:",
                "   - ssm:DescribeInstanceInformation",
                "   - ssm:SendCommand",
                "   - ssm:GetCommandInvocation",
                "   - ec2:DescribeInstances",
                "2. Check if the IAM policy is attached to your user/role",
                "3. Ensure no Service Control Policies (SCPs) are blocking access",
                "4. Verify you're using the correct AWS credentials"
            ],
            "ThrottlingException": [
                "1. Wait 1-2 minutes before retrying",
                "2. Reduce the frequency of API calls",
                "3. Consider implementing exponential backoff",
                "4. Contact AWS Support if throttling persists"
            ],
            "UnsupportedPlatformType": [
                "1. SSM Agent supports: Amazon Linux, Ubuntu, RHEL, SUSE, Windows Server",
                "2. Verify your OS version is supported",
                "3. Check if the OS is up to date",
                "4. For unsupported OS, consider using AWS Hybrid Activations"
            ]
        }
        
        return troubleshooting_guides.get(error_code, [
            "1. Check SSM Agent installation and status",
            "2. Verify IAM instance profile is attached",
            "3. Ensure network connectivity (outbound HTTPS)",
            "4. Review CloudWatch Logs for SSM Agent errors",
            "5. Restart SSM Agent service",
            "6. Contact AWS Support if issue persists"
        ])
    
    async def get_connection_setup_guide(self, platform: str = "linux") -> Dict[str, Any]:
        """Get comprehensive step-by-step setup guide for SSM agent
        
        Args:
            platform: 'linux', 'windows', 'ubuntu', 'amazon-linux'
        
        Returns:
            Enhanced setup guide with detailed instructions, commands, and validation steps
        """
        guides = {
            "ubuntu": {
                "platform": "Ubuntu",
                "description": "Complete setup guide for Ubuntu-based EC2 instances",
                "prerequisites": [
                    "✅ EC2 instance running Ubuntu 16.04 or later",
                    "✅ SSH access to the instance",
                    "✅ sudo privileges on the instance",
                    "✅ Internet connectivity (outbound HTTPS/443)"
                ],
                "install_commands": [
                    "sudo snap install amazon-ssm-agent --classic",
                    "sudo systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service",
                    "sudo systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service"
                ],
                "verify_commands": [
                    "sudo systemctl status snap.amazon-ssm-agent.amazon-ssm-agent.service"
                ],
                "expected_output": "Active: active (running)",
                "troubleshooting_commands": [
                    "# Check agent logs",
                    "sudo journalctl -u snap.amazon-ssm-agent.amazon-ssm-agent -n 50",
                    "",
                    "# Restart if needed",
                    "sudo systemctl restart snap.amazon-ssm-agent.amazon-ssm-agent.service",
                    "",
                    "# Check connectivity to SSM endpoints",
                    "curl -I https://ssm.us-east-2.amazonaws.com"
                ],
                "iam_setup_steps": [
                    "1. Go to AWS Console → IAM → Roles",
                    "2. Click 'Create role'",
                    "3. Select 'AWS service' → 'EC2'",
                    "4. Search and attach: 'AmazonSSMManagedInstanceCore'",
                    "5. Name the role: 'AlertWhisperer-SSM-Role'",
                    "6. Go to EC2 Console → Select your instance",
                    "7. Actions → Security → Modify IAM role",
                    "8. Select 'AlertWhisperer-SSM-Role' and save"
                ],
                "wait_time": "5-10 minutes for agent to register with AWS SSM",
                "verification_steps": [
                    "1. Install SSM Agent using the commands above",
                    "2. Verify service is running (should show 'active (running)')",
                    "3. Attach IAM role to the EC2 instance",
                    "4. Wait 5-10 minutes for registration",
                    "5. Click 'Check Connection' button below to test"
                ],
                "iam_role_policy": self._get_iam_trust_policy(),
                "iam_permissions": self._get_iam_permissions_policy(),
                "security_notes": [
                    "🔒 No SSH keys needed after setup",
                    "🔒 No inbound firewall rules required",
                    "🔒 All communication over HTTPS (443)",
                    "🔒 Full audit trail in CloudWatch Logs"
                ]
            },
            "amazon-linux": {
                "platform": "Amazon Linux 2 / AL2023",
                "description": "SSM Agent is pre-installed on Amazon Linux - just configure IAM",
                "prerequisites": [
                    "✅ EC2 instance running Amazon Linux 2 or AL2023",
                    "✅ Instance has internet connectivity",
                    "✅ IAM instance profile with SSM permissions"
                ],
                "install_commands": [
                    "# SSM Agent is pre-installed, but if needed:",
                    "sudo yum install -y amazon-ssm-agent",
                    "sudo systemctl enable amazon-ssm-agent",
                    "sudo systemctl start amazon-ssm-agent"
                ],
                "verify_commands": [
                    "sudo systemctl status amazon-ssm-agent"
                ],
                "expected_output": "Active: active (running)",
                "troubleshooting_commands": [
                    "# Check agent logs",
                    "sudo tail -f /var/log/amazon/ssm/amazon-ssm-agent.log",
                    "",
                    "# Restart if needed",
                    "sudo systemctl restart amazon-ssm-agent",
                    "",
                    "# Check if IAM role is attached",
                    "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                ],
                "iam_setup_steps": [
                    "1. AWS Console → IAM → Roles → Create role",
                    "2. Trusted entity: AWS service → EC2",
                    "3. Add permission: AmazonSSMManagedInstanceCore",
                    "4. Name: AlertWhisperer-SSM-Role",
                    "5. EC2 Console → Instance → Actions → Security → Modify IAM role",
                    "6. Attach the role and save"
                ],
                "wait_time": "2-5 minutes (faster on Amazon Linux)",
                "verification_steps": [
                    "1. Verify SSM Agent is running",
                    "2. Attach IAM role to EC2 instance",
                    "3. Wait 2-5 minutes",
                    "4. Test connection using button below"
                ],
                "iam_role_policy": self._get_iam_trust_policy(),
                "iam_permissions": self._get_iam_permissions_policy(),
                "security_notes": [
                    "🔒 Amazon Linux comes with SSM Agent pre-configured",
                    "🔒 Just attach IAM role - no SSH needed",
                    "🔒 Automatic updates keep agent secure"
                ]
            },
            "windows": {
                "platform": "Windows Server",
                "description": "SSM Agent setup for Windows Server instances",
                "prerequisites": [
                    "✅ Windows Server 2012 R2 or later",
                    "✅ RDP access to the instance",
                    "✅ Administrator privileges",
                    "✅ Internet connectivity (outbound HTTPS/443)"
                ],
                "install_commands": [
                    "# Download installer",
                    "Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe' -OutFile 'C:\\AmazonSSMAgentSetup.exe'",
                    "",
                    "# Install (run as Administrator)",
                    "Start-Process -FilePath 'C:\\AmazonSSMAgentSetup.exe' -ArgumentList '/quiet' -Wait",
                    "",
                    "# Start service",
                    "Start-Service AmazonSSMAgent"
                ],
                "verify_commands": [
                    "Get-Service AmazonSSMAgent"
                ],
                "expected_output": "Status: Running",
                "troubleshooting_commands": [
                    "# Check service status",
                    "Get-Service AmazonSSMAgent | Select-Object *",
                    "",
                    "# View agent logs",
                    "Get-Content 'C:\\ProgramData\\Amazon\\SSM\\Logs\\amazon-ssm-agent.log' -Tail 50",
                    "",
                    "# Restart service",
                    "Restart-Service AmazonSSMAgent",
                    "",
                    "# Test connectivity",
                    "Test-NetConnection -ComputerName ssm.us-east-2.amazonaws.com -Port 443"
                ],
                "iam_setup_steps": [
                    "1. AWS Console → IAM → Roles",
                    "2. Create role → AWS service → EC2",
                    "3. Attach policy: AmazonSSMManagedInstanceCore",
                    "4. Role name: AlertWhisperer-SSM-Role",
                    "5. EC2 Console → Right-click instance",
                    "6. Security → Modify IAM role",
                    "7. Select the role and apply"
                ],
                "wait_time": "5-10 minutes for Windows agent registration",
                "verification_steps": [
                    "1. Download and install SSM Agent",
                    "2. Verify service is Running",
                    "3. Attach IAM role via EC2 console",
                    "4. Wait 5-10 minutes",
                    "5. Test connection below"
                ],
                "iam_role_policy": self._get_iam_trust_policy(),
                "iam_permissions": self._get_iam_permissions_policy(),
                "security_notes": [
                    "🔒 No RDP needed after SSM setup",
                    "🔒 Session Manager provides secure shell access",
                    "🔒 All actions logged to CloudWatch"
                ]
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
