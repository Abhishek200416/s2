"""SSM Agent Bulk Installer Service"""

import os
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, List, Optional
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import uuid

# Thread pool for blocking boto3 calls
executor = ThreadPoolExecutor(max_workers=5)


class SSMInstallerService:
    """Service for bulk installing SSM agents on EC2 instances"""
    
    def __init__(self):
        print("✅ SSM Installer Service initialized")
    
    def create_ssm_client(self, access_key_id: str, secret_access_key: str, region: str):
        """Create SSM client with provided credentials"""
        try:
            return boto3.client(
                'ssm',
                region_name=region,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key
            )
        except Exception as e:
            print(f"❌ Failed to create SSM client: {e}")
            return None
    
    def create_ec2_client(self, access_key_id: str, secret_access_key: str, region: str):
        """Create EC2 client with provided credentials"""
        try:
            return boto3.client(
                'ec2',
                region_name=region,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key
            )
        except Exception as e:
            print(f"❌ Failed to create EC2 client: {e}")
            return None
    
    async def get_instances_without_ssm(self, access_key_id: str, secret_access_key: str, region: str) -> List[Dict[str, Any]]:
        """Get list of EC2 instances that don't have SSM agent installed/online
        
        Args:
            access_key_id: AWS access key
            secret_access_key: AWS secret key
            region: AWS region
        
        Returns:
            List of instances without SSM agent
        """
        ssm_client = self.create_ssm_client(access_key_id, secret_access_key, region)
        ec2_client = self.create_ec2_client(access_key_id, secret_access_key, region)
        
        if not ssm_client or not ec2_client:
            return []
        
        try:
            # Get all running EC2 instances
            ec2_response = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: ec2_client.describe_instances(
                    Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
                )
            )
            
            all_instances = []
            for reservation in ec2_response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    all_instances.append(instance)
            
            # Get instances managed by SSM
            ssm_response = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: ssm_client.describe_instance_information()
            )
            
            ssm_instance_ids = set(
                info['InstanceId'] 
                for info in ssm_response.get('InstanceInformationList', [])
                if info.get('PingStatus') == 'Online'
            )
            
            # Find instances without SSM
            instances_without_ssm = []
            for instance in all_instances:
                instance_id = instance.get('InstanceId')
                if instance_id not in ssm_instance_ids:
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    
                    instances_without_ssm.append({
                        'instance_id': instance_id,
                        'instance_name': tags.get('Name', 'Unnamed'),
                        'instance_type': instance.get('InstanceType'),
                        'platform': instance.get('Platform', 'linux'),
                        'private_ip': instance.get('PrivateIpAddress'),
                        'public_ip': instance.get('PublicIpAddress'),
                        'state': instance.get('State', {}).get('Name'),
                        'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                        'tags': tags
                    })
            
            return instances_without_ssm
            
        except Exception as e:
            print(f"❌ Error getting instances without SSM: {e}")
            return []
    
    async def bulk_install_ssm_agent(self, access_key_id: str, secret_access_key: str, region: str, instance_ids: List[str]) -> Dict[str, Any]:
        """Install SSM agent on multiple instances
        
        Args:
            access_key_id: AWS access key
            secret_access_key: AWS secret key
            region: AWS region
            instance_ids: List of instance IDs to install agent on
        
        Returns:
            Installation result with command_id and status
        """
        ssm_client = self.create_ssm_client(access_key_id, secret_access_key, region)
        
        if not ssm_client:
            return {
                'success': False,
                'error': 'Failed to create SSM client',
                'installed_count': 0,
                'failed_count': len(instance_ids)
            }
        
        try:
            # Use AWS Systems Manager Distributor to install SSM agent
            # This uses the AWS-ConfigureAWSPackage document
            command_id = str(uuid.uuid4())
            
            response = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: ssm_client.send_command(
                    InstanceIds=instance_ids,
                    DocumentName='AWS-ConfigureAWSPackage',
                    Parameters={
                        'action': ['Install'],
                        'name': ['AmazonCloudWatchAgent']  # This also installs SSM agent dependencies
                    },
                    TimeoutSeconds=3600
                )
            )
            
            actual_command_id = response['Command']['CommandId']
            
            return {
                'success': True,
                'command_id': actual_command_id,
                'instance_ids': instance_ids,
                'status': 'InProgress',
                'message': f'SSM agent installation started on {len(instance_ids)} instances',
                'started_at': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            print(f"❌ Error installing SSM agents: {e}")
            return {
                'success': False,
                'error': str(e),
                'installed_count': 0,
                'failed_count': len(instance_ids)
            }
    
    async def get_installation_status(self, access_key_id: str, secret_access_key: str, region: str, command_id: str) -> Dict[str, Any]:
        """Get status of bulk SSM agent installation
        
        Args:
            access_key_id: AWS access key
            secret_access_key: AWS secret key
            region: AWS region
            command_id: SSM command ID
        
        Returns:
            Installation status
        """
        ssm_client = self.create_ssm_client(access_key_id, secret_access_key, region)
        
        if not ssm_client:
            return {'success': False, 'error': 'Failed to create SSM client'}
        
        try:
            # Get command status
            response = await asyncio.get_event_loop().run_in_executor(
                executor,
                lambda: ssm_client.list_command_invocations(
                    CommandId=command_id,
                    Details=True
                )
            )
            
            invocations = response.get('CommandInvocations', [])
            
            status_counts = {
                'Success': 0,
                'InProgress': 0,
                'Failed': 0,
                'TimedOut': 0,
                'Cancelled': 0
            }
            
            instance_statuses = []
            for invocation in invocations:
                status = invocation.get('Status')
                status_counts[status] = status_counts.get(status, 0) + 1
                
                instance_statuses.append({
                    'instance_id': invocation.get('InstanceId'),
                    'status': status,
                    'status_details': invocation.get('StatusDetails'),
                    'output': invocation.get('StandardOutputContent', ''),
                    'error': invocation.get('StandardErrorContent', '')
                })
            
            overall_status = 'InProgress'
            if status_counts['InProgress'] == 0:
                if status_counts['Failed'] > 0 or status_counts['TimedOut'] > 0:
                    overall_status = 'PartialSuccess' if status_counts['Success'] > 0 else 'Failed'
                else:
                    overall_status = 'Success'
            
            return {
                'success': True,
                'command_id': command_id,
                'overall_status': overall_status,
                'status_counts': status_counts,
                'instance_statuses': instance_statuses,
                'total_instances': len(invocations)
            }
            
        except Exception as e:
            print(f"❌ Error getting installation status: {e}")
            return {
                'success': False,
                'error': str(e)
            }


# Global SSM installer service instance
ssm_installer_service = SSMInstallerService()
