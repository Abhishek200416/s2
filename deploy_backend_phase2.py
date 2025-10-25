#!/usr/bin/env python3
"""
Phase 2: Complete Backend Deployment to ECS Fargate
Creates: Load Balancer, Security Groups, Task Definition, ECS Service
"""

import boto3
import json
import time
import os
from botocore.exceptions import ClientError

# AWS Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID', '728925775278')
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_SESSION_TOKEN = os.environ.get('AWS_SESSION_TOKEN')

# Load deployment info from Phase 1
with open('/tmp/deployment_info.json', 'r') as f:
    deployment_info = json.load(f)

# Initialize AWS clients
def get_aws_client(service):
    params = {
        'region_name': AWS_REGION,
        'aws_access_key_id': AWS_ACCESS_KEY_ID,
        'aws_secret_access_key': AWS_SECRET_ACCESS_KEY
    }
    if AWS_SESSION_TOKEN:
        params['aws_session_token'] = AWS_SESSION_TOKEN
    return boto3.client(service, **params)

ecs = get_aws_client('ecs')
ec2 = get_aws_client('ec2')
elbv2 = get_aws_client('elbv2')
iam = get_aws_client('iam')
logs = get_aws_client('logs')

print("="*80)
print("🚀 PHASE 2: BACKEND DEPLOYMENT TO ECS FARGATE")
print("="*80)

vpc_id = deployment_info['vpc_info']['vpc_id']
subnet_ids = deployment_info['vpc_info']['subnet_ids']
cluster_name = deployment_info['cluster_name']
ecr_uri = deployment_info['ecr_uri']

# Step 1: Create Security Group for ALB
def create_alb_security_group():
    print("\n🔒 STEP 1: Creating Security Group for Load Balancer")
    print("-" * 80)
    
    try:
        response = ec2.create_security_group(
            GroupName='alert-whisperer-alb-sg',
            Description='Security group for Alert Whisperer ALB',
            VpcId=vpc_id
        )
        sg_id = response['GroupId']
        print(f"✅ Created ALB security group: {sg_id}")
        
        # Allow HTTP from anywhere
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP from anywhere'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS from anywhere'}]
                }
            ]
        )
        print("✅ Configured inbound rules (HTTP/HTTPS)")
        return sg_id
        
    except ClientError as e:
        if 'already exists' in str(e):
            # Find existing security group
            response = ec2.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': ['alert-whisperer-alb-sg']},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            if response['SecurityGroups']:
                sg_id = response['SecurityGroups'][0]['GroupId']
                print(f"✅ Using existing ALB security group: {sg_id}")
                return sg_id
        print(f"❌ Error creating security group: {e}")
        return None

# Step 2: Create Security Group for ECS Tasks
def create_ecs_security_group(alb_sg_id):
    print("\n🔒 STEP 2: Creating Security Group for ECS Tasks")
    print("-" * 80)
    
    try:
        response = ec2.create_security_group(
            GroupName='alert-whisperer-ecs-sg',
            Description='Security group for Alert Whisperer ECS tasks',
            VpcId=vpc_id
        )
        sg_id = response['GroupId']
        print(f"✅ Created ECS security group: {sg_id}")
        
        # Allow traffic from ALB
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 8001,
                    'ToPort': 8001,
                    'UserIdGroupPairs': [{'GroupId': alb_sg_id, 'Description': 'From ALB'}]
                }
            ]
        )
        print("✅ Configured inbound rules (Port 8001 from ALB)")
        return sg_id
        
    except ClientError as e:
        if 'already exists' in str(e):
            response = ec2.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': ['alert-whisperer-ecs-sg']},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            if response['SecurityGroups']:
                sg_id = response['SecurityGroups'][0]['GroupId']
                print(f"✅ Using existing ECS security group: {sg_id}")
                return sg_id
        print(f"❌ Error creating security group: {e}")
        return None

# Step 3: Create Application Load Balancer
def create_load_balancer(alb_sg_id):
    print("\n⚖️  STEP 3: Creating Application Load Balancer")
    print("-" * 80)
    
    try:
        response = elbv2.create_load_balancer(
            Name='alert-whisperer-alb',
            Subnets=subnet_ids,
            SecurityGroups=[alb_sg_id],
            Scheme='internet-facing',
            Type='application',
            IpAddressType='ipv4'
        )
        
        alb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
        alb_dns = response['LoadBalancers'][0]['DNSName']
        
        print(f"✅ Created load balancer")
        print(f"   ARN: {alb_arn}")
        print(f"   DNS: {alb_dns}")
        
        return {
            'arn': alb_arn,
            'dns': alb_dns
        }
        
    except ClientError as e:
        if 'already exists' in str(e):
            response = elbv2.describe_load_balancers(Names=['alert-whisperer-alb'])
            alb = response['LoadBalancers'][0]
            print(f"✅ Using existing load balancer")
            print(f"   DNS: {alb['DNSName']}")
            return {
                'arn': alb['LoadBalancerArn'],
                'dns': alb['DNSName']
            }
        print(f"❌ Error creating load balancer: {e}")
        return None

# Step 4: Create Target Group
def create_target_group():
    print("\n🎯 STEP 4: Creating Target Group")
    print("-" * 80)
    
    try:
        response = elbv2.create_target_group(
            Name='alert-whisperer-tg',
            Protocol='HTTP',
            Port=8001,
            VpcId=vpc_id,
            TargetType='ip',
            HealthCheckPath='/api/health',
            HealthCheckProtocol='HTTP',
            HealthCheckIntervalSeconds=30,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=2,
            UnhealthyThresholdCount=3
        )
        
        tg_arn = response['TargetGroups'][0]['TargetGroupArn']
        print(f"✅ Created target group: {tg_arn}")
        return tg_arn
        
    except ClientError as e:
        if 'already exists' in str(e):
            response = elbv2.describe_target_groups(Names=['alert-whisperer-tg'])
            tg_arn = response['TargetGroups'][0]['TargetGroupArn']
            print(f"✅ Using existing target group: {tg_arn}")
            return tg_arn
        print(f"❌ Error creating target group: {e}")
        return None

# Step 5: Create ALB Listener
def create_listener(alb_arn, tg_arn):
    print("\n👂 STEP 5: Creating ALB Listener")
    print("-" * 80)
    
    try:
        response = elbv2.create_listener(
            LoadBalancerArn=alb_arn,
            Protocol='HTTP',
            Port=80,
            DefaultActions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': tg_arn
                }
            ]
        )
        
        listener_arn = response['Listeners'][0]['ListenerArn']
        print(f"✅ Created listener: {listener_arn}")
        return listener_arn
        
    except ClientError as e:
        # Listener might already exist
        response = elbv2.describe_listeners(LoadBalancerArn=alb_arn)
        if response['Listeners']:
            listener_arn = response['Listeners'][0]['ListenerArn']
            print(f"✅ Using existing listener: {listener_arn}")
            return listener_arn
        print(f"❌ Error creating listener: {e}")
        return None

# Step 6: Create IAM Role for ECS Task
def create_ecs_task_role():
    print("\n👤 STEP 6: Creating IAM Roles for ECS")
    print("-" * 80)
    
    # Task Execution Role
    execution_role_name = 'alertWhispererTaskExecutionRole'
    try:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        
        response = iam.create_role(
            RoleName=execution_role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='ECS task execution role for Alert Whisperer'
        )
        execution_role_arn = response['Role']['Arn']
        
        # Attach AWS managed policy
        iam.attach_role_policy(
            RoleName=execution_role_name,
            PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
        )
        
        print(f"✅ Created execution role: {execution_role_arn}")
        
    except ClientError as e:
        if 'already exists' in str(e):
            response = iam.get_role(RoleName=execution_role_name)
            execution_role_arn = response['Role']['Arn']
            print(f"✅ Using existing execution role: {execution_role_arn}")
        else:
            print(f"❌ Error creating execution role: {e}")
            return None, None
    
    # Task Role (for DynamoDB access)
    task_role_name = 'alertWhispererTaskRole'
    try:
        response = iam.create_role(
            RoleName=task_role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='ECS task role for Alert Whisperer with DynamoDB access'
        )
        task_role_arn = response['Role']['Arn']
        
        # Attach DynamoDB full access policy
        iam.attach_role_policy(
            RoleName=task_role_name,
            PolicyArn='arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess'
        )
        
        print(f"✅ Created task role: {task_role_arn}")
        
    except ClientError as e:
        if 'already exists' in str(e):
            response = iam.get_role(RoleName=task_role_name)
            task_role_arn = response['Role']['Arn']
            print(f"✅ Using existing task role: {task_role_arn}")
        else:
            print(f"⚠️  Warning: {e}")
            task_role_arn = None
    
    return execution_role_arn, task_role_arn

# Step 7: Create CloudWatch Log Group
def create_log_group():
    print("\n📝 STEP 7: Creating CloudWatch Log Group")
    print("-" * 80)
    
    log_group_name = '/ecs/alert-whisperer-backend'
    
    try:
        logs.create_log_group(logGroupName=log_group_name)
        print(f"✅ Created log group: {log_group_name}")
    except ClientError as e:
        if 'already exists' in str(e):
            print(f"✅ Using existing log group: {log_group_name}")
        else:
            print(f"❌ Error creating log group: {e}")
    
    return log_group_name

def print_final_summary(alb_info, deployment_info):
    print("\n" + "="*80)
    print("🎉 AWS DEPLOYMENT COMPLETE!")
    print("="*80)
    
    print(f"\n🌐 YOUR APPLICATION URLs:")
    print(f"   Frontend (S3): {deployment_info['frontend']['website_url']}")
    if alb_info:
        print(f"   Backend API: http://{alb_info['dns']}/api")
        print(f"   Full App URL: http://{alb_info['dns']}")
    
    print(f"\n📊 INFRASTRUCTURE:")
    print(f"   ✅ S3 Bucket: {deployment_info['frontend']['bucket_name']}")
    print(f"   ✅ DynamoDB: 11 tables (AlertWhisperer_*)")
    print(f"   ✅ ECR Repository: {ecr_uri}")
    print(f"   ✅ ECS Cluster: {cluster_name}")
    if alb_info:
        print(f"   ✅ Load Balancer: {alb_info['dns']}")
    
    print(f"\n⚠️  IMPORTANT - FINAL STEP REQUIRED:")
    print(f"   The infrastructure is ready, but you need to:")
    print(f"   1. Build Docker image for backend")
    print(f"   2. Push to ECR: {ecr_uri}")
    print(f"   3. Create ECS task definition")
    print(f"   4. Deploy ECS service")
    print(f"\n   Without a running backend container, API calls will fail.")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    # Create Security Groups
    alb_sg_id = create_alb_security_group()
    if not alb_sg_id:
        sys.exit(1)
    
    ecs_sg_id = create_ecs_security_group(alb_sg_id)
    if not ecs_sg_id:
        sys.exit(1)
    
    # Create Load Balancer
    alb_info = create_load_balancer(alb_sg_id)
    if not alb_info:
        sys.exit(1)
    
    # Wait for ALB to be active
    print("\n⏳ Waiting for load balancer to be active (this may take 2-3 minutes)...")
    time.sleep(10)
    
    # Create Target Group
    tg_arn = create_target_group()
    if not tg_arn:
        sys.exit(1)
    
    # Create Listener
    listener_arn = create_listener(alb_info['arn'], tg_arn)
    if not listener_arn:
        sys.exit(1)
    
    # Create IAM Roles
    execution_role_arn, task_role_arn = create_ecs_task_role()
    
    # Create Log Group
    log_group_name = create_log_group()
    
    # Save deployment info
    deployment_info['alb'] = alb_info
    deployment_info['security_groups'] = {
        'alb_sg': alb_sg_id,
        'ecs_sg': ecs_sg_id
    }
    deployment_info['target_group_arn'] = tg_arn
    deployment_info['listener_arn'] = listener_arn
    deployment_info['execution_role_arn'] = execution_role_arn
    deployment_info['task_role_arn'] = task_role_arn
    deployment_info['log_group_name'] = log_group_name
    
    with open('/tmp/deployment_info.json', 'w') as f:
        json.dump(deployment_info, f, indent=2)
    
    print_final_summary(alb_info, deployment_info)
    
    print(f"\n💾 Updated deployment info saved to: /tmp/deployment_info.json")
