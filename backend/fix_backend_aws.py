#!/usr/bin/env python3
"""
Fix Backend AWS Deployment - Add IAM Role for DynamoDB Access
"""

import boto3
import json
import time

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "728925775278"

iam = boto3.client('iam', region_name=AWS_REGION)
ecs = boto3.client('ecs', region_name=AWS_REGION)

def create_ecs_task_role():
    """Create IAM role for ECS task to access DynamoDB"""
    role_name = "AlertWhispererECSTaskRole"
    
    print(f"🔐 Creating ECS Task Role...")
    
    # Check if role exists
    try:
        role = iam.get_role(RoleName=role_name)
        print(f"✅ Role already exists: {role['Role']['Arn']}")
        return role['Role']['Arn']
    except iam.exceptions.NoSuchEntityException:
        pass
    
    # Trust policy for ECS tasks
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    
    # Create role
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="Allow ECS tasks to access DynamoDB for Alert Whisperer"
    )
    
    # Attach DynamoDB Full Access policy
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
    )
    
    print(f"✅ Role created: {role['Role']['Arn']}")
    time.sleep(10)  # Wait for role propagation
    
    return role['Role']['Arn']

def update_task_definition(task_role_arn):
    """Update ECS task definition with IAM role"""
    print(f"\n📝 Updating ECS Task Definition...")
    
    # Get current task definition
    response = ecs.describe_task_definition(taskDefinition="alert-whisperer-backend")
    old_td = response['taskDefinition']
    
    # Create new task definition with IAM role
    new_td = {
        "family": old_td['family'],
        "taskRoleArn": task_role_arn,  # Add task role
        "executionRoleArn": old_td.get('executionRoleArn'),
        "networkMode": old_td['networkMode'],
        "containerDefinitions": old_td['containerDefinitions'],
        "requiresCompatibilities": old_td['requiresCompatibilities'],
        "cpu": old_td['cpu'],
        "memory": old_td['memory']
    }
    
    # Register new task definition
    response = ecs.register_task_definition(**new_td)
    new_version = response['taskDefinition']['taskDefinitionArn']
    
    print(f"✅ New task definition: {new_version}")
    
    return new_version

def update_ecs_service(new_task_def):
    """Update ECS service to use new task definition"""
    print(f"\n🔄 Updating ECS Service...")
    
    ecs.update_service(
        cluster="alert-whisperer-cluster",
        service="alert-whisperer-backend-svc",
        taskDefinition=new_task_def,
        forceNewDeployment=True
    )
    
    print(f"✅ Service updated with new task definition")

def main():
    print("=" * 70)
    print("🔧 FIXING BACKEND DEPLOYMENT - Adding DynamoDB Access")
    print("=" * 70)
    
    try:
        # Step 1: Create IAM role
        task_role_arn = create_ecs_task_role()
        
        # Step 2: Update task definition
        new_task_def = update_task_definition(task_role_arn)
        
        # Step 3: Update ECS service
        update_ecs_service(new_task_def)
        
        print("\n" + "=" * 70)
        print("✅ BACKEND FIX DEPLOYED!")
        print("=" * 70)
        print(f"\n⏳ Wait 2-3 minutes for the new task to start...")
        print(f"\n🌐 Then try logging in again:")
        print(f"   http://alert-whisperer-frontend-728925775278.s3-website-us-east-1.amazonaws.com/login")
        print(f"\n   Email: admin@alertwhisperer.com")
        print(f"   Password: admin123")
        
    except Exception as e:
        print(f"\n❌ Fix failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
