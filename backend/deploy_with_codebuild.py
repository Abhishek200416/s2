#!/usr/bin/env python3
"""
Automated AWS Deployment Script using CodeBuild
This script creates a CodeBuild project that builds Docker images in AWS
(no local Docker required)
"""

import boto3
import time
import json
import os
import sys

# AWS Configuration
AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "728925775278"
REPO_NAME = "alert-whisperer-backend"
CLUSTER_NAME = "alert-whisperer-cluster"
SERVICE_NAME = "alert-whisperer-backend-svc"

# Initialize AWS clients
ecr = boto3.client('ecr', region_name=AWS_REGION)
ecs = boto3.client('ecs', region_name=AWS_REGION)
codebuild = boto3.client('codebuild', region_name=AWS_REGION)
iam = boto3.client('iam', region_name=AWS_REGION)

def create_codebuild_role():
    """Create IAM role for CodeBuild if it doesn't exist"""
    role_name = "CodeBuildAlertWhispererRole"
    
    # Check if role exists
    try:
        iam.get_role(RoleName=role_name)
        print(f"✅ IAM Role '{role_name}' already exists")
        return f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{role_name}"
    except iam.exceptions.NoSuchEntityException:
        pass
    
    print(f"📝 Creating IAM Role '{role_name}'...")
    
    # Trust policy
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    
    # Create role
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="Role for CodeBuild to build Alert Whisperer Docker images"
    )
    
    # Attach policies
    policies = [
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser",
        "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
    ]
    
    for policy_arn in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    
    print(f"✅ IAM Role created: {role['Role']['Arn']}")
    time.sleep(10)  # Wait for role to propagate
    return role['Role']['Arn']

def create_buildspec():
    """Create buildspec.yml content"""
    return f"""version: 0.2

phases:
  pre_build:
    commands:
      - echo Logging in to Amazon ECR...
      - aws ecr get-login-password --region {AWS_REGION} | docker login --username AWS --password-stdin {AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com
  build:
    commands:
      - echo Build started on `date`
      - echo Building the Docker image...
      - docker build -f Dockerfile.production -t {REPO_NAME}:latest .
      - docker tag {REPO_NAME}:latest {AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/{REPO_NAME}:latest
  post_build:
    commands:
      - echo Build completed on `date`
      - echo Pushing the Docker image...
      - docker push {AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/{REPO_NAME}:latest
      - echo Image pushed successfully
"""

def create_codebuild_project(role_arn):
    """Create or update CodeBuild project"""
    project_name = "alert-whisperer-backend-build"
    
    # Check if project exists
    try:
        codebuild.batch_get_projects(names=[project_name])
        print(f"✅ CodeBuild project '{project_name}' already exists")
        return project_name
    except:
        pass
    
    print(f"📝 Creating CodeBuild project '{project_name}'...")
    
    project = codebuild.create_project(
        name=project_name,
        description="Build Alert Whisperer backend Docker image",
        source={
            'type': 'NO_SOURCE',
            'buildspec': create_buildspec()
        },
        artifacts={'type': 'NO_ARTIFACTS'},
        environment={
            'type': 'LINUX_CONTAINER',
            'image': 'aws/codebuild/standard:7.0',
            'computeType': 'BUILD_GENERAL1_SMALL',
            'environmentVariables': [],
            'privilegedMode': True  # Required for Docker builds
        },
        serviceRole=role_arn,
        timeoutInMinutes=30
    )
    
    print(f"✅ CodeBuild project created: {project['project']['name']}")
    return project_name

def upload_source_to_s3():
    """Upload source code to S3 for CodeBuild"""
    # For now, we'll use NO_SOURCE and inline buildspec
    # In production, you'd zip the source and upload to S3
    pass

def start_build(project_name):
    """Start a CodeBuild build"""
    print(f"\n🚀 Starting CodeBuild build...")
    
    build = codebuild.start_build(
        projectName=project_name
    )
    
    build_id = build['build']['id']
    print(f"✅ Build started: {build_id}")
    
    return build_id

def wait_for_build(build_id):
    """Wait for build to complete"""
    print(f"\n⏳ Waiting for build to complete...")
    
    while True:
        builds = codebuild.batch_get_builds(ids=[build_id])
        build = builds['builds'][0]
        status = build['buildStatus']
        
        if status == 'IN_PROGRESS':
            print(f"   Build in progress... ({build.get('currentPhase', 'UNKNOWN')})")
            time.sleep(10)
        elif status == 'SUCCEEDED':
            print(f"✅ Build completed successfully!")
            return True
        else:
            print(f"❌ Build failed with status: {status}")
            if 'phases' in build:
                for phase in build['phases']:
                    if phase.get('phaseStatus') == 'FAILED':
                        print(f"   Failed phase: {phase['phaseType']}")
            return False

def update_ecs_service():
    """Force ECS service to redeploy with new image"""
    print(f"\n🔄 Updating ECS service to use new image...")
    
    response = ecs.update_service(
        cluster=CLUSTER_NAME,
        service=SERVICE_NAME,
        forceNewDeployment=True
    )
    
    print(f"✅ ECS service update initiated")
    print(f"   Service: {SERVICE_NAME}")
    print(f"   Cluster: {CLUSTER_NAME}")
    
    return True

def check_deployment_status():
    """Check ECS deployment status"""
    print(f"\n⏳ Checking deployment status...")
    
    for i in range(30):  # Check for up to 5 minutes
        services = ecs.describe_services(
            cluster=CLUSTER_NAME,
            services=[SERVICE_NAME]
        )
        
        service = services['services'][0]
        deployments = service['deployments']
        
        if len(deployments) == 1 and deployments[0]['status'] == 'PRIMARY':
            running_count = deployments[0]['runningCount']
            desired_count = deployments[0]['desiredCount']
            
            if running_count == desired_count:
                print(f"✅ Deployment complete! Running {running_count}/{desired_count} tasks")
                return True
            else:
                print(f"   Progress: {running_count}/{desired_count} tasks running...")
        
        time.sleep(10)
    
    print(f"⚠️  Deployment check timeout - please verify manually in AWS Console")
    return False

def main():
    """Main deployment orchestration"""
    print("=" * 70)
    print("🚀 ALERT WHISPERER AWS DEPLOYMENT")
    print("=" * 70)
    print(f"Account: {AWS_ACCOUNT_ID}")
    print(f"Region: {AWS_REGION}")
    print(f"ECR Repo: {REPO_NAME}")
    print(f"ECS Cluster: {CLUSTER_NAME}")
    print(f"ECS Service: {SERVICE_NAME}")
    print("=" * 70)
    
    try:
        # Step 1: Create IAM role
        print("\n📌 STEP 1: IAM Role Setup")
        role_arn = create_codebuild_role()
        
        # Step 2: Create CodeBuild project
        print("\n📌 STEP 2: CodeBuild Project Setup")
        project_name = create_codebuild_project(role_arn)
        
        # Step 3: Start build
        print("\n📌 STEP 3: Docker Image Build")
        build_id = start_build(project_name)
        
        # Step 4: Wait for build
        build_success = wait_for_build(build_id)
        
        if not build_success:
            print("\n❌ Build failed - deployment aborted")
            sys.exit(1)
        
        # Step 5: Update ECS service
        print("\n📌 STEP 4: ECS Service Update")
        update_ecs_service()
        
        # Step 6: Check deployment
        check_deployment_status()
        
        print("\n" + "=" * 70)
        print("✅ DEPLOYMENT COMPLETE!")
        print("=" * 70)
        print(f"\nImage: {AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/{REPO_NAME}:latest")
        print(f"ECS Service: {SERVICE_NAME}")
        print(f"Cluster: {CLUSTER_NAME}")
        print("\n📋 Next Steps:")
        print("   1. Check ECS console for task status")
        print("   2. View CloudWatch logs for application logs")
        print("   3. Test your API endpoints")
        
    except Exception as e:
        print(f"\n❌ Deployment failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
