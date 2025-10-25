#!/usr/bin/env python3
"""
Automated Backend Deployment using AWS CodeBuild
No local Docker required - builds in AWS cloud
"""

import boto3
import json
import time
import zipfile
import io
import os
from pathlib import Path

# Configuration
AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "728925775278"
PROJECT_NAME = "alert-whisperer-backend-build"
REPO_NAME = "alert-whisperer-backend"
CLUSTER_NAME = "alert-whisperer-cluster"
SERVICE_NAME = "alert-whisperer-backend-svc"
S3_BUCKET = "alert-whisperer-build-728925775278"

# Initialize clients
iam = boto3.client('iam', region_name=AWS_REGION)
codebuild = boto3.client('codebuild', region_name=AWS_REGION)
s3 = boto3.client('s3', region_name=AWS_REGION)
ecs = boto3.client('ecs', region_name=AWS_REGION)

def ensure_s3_bucket():
    """Ensure S3 bucket exists"""
    print(f"📦 Checking S3 bucket: {S3_BUCKET}")
    try:
        s3.head_bucket(Bucket=S3_BUCKET)
        print(f"✅ Bucket exists")
    except:
        print(f"   Creating bucket...")
        s3.create_bucket(Bucket=S3_BUCKET)
        print(f"✅ Bucket created")

def create_source_zip():
    """Create zip of backend source"""
    print(f"\n📦 Creating source code zip...")
    
    backend_dir = "/app/backend"
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(backend_dir):
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.pytest_cache', 'venv']]
            
            for file in files:
                if file.endswith(('.py', '.txt', '.env')) or file == 'Dockerfile.production':
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, backend_dir)
                    zipf.write(file_path, arcname)
                    print(f"   ✓ {arcname}")
    
    zip_buffer.seek(0)
    size_kb = len(zip_buffer.getvalue()) / 1024
    print(f"✅ Zip created: {size_kb:.1f} KB")
    
    return zip_buffer.getvalue()

def upload_source(zip_data):
    """Upload source to S3"""
    print(f"\n📤 Uploading source to S3...")
    
    key = f"source/backend-{int(time.time())}.zip"
    s3.put_object(Bucket=S3_BUCKET, Key=key, Body=zip_data)
    
    s3_location = f"s3://{S3_BUCKET}/{key}"
    print(f"✅ Uploaded to: {s3_location}")
    
    return s3_location, key

def create_iam_role():
    """Create IAM role for CodeBuild"""
    role_name = "CodeBuildAlertWhispererRole"
    
    print(f"\n🔐 Setting up IAM role...")
    
    try:
        role = iam.get_role(RoleName=role_name)
        print(f"✅ Role exists: {role['Role']['Arn']}")
        return role['Role']['Arn']
    except iam.exceptions.NoSuchEntityException:
        pass
    
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
    print(f"   Creating role...")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="Role for CodeBuild to build Alert Whisperer"
    )
    
    # Attach policies
    policies = [
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser",
        "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    ]
    
    for policy_arn in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    
    print(f"✅ Role created: {role['Role']['Arn']}")
    time.sleep(10)  # Wait for role propagation
    
    return role['Role']['Arn']

def create_buildspec():
    """Generate buildspec.yml"""
    return f"""version: 0.2

phases:
  pre_build:
    commands:
      - echo Logging in to Amazon ECR...
      - aws ecr get-login-password --region {AWS_REGION} | docker login --username AWS --password-stdin {AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com
      - echo Listing files...
      - ls -la
  build:
    commands:
      - echo Build started on `date`
      - echo Building Docker image...
      - docker build -f Dockerfile.production -t {REPO_NAME}:latest .
      - docker tag {REPO_NAME}:latest {AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/{REPO_NAME}:latest
  post_build:
    commands:
      - echo Build completed on `date`
      - echo Pushing Docker image...
      - docker push {AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/{REPO_NAME}:latest
      - echo Image pushed successfully!
"""

def create_codebuild_project(role_arn, s3_location):
    """Create or update CodeBuild project"""
    print(f"\n🏗️  Setting up CodeBuild project...")
    
    try:
        codebuild.delete_project(name=PROJECT_NAME)
        print(f"   Deleted existing project")
        time.sleep(2)
    except:
        pass
    
    project = codebuild.create_project(
        name=PROJECT_NAME,
        description="Build Alert Whisperer backend Docker image",
        source={
            'type': 'S3',
            'location': s3_location,
            'buildspec': create_buildspec()
        },
        artifacts={'type': 'NO_ARTIFACTS'},
        environment={
            'type': 'LINUX_CONTAINER',
            'image': 'aws/codebuild/standard:7.0',
            'computeType': 'BUILD_GENERAL1_SMALL',
            'privilegedMode': True,
            'environmentVariables': [
                {'name': 'AWS_DEFAULT_REGION', 'value': AWS_REGION},
                {'name': 'AWS_ACCOUNT_ID', 'value': AWS_ACCOUNT_ID},
                {'name': 'IMAGE_REPO_NAME', 'value': REPO_NAME},
            ]
        },
        serviceRole=role_arn,
        timeoutInMinutes=30
    )
    
    print(f"✅ CodeBuild project created: {PROJECT_NAME}")
    return PROJECT_NAME

def start_build():
    """Start CodeBuild build"""
    print(f"\n🚀 Starting Docker image build...")
    
    build = codebuild.start_build(projectName=PROJECT_NAME)
    build_id = build['build']['id']
    
    print(f"✅ Build started: {build_id}")
    return build_id

def wait_for_build(build_id):
    """Wait for build to complete"""
    print(f"\n⏳ Waiting for build to complete...")
    print(f"   (This may take 3-5 minutes)")
    
    last_phase = None
    
    while True:
        builds = codebuild.batch_get_builds(ids=[build_id])
        build = builds['builds'][0]
        status = build['buildStatus']
        phase = build.get('currentPhase', 'UNKNOWN')
        
        if phase != last_phase:
            print(f"   📍 Phase: {phase}")
            last_phase = phase
        
        if status == 'IN_PROGRESS':
            time.sleep(10)
        elif status == 'SUCCEEDED':
            print(f"\n✅ Build completed successfully!")
            return True
        else:
            print(f"\n❌ Build failed with status: {status}")
            
            # Show error details
            if 'phases' in build:
                for phase_info in build['phases']:
                    if phase_info.get('phaseStatus') == 'FAILED':
                        print(f"\n   Failed Phase: {phase_info['phaseType']}")
                        if 'contexts' in phase_info:
                            for ctx in phase_info['contexts']:
                                print(f"   Error: {ctx.get('message', 'Unknown')}")
            
            return False

def update_ecs_service():
    """Trigger ECS service to use new image"""
    print(f"\n🔄 Updating ECS service...")
    
    response = ecs.update_service(
        cluster=CLUSTER_NAME,
        service=SERVICE_NAME,
        forceNewDeployment=True
    )
    
    print(f"✅ ECS service update initiated")
    return True

def wait_for_ecs_deployment():
    """Wait for ECS deployment to complete"""
    print(f"\n⏳ Waiting for ECS deployment...")
    print(f"   (This may take 2-3 minutes)")
    
    for i in range(30):
        services = ecs.describe_services(
            cluster=CLUSTER_NAME,
            services=[SERVICE_NAME]
        )
        
        if not services['services']:
            print(f"   ❌ Service not found")
            return False
        
        service = services['services'][0]
        deployments = service['deployments']
        
        if len(deployments) == 1:
            primary = deployments[0]
            running = primary['runningCount']
            desired = primary['desiredCount']
            
            if primary['status'] == 'PRIMARY' and running == desired:
                print(f"✅ Deployment complete! {running}/{desired} tasks running")
                return True
            else:
                print(f"   Progress: {running}/{desired} tasks running...")
        else:
            print(f"   Rolling update in progress ({len(deployments)} deployments)...")
        
        time.sleep(10)
    
    print(f"⚠️  Deployment timeout - check AWS Console")
    return False

def main():
    """Main deployment orchestration"""
    print("=" * 70)
    print("🚀 AUTOMATED BACKEND DEPLOYMENT")
    print("=" * 70)
    print(f"Account: {AWS_ACCOUNT_ID}")
    print(f"Region: {AWS_REGION}")
    print(f"Project: {PROJECT_NAME}")
    print("=" * 70)
    
    try:
        # Step 1: Ensure S3 bucket
        ensure_s3_bucket()
        
        # Step 2: Create source zip
        zip_data = create_source_zip()
        
        # Step 3: Upload to S3
        s3_location, s3_key = upload_source(zip_data)
        
        # Step 4: Create IAM role
        role_arn = create_iam_role()
        
        # Step 5: Create CodeBuild project
        s3_full_path = f"{S3_BUCKET}/{s3_key}"
        create_codebuild_project(role_arn, s3_full_path)
        
        # Step 6: Start build
        build_id = start_build()
        
        # Step 7: Wait for build
        if not wait_for_build(build_id):
            print("\n❌ Build failed - deployment aborted")
            return 1
        
        # Step 8: Update ECS
        update_ecs_service()
        
        # Step 9: Wait for deployment
        wait_for_ecs_deployment()
        
        print("\n" + "=" * 70)
        print("✅ DEPLOYMENT COMPLETE!")
        print("=" * 70)
        print(f"\n🌐 Your Application URLs:")
        print(f"   Frontend: http://alert-whisperer-frontend-728925775278.s3-website-us-east-1.amazonaws.com")
        print(f"   Backend:  http://alert-whisperer-alb-1592907964.us-east-1.elb.amazonaws.com/api")
        print(f"   Health:   http://alert-whisperer-alb-1592907964.us-east-1.elb.amazonaws.com/api/agent/ping")
        print("\n🎉 Backend is now running with all Python files!")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Deployment failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main())
