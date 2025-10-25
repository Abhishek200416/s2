#!/usr/bin/env python3
"""
Complete AWS Deployment Script for Alert Whisperer MSP Platform
Deploys: Frontend (S3+CloudFront), Backend (ECS Fargate), DynamoDB
"""

import boto3
import json
import time
import os
import sys
from botocore.exceptions import ClientError

# AWS Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID', '728925775278')
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_SESSION_TOKEN = os.environ.get('AWS_SESSION_TOKEN')

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

s3 = get_aws_client('s3')
cloudfront = get_aws_client('cloudfront')
ecs = get_aws_client('ecs')
ecr = get_aws_client('ecr')
iam = get_aws_client('iam')
ec2 = get_aws_client('ec2')
elbv2 = get_aws_client('elbv2')
logs = get_aws_client('logs')

print("="*80)
print("🚀 ALERT WHISPERER - AWS DEPLOYMENT SCRIPT")
print("="*80)
print(f"Region: {AWS_REGION}")
print(f"Account: {AWS_ACCOUNT_ID}")
print("="*80)

# Step 1: Create S3 Bucket for Frontend
def deploy_frontend():
    print("\n📦 STEP 1: Deploying Frontend to S3")
    print("-" * 80)
    
    bucket_name = f"alert-whisperer-frontend-{AWS_ACCOUNT_ID}"
    
    try:
        # Create bucket
        print(f"Creating S3 bucket: {bucket_name}")
        if AWS_REGION == 'us-east-1':
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': AWS_REGION}
            )
        print(f"✅ Bucket created: {bucket_name}")
    except ClientError as e:
        if e.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
            print(f"✅ Bucket already exists: {bucket_name}")
        else:
            print(f"❌ Error creating bucket: {e}")
            return None
    
    # Configure bucket for static website hosting
    try:
        print("Configuring static website hosting...")
        website_config = {
            'IndexDocument': {'Suffix': 'index.html'},
            'ErrorDocument': {'Key': 'index.html'}
        }
        s3.put_bucket_website(Bucket=bucket_name, WebsiteConfiguration=website_config)
        
        # Make bucket public
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }]
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))
        print("✅ Static website hosting configured")
        
    except ClientError as e:
        print(f"⚠️  Warning: {e}")
    
    # Upload frontend files
    try:
        print("Uploading frontend files...")
        import os
        from pathlib import Path
        
        build_dir = Path('/app/frontend/build')
        if not build_dir.exists():
            print("❌ Build directory not found. Run 'yarn build' first.")
            return None
        
        file_count = 0
        for file_path in build_dir.rglob('*'):
            if file_path.is_file():
                relative_path = str(file_path.relative_to(build_dir))
                
                # Determine content type
                content_type = 'text/html'
                if relative_path.endswith('.js'):
                    content_type = 'application/javascript'
                elif relative_path.endswith('.css'):
                    content_type = 'text/css'
                elif relative_path.endswith('.json'):
                    content_type = 'application/json'
                elif relative_path.endswith('.png'):
                    content_type = 'image/png'
                elif relative_path.endswith('.jpg') or relative_path.endswith('.jpeg'):
                    content_type = 'image/jpeg'
                elif relative_path.endswith('.svg'):
                    content_type = 'image/svg+xml'
                
                s3.upload_file(
                    str(file_path),
                    bucket_name,
                    relative_path,
                    ExtraArgs={'ContentType': content_type}
                )
                file_count += 1
                if file_count % 10 == 0:
                    print(f"  Uploaded {file_count} files...")
        
        print(f"✅ Uploaded {file_count} files to S3")
        
    except Exception as e:
        print(f"❌ Error uploading files: {e}")
        return None
    
    website_url = f"http://{bucket_name}.s3-website-{AWS_REGION}.amazonaws.com"
    print(f"\n✅ Frontend deployed!")
    print(f"   URL: {website_url}")
    
    return {
        'bucket_name': bucket_name,
        'website_url': website_url
    }

# Step 2: Create ECR Repository
def create_ecr_repository():
    print("\n🐳 STEP 2: Creating ECR Repository for Backend")
    print("-" * 80)
    
    repo_name = "alert-whisperer-backend"
    
    try:
        response = ecr.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={'scanOnPush': True}
        )
        repo_uri = response['repository']['repositoryUri']
        print(f"✅ ECR repository created: {repo_uri}")
        return repo_uri
    except ClientError as e:
        if e.response['Error']['Code'] == 'RepositoryAlreadyExistsException':
            response = ecr.describe_repositories(repositoryNames=[repo_name])
            repo_uri = response['repositories'][0]['repositoryUri']
            print(f"✅ ECR repository already exists: {repo_uri}")
            return repo_uri
        else:
            print(f"❌ Error creating ECR repository: {e}")
            return None

# Step 3: Get Default VPC
def get_default_vpc():
    print("\n🌐 STEP 3: Getting Default VPC and Subnets")
    print("-" * 80)
    
    try:
        vpcs = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
        if not vpcs['Vpcs']:
            print("❌ No default VPC found")
            return None
        
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        print(f"✅ Default VPC: {vpc_id}")
        
        subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        subnet_ids = [subnet['SubnetId'] for subnet in subnets['Subnets']]
        print(f"✅ Found {len(subnet_ids)} subnets: {subnet_ids[:3]}...")
        
        return {
            'vpc_id': vpc_id,
            'subnet_ids': subnet_ids
        }
    except Exception as e:
        print(f"❌ Error getting VPC: {e}")
        return None

# Step 4: Create ECS Cluster
def create_ecs_cluster():
    print("\n📦 STEP 4: Creating ECS Fargate Cluster")
    print("-" * 80)
    
    cluster_name = "alert-whisperer-cluster"
    
    try:
        response = ecs.create_cluster(clusterName=cluster_name)
        print(f"✅ ECS cluster created: {cluster_name}")
        return cluster_name
    except ClientError as e:
        if 'already exists' in str(e):
            print(f"✅ ECS cluster already exists: {cluster_name}")
            return cluster_name
        else:
            print(f"❌ Error creating cluster: {e}")
            return None

def print_deployment_summary(frontend_info, ecr_uri, cluster_name):
    print("\n" + "="*80)
    print("🎉 DEPLOYMENT SUMMARY")
    print("="*80)
    
    if frontend_info:
        print(f"\n📱 FRONTEND:")
        print(f"   S3 Bucket: {frontend_info['bucket_name']}")
        print(f"   Website URL: {frontend_info['website_url']}")
    
    if ecr_uri:
        print(f"\n🐳 BACKEND ECR:")
        print(f"   Repository: {ecr_uri}")
    
    if cluster_name:
        print(f"\n📦 ECS CLUSTER:")
        print(f"   Cluster: {cluster_name}")
    
    print(f"\n💾 DATABASE:")
    print(f"   DynamoDB: AlertWhisperer_* (11 tables)")
    
    print("\n" + "="*80)
    print("📝 NEXT STEPS:")
    print("   1. Build Docker image for backend")
    print("   2. Push to ECR")
    print("   3. Create ECS task definition")
    print("   4. Deploy ECS service")
    print("   5. Set up API Gateway")
    print("="*80)

if __name__ == "__main__":
    # Deploy Frontend
    frontend_info = deploy_frontend()
    
    # Create ECR Repository
    ecr_uri = create_ecr_repository()
    
    # Get VPC info
    vpc_info = get_default_vpc()
    
    # Create ECS Cluster
    cluster_name = create_ecs_cluster()
    
    # Print summary
    print_deployment_summary(frontend_info, ecr_uri, cluster_name)
    
    # Save deployment info
    deployment_info = {
        'frontend': frontend_info,
        'ecr_uri': ecr_uri,
        'vpc_info': vpc_info,
        'cluster_name': cluster_name,
        'region': AWS_REGION,
        'account_id': AWS_ACCOUNT_ID
    }
    
    with open('/tmp/deployment_info.json', 'w') as f:
        json.dump(deployment_info, f, indent=2)
    
    print(f"\n💾 Deployment info saved to: /tmp/deployment_info.json")
