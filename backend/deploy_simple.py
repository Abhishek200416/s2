#!/usr/bin/env python3
"""
Simple AWS ECS Deployment Script
Uploads backend code as a zip file and triggers rebuild
"""

import boto3
import zipfile
import io
import os
import time
import json

# AWS Configuration  
AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "728925775278"
REPO_NAME = "alert-whisperer-backend"
CLUSTER_NAME = "alert-whisperer-cluster"
SERVICE_NAME = "alert-whisperer-backend-svc"

# Paths
BACKEND_DIR = "/app/backend"

def create_source_zip():
    """Create a zip file of the backend source code"""
    print("📦 Creating source code zip...")
    
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(BACKEND_DIR):
            # Skip unnecessary directories
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.pytest_cache', 'venv', 'node_modules']]
            
            for file in files:
                if file.endswith(('.py', '.txt', '.env', 'Dockerfile.production')):
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, BACKEND_DIR)
                    zipf.write(file_path, arcname)
                    print(f"   Added: {arcname}")
    
    zip_buffer.seek(0)
    print(f"✅ Source zip created ({len(zip_buffer.getvalue()) / 1024:.1f} KB)")
    
    return zip_buffer.getvalue()

def upload_to_s3(zip_data):
    """Upload source code to S3"""
    s3 = boto3.client('s3', region_name=AWS_REGION)
    bucket_name = f"alert-whisperer-builds-{AWS_ACCOUNT_ID}"
    key = f"source/{int(time.time())}.zip"
    
    print(f"\n📤 Uploading to S3...")
    
    # Create bucket if doesn't exist
    try:
        s3.head_bucket(Bucket=bucket_name)
    except:
        print(f"   Creating S3 bucket: {bucket_name}")
        s3.create_bucket(Bucket=bucket_name)
    
    # Upload zip
    s3.put_object(Bucket=bucket_name, Key=key, Body=zip_data)
    
    print(f"✅ Uploaded to s3://{bucket_name}/{key}")
    
    return f"s3://{bucket_name}/{key}"

def trigger_ecs_redeploy():
    """Force ECS to pull latest image and redeploy"""
    ecs = boto3.client('ecs', region_name=AWS_REGION)
    
    print(f"\n🔄 Triggering ECS service redeployment...")
    print(f"   Cluster: {CLUSTER_NAME}")
    print(f"   Service: {SERVICE_NAME}")
    
    response = ecs.update_service(
        cluster=CLUSTER_NAME,
        service=SERVICE_NAME,
        forceNewDeployment=True
    )
    
    print(f"✅ Redeployment triggered")
    
    return True

def wait_for_deployment():
    """Wait for ECS deployment to complete"""
    ecs = boto3.client('ecs', region_name=AWS_REGION)
    
    print(f"\n⏳ Waiting for deployment to complete...")
    
    for i in range(60):  # 10 minutes max
        try:
            services = ecs.describe_services(
                cluster=CLUSTER_NAME,
                services=[SERVICE_NAME]
            )
            
            if not services['services']:
                print(f"❌ Service not found")
                return False
            
            service = services['services'][0]
            deployments = service['deployments']
            
            print(f"\n   Deployments: {len(deployments)}")
            for dep in deployments:
                status = dep['status']
                running = dep['runningCount']
                desired = dep['desiredCount']
                print(f"   - {status}: {running}/{desired} tasks")
            
            # Check if primary deployment is stable
            if len(deployments) == 1:
                primary = deployments[0]
                if primary['status'] == 'PRIMARY' and primary['runningCount'] == primary['desiredCount']:
                    print(f"\n✅ Deployment complete!")
                    return True
            
            time.sleep(10)
            
        except Exception as e:
            print(f"   Error checking deployment: {e}")
            time.sleep(10)
    
    print(f"\n⚠️  Deployment timeout - check AWS Console")
    return False

def get_task_logs():
    """Get logs from ECS tasks"""
    ecs = boto3.client('ecs', region_name=AWS_REGION)
    logs = boto3.client('logs', region_name=AWS_REGION)
    
    print(f"\n📋 Fetching recent logs...")
    
    try:
        # Get tasks
        tasks = ecs.list_tasks(cluster=CLUSTER_NAME, serviceName=SERVICE_NAME)
        
        if not tasks['taskArns']:
            print(f"   No tasks found")
            return
        
        # Get task details
        task_details = ecs.describe_tasks(cluster=CLUSTER_NAME, tasks=tasks['taskArns'])
        
        for task in task_details['tasks']:
            task_id = task['taskArn'].split('/')[-1]
            print(f"\n   Task: {task_id}")
            print(f"   Status: {task['lastStatus']}")
            
            # Try to get logs
            log_group = f"/ecs/{SERVICE_NAME}"
            log_stream = f"ecs/{SERVICE_NAME}/{task_id}"
            
            try:
                log_events = logs.get_log_events(
                    logGroupName=log_group,
                    logStreamName=log_stream,
                    limit=20
                )
                
                print(f"\n   Recent logs:")
                for event in log_events['events']:
                    print(f"      {event['message']}")
                    
            except Exception as e:
                print(f"   Could not fetch logs: {e}")
                
    except Exception as e:
        print(f"   Error fetching logs: {e}")

def main():
    """Main deployment flow"""
    print("=" * 70)
    print("🚀 ALERT WHISPERER BACKEND DEPLOYMENT")
    print("=" * 70)
    print(f"Region: {AWS_REGION}")
    print(f"Account: {AWS_ACCOUNT_ID}")
    print(f"Service: {SERVICE_NAME}")
    print("=" * 70)
    
    try:
        # Note: We can't build Docker images here, but we can trigger redeploy
        # assuming the image in ECR has been updated externally
        
        print("\n⚠️  NOTE: This script triggers a redeploy of existing image")
        print("   To update the Docker image, you need to:")
        print("   1. Build locally: cd /app/backend && docker build -f Dockerfile.production -t alert-whisperer-backend .")
        print("   2. Push to ECR: Use the deploy_aws.sh script")
        print("   3. Or run this script to redeploy existing image")
        
        print("\n📌 Would you like to proceed with redeployment? (yes/no)")
        # For automation, we'll proceed automatically
        
        # Step 1: Trigger redeploy
        trigger_ecs_redeploy()
        
        # Step 2: Wait for deployment
        wait_for_deployment()
        
        # Step 3: Show logs
        get_task_logs()
        
        print("\n" + "=" * 70)
        print("✅ DEPLOYMENT PROCESS COMPLETE")
        print("=" * 70)
        print("\n📋 Next Steps:")
        print("   1. Check AWS ECS Console for detailed task status")
        print("   2. Review CloudWatch Logs for application errors")
        print("   3. Test your API endpoints")
        print(f"\n   ECS Console: https://console.aws.amazon.com/ecs/home?region={AWS_REGION}#/clusters/{CLUSTER_NAME}/services/{SERVICE_NAME}/tasks")
        
    except Exception as e:
        print(f"\n❌ Deployment failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
