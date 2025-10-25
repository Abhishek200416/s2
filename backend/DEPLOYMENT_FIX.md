# 🚀 AWS Deployment Fix Guide

## Problem Identified

The Docker image in ECR is MISSING Python files, specifically `ssm_health_service.py` and likely others.

### Root Cause
The `Dockerfile.production` was only copying specific files:
- ❌ OLD: `COPY server.py /app/` (only 6-7 files)
- ✅ FIXED: `COPY *.py /app/` (all 29 Python files)

## Solution (✅ ALREADY FIXED)

I've updated `/app/backend/Dockerfile.production` to copy ALL Python files.

---

## 📋 Deployment Options

### Option 1: Build & Deploy from Your Computer (RECOMMENDED)

If you have Docker installed locally, run these commands:

```bash
# 1. Navigate to the backend directory on YOUR computer
cd /path/to/your/backend

# 2. Set environment variables
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID="728925775278"
export REPO_NAME="alert-whisperer-backend"

# 3. Login to ECR
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# 4. Build the Docker image
docker build -f Dockerfile.production -t $REPO_NAME:latest .

# 5. Tag the image
docker tag $REPO_NAME:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO_NAME:latest

# 6. Push to ECR
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO_NAME:latest

# 7. Trigger ECS redeployment
aws ecs update-service --cluster alert-whisperer-cluster --service alert-whisperer-backend-svc --force-new-deployment --region $AWS_REGION
```

### Option 2: Use the Deploy Script

If you have Docker installed, you can also use the existing deploy script:

```bash
cd /app/backend

# Set credentials
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID="728925775278"

# Run the deployment script
bash deploy_aws.sh
```

### Option 3: Build in AWS using CodeBuild

If you DON'T have Docker installed, I can help you set up AWS CodeBuild to build the image in the cloud:

1. The source code needs to be in a Git repository or S3
2. CodeBuild will build and push the Docker image for you
3. Then trigger ECS redeployment

---

## 🔍 Current Status

**AWS Infrastructure:**
- ✅ ECR Repository: `alert-whisperer-backend`
- ✅ ECS Cluster: `alert-whisperer-cluster`
- ✅ ECS Service: `alert-whisperer-backend-svc`
- ⚠️ Current Docker Image: Missing Python files (needs rebuild)

**Latest Task Status:**
- Task is PENDING (waiting for healthy container)
- The current image will fail with: `ModuleNotFoundError: No module named 'ssm_health_service'`

---

## 📝 Files Updated

1. ✅ `/app/backend/Dockerfile.production` - Fixed to copy ALL Python files

## What Happens Next

Once you rebuild and push the Docker image:
1. ECS will pull the new image (with all Python files)
2. Start a new task
3. The healthcheck will pass (`/api/agent/ping`)
4. The old task will be drained
5. Your backend will be live! 🎉

---

## 🆘 Need Help?

**If you don't have Docker installed:**
1. Install Docker Desktop: https://www.docker.com/products/docker-desktop
2. OR use a cloud-based build service (CodeBuild, GitHub Actions, etc.)

**If you're stuck:**
- Let me know and I can help set up automated cloud builds
- Or walk you through alternative deployment methods

---

## ✅ Summary

- **Problem**: Dockerfile was incomplete (missing files)
- **Fix**: Updated Dockerfile to copy all Python files  
- **Action Required**: Rebuild and push Docker image
- **Expected Result**: Backend will start successfully in ECS

