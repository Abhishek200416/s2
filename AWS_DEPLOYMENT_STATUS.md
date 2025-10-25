# 🏗️ AWS Deployment Architecture - Alert Whisperer

## Current Deployment Status

### ✅ Backend (API) - ECS Fargate
- **Service**: `alert-whisperer-backend-svc`
- **Cluster**: `alert-whisperer-cluster`
- **Container Registry**: ECR - `alert-whisperer-backend`
- **Status**: ⚠️ **ISSUE** - Container failing (missing Python files)
- **Load Balancer**: `alert-whisperer-alb-1592907964.us-east-1.elb.amazonaws.com`

**Issue**: Docker image in ECR is missing Python files (see DEPLOYMENT_FIX.md)

---

### ✅ Frontend (React) - S3 + CloudFront
- **S3 Bucket**: `alert-whisperer-frontend-728925775278`
- **Files Present**: 
  - `index.html`
  - `asset-manifest.json`
  - `static/` folder
- **Status**: ✅ **DEPLOYED** and accessible
- **Load Balancer**: `alertw-alb-1475356777.us-east-1.elb.amazonaws.com`

---

## 🌐 Access URLs

### Frontend URL
**Primary**: http://alertw-alb-1475356777.us-east-1.elb.amazonaws.com

### Backend API URL
**Primary**: http://alert-whisperer-alb-1592907964.us-east-1.elb.amazonaws.com/api

---

## 📊 Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                        USER                              │
└─────────────────┬───────────────────────┬───────────────┘
                  │                       │
         ┌────────▼─────────┐    ┌───────▼────────────┐
         │  ALB (Frontend)  │    │  ALB (Backend)     │
         │  alertw-alb      │    │  alert-whisperer   │
         └────────┬─────────┘    └────────┬───────────┘
                  │                       │
         ┌────────▼─────────┐    ┌───────▼───────────┐
         │   S3 Bucket      │    │  ECS Service      │
         │   (React App)    │    │  (FastAPI)        │
         │   Static Files   │    │  ⚠️ FAILING NOW  │
         └──────────────────┘    └───────────────────┘
```

---

## 🔧 Current Issues

### 1. Backend Container Failing ❌
**Problem**: Docker image missing Python files
**Impact**: Backend API not responding
**Fix**: Rebuild Docker image with corrected Dockerfile (already fixed in code)
**Action Required**: Run build commands from DEPLOYMENT_FIX.md

### 2. Frontend is Working ✅
**Status**: Frontend is deployed and accessible
**Location**: S3 bucket with ALB in front
**Issue**: May show errors connecting to backend (since backend is down)

---

## 🚀 Deployment Flow

### Backend Deployment
1. **Build**: Create Docker image from `/app/backend/Dockerfile.production`
2. **Push**: Upload to ECR repository
3. **Deploy**: ECS pulls image and runs container
4. **Expose**: ALB routes traffic to container

### Frontend Deployment
1. **Build**: React build creates static files
2. **Upload**: Copy files to S3 bucket
3. **Serve**: ALB serves files from S3
4. **Connect**: Frontend calls backend via ALB

---

## ✅ What's Working

- ✅ S3 bucket for frontend exists and has files
- ✅ ECS cluster is running
- ✅ ECS service is configured
- ✅ Load balancers are active
- ✅ ECR repository exists with image (image is incomplete though)
- ✅ Network infrastructure (VPC, subnets, security groups)

---

## ⚠️ What Needs Fixing

1. **Backend Docker Image** (Critical)
   - Missing Python modules
   - Need to rebuild with fixed Dockerfile
   - See: `/app/backend/DEPLOYMENT_FIX.md`

2. **Frontend-Backend Connection**
   - Once backend is fixed, ensure frontend points to correct backend URL
   - Check environment variables in frontend build

---

## 📝 Next Steps

### To Fix Backend (Required):
```bash
# Option 1: Build locally and push
cd /your/local/backend
docker build -f Dockerfile.production -t alert-whisperer-backend:latest .
docker tag alert-whisperer-backend:latest 728925775278.dkr.ecr.us-east-1.amazonaws.com/alert-whisperer-backend:latest
docker push 728925775278.dkr.ecr.us-east-1.amazonaws.com/alert-whisperer-backend:latest
aws ecs update-service --cluster alert-whisperer-cluster --service alert-whisperer-backend-svc --force-new-deployment --region us-east-1

# Option 2: Use deployment script
cd /app/backend
bash deploy_aws.sh
```

### To Update Frontend (If Needed):
```bash
# Build React app
cd /app/frontend
npm run build

# Upload to S3
aws s3 sync build/ s3://alert-whisperer-frontend-728925775278/ --delete
```

---

## 🌍 Full Application URLs (After Fix)

**Frontend**: http://alertw-alb-1475356777.us-east-1.elb.amazonaws.com
**Backend API**: http://alert-whisperer-alb-1592907964.us-east-1.elb.amazonaws.com/api
**Health Check**: http://alert-whisperer-alb-1592907964.us-east-1.elb.amazonaws.com/api/agent/ping

---

## 📊 AWS Resources Summary

| Resource Type | Name/ID | Status | Region |
|--------------|---------|--------|--------|
| ECS Cluster | alert-whisperer-cluster | ✅ Active | us-east-1 |
| ECS Service | alert-whisperer-backend-svc | ⚠️ Unhealthy | us-east-1 |
| ECR Repo | alert-whisperer-backend | ✅ Active | us-east-1 |
| S3 Bucket | alert-whisperer-frontend-* | ✅ Active | us-east-1 |
| ALB | alert-whisperer-alb | ✅ Active | us-east-1 |
| ALB | alertw-alb | ✅ Active | us-east-1 |
| Account ID | 728925775278 | - | - |

---

## 💡 Key Points

1. **Both frontend and backend are configured in AWS**
2. **Frontend is working** - deployed to S3, served via ALB
3. **Backend has issues** - Docker image incomplete, container failing
4. **Fix is ready** - Dockerfile corrected, just needs rebuild
5. **Infrastructure is solid** - All AWS resources properly configured

