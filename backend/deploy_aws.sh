#!/bin/bash
# Deploy to AWS ECR + ECS
set -e

REGION=${AWS_REGION:-"us-east-1"}
ACCOUNT_ID=${AWS_ACCOUNT_ID}
REPO_NAME="alert-whisperer-agent"
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "manual")

echo "🚀 Deploying Alert Whisperer Agent to AWS"
echo "   Region: $REGION"
echo "   Repository: $REPO_NAME"
echo "   Version: $GIT_SHA"

# Login to ECR
echo "🔑 Logging into ECR..."
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# Build image
echo "🛠️  Building Docker image..."
docker build -f Dockerfile.production -t $REPO_NAME:$GIT_SHA -t $REPO_NAME:latest .

# Tag image
echo "🏷️  Tagging image..."
docker tag $REPO_NAME:$GIT_SHA $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:$GIT_SHA
docker tag $REPO_NAME:latest $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:latest

# Push to ECR
echo "📤 Pushing to ECR..."
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:$GIT_SHA
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:latest

echo "✅ Deployment complete!"
echo "   Image: $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:$GIT_SHA"
echo ""
echo "Next steps:"
echo "1. Update ECS task definition with new image"
echo "2. Deploy to ECS service"
echo "3. Verify health check: https://your-domain.com/api/agent/ping"
