# 🚀 AWS Bedrock Agent Setup Guide

> **Complete guide to configure AWS credentials and deploy Alert Whisperer with AWS Bedrock integration**

---

## 📋 Prerequisites

Before enabling AWS Bedrock integration, you need:

1. **AWS Account** with appropriate permissions
2. **AWS CLI** installed (optional but recommended)
3. **Bedrock Model Access** enabled in your AWS region

---

## 🔑 Required AWS Credentials

Alert Whisperer needs the following AWS credentials to integrate with Bedrock:

### Option 1: IAM User Credentials (Recommended for Testing)

**What you need:**
- AWS Access Key ID
- AWS Secret Access Key
- AWS Region (e.g., `us-east-1`)

**Where to provide them:**
```bash
# Add to backend/.env file
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
```

**How to get them:**
1. Go to AWS Console → IAM → Users
2. Select your user or create new one
3. Click "Security credentials" tab
4. Click "Create access key"
5. Choose "Application running outside AWS"
6. Copy both Access Key ID and Secret Access Key

### Option 2: IAM Role (Recommended for Production)

**For EC2/ECS/Lambda deployments:**
- Attach IAM role to your compute instance
- No credentials needed in .env file
- Role must have Bedrock permissions (see below)

---

## 🎯 Required IAM Permissions

Your IAM user or role needs these permissions:

### Minimum Permissions Policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeAgent",
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": [
        "arn:aws:bedrock:*:*:agent/*",
        "arn:aws:bedrock:*::foundation-model/*"
      ]
    }
  ]
}
```

### How to attach this policy:

1. Go to AWS Console → IAM → Policies
2. Click "Create policy"
3. Choose "JSON" tab
4. Paste the policy above
5. Name it: `AlertWhispererBedrockAccess`
6. Attach to your IAM user or role

---

## 🤖 Enable Bedrock Model Access

Before using Bedrock models, you must request access:

### Step 1: Request Model Access

1. Go to AWS Console → Amazon Bedrock
2. Click "Model access" in left sidebar
3. Click "Manage model access"
4. Select models you want:
   - ✅ **Claude 3.5 Sonnet v2** (Recommended - best reasoning)
   - ✅ **Claude 3 Haiku** (Fast, cost-effective)
   - ✅ **Claude 3 Opus** (Most capable, slower)
5. Click "Request model access"
6. Wait for approval (usually instant for Claude models)

### Step 2: Verify Access

```bash
# Using AWS CLI
aws bedrock list-foundation-models --region us-east-1

# Should show Claude models with "modelLifecycle": "ACTIVE"
```

---

## ⚙️ Configuration Options

Add these environment variables to `/app/backend/.env`:

### Basic Configuration:

```bash
# AWS Credentials (Option 1: IAM User)
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_REGION=us-east-1

# Agent Provider Selection
AGENT_PROVIDER=bedrock-runtime
# Options:
#   - gemini (default): Google Gemini
#   - bedrock-runtime: Direct Bedrock model calls (recommended)
#   - bedrock-managed: Use Bedrock managed agents (requires agent setup)
#   - rules: Pure deterministic rules (no AI)

# Bedrock Model Selection
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
# Options:
#   - anthropic.claude-3-5-sonnet-20241022-v2:0 (Claude 3.5 Sonnet v2)
#   - anthropic.claude-3-haiku-20240307-v1:0 (Claude 3 Haiku)
#   - anthropic.claude-3-opus-20240229-v1:0 (Claude 3 Opus)
```

### Advanced Configuration (Managed Agents):

If you want to use AWS Bedrock managed agents (with action groups, knowledge bases):

```bash
# Use managed agent
AGENT_PROVIDER=bedrock-managed
USE_BEDROCK_MANAGED_AGENT=true

# Your Bedrock Agent details
BEDROCK_AGENT_ID=ABCDEFGHIJ
BEDROCK_AGENT_ALIAS_ID=TSTALIASID

# Model for direct inference (fallback)
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
```

---

## 🧪 Testing Your Setup

### 1. Test AWS Credentials

```bash
# From /app/backend directory
python3 -c "
import boto3
import os

# Load credentials from environment
region = os.getenv('AWS_REGION', 'us-east-1')

try:
    # Test Bedrock client
    client = boto3.client('bedrock-runtime', region_name=region)
    print('✅ AWS credentials are valid')
    print(f'✅ Bedrock client initialized (region: {region})')
except Exception as e:
    print(f'❌ Error: {e}')
"
```

### 2. Test Bedrock Model Access

```bash
# Test if you can invoke Claude
python3 -c "
import boto3
import json
import os

client = boto3.client('bedrock-runtime', region_name=os.getenv('AWS_REGION', 'us-east-1'))

try:
    response = client.invoke_model(
        modelId='anthropic.claude-3-5-sonnet-20241022-v2:0',
        body=json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 100,
            'messages': [{'role': 'user', 'content': 'Say hello'}]
        })
    )
    result = json.loads(response['body'].read())
    print('✅ Bedrock model access working')
    print(f'Response: {result[\"content\"][0][\"text\"]}')
except Exception as e:
    print(f'❌ Model access error: {e}')
    print('👉 Make sure you requested model access in Bedrock console')
"
```

### 3. Test Agent Health Endpoint

```bash
# Restart backend with new configuration
cd /app/backend
sudo supervisorctl restart backend

# Check agent health
curl http://localhost:8001/api/agent/ping | jq

# Should show:
# {
#   "status": "ok",
#   "provider": "bedrock-runtime",
#   "providers_available": {
#     "gemini": false,
#     "bedrock": true,
#     "rules": true
#   },
#   "ready_for_agentcore": true
# }
```

### 4. Test Decision Making

```bash
# Make a test decision request
curl -X POST http://localhost:8001/api/agent/decide \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "test-inc-001",
    "company_id": "comp-test",
    "incident_data": {
      "severity": "high",
      "signature": "disk_full",
      "alert_count": 5,
      "affected_assets": ["server-01"]
    },
    "stream": false
  }' | jq

# Should return a decision with recommendation and reasoning
```

---

## 🎯 Quick Start Commands

### Complete Setup (Copy-Paste):

```bash
# 1. Navigate to backend directory
cd /app/backend

# 2. Open .env file
nano .env

# 3. Add these lines (replace with your actual values):
# AWS_ACCESS_KEY_ID=your_key_here
# AWS_SECRET_ACCESS_KEY=your_secret_here
# AWS_REGION=us-east-1
# AGENT_PROVIDER=bedrock-runtime
# BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0

# 4. Save and exit (Ctrl+X, Y, Enter)

# 5. Restart backend
sudo supervisorctl restart backend

# 6. Verify it's working
curl http://localhost:8001/api/agent/ping | jq
```

---

## 📊 Cost Estimates

### Claude 3.5 Sonnet v2 Pricing (us-east-1):
- **Input**: $3.00 per 1M tokens
- **Output**: $15.00 per 1M tokens

### Typical Decision Request:
- Input tokens: ~500 tokens (incident details + context)
- Output tokens: ~200 tokens (recommendation)
- **Cost per decision**: ~$0.004 (less than half a cent)

### Monthly estimates (1000 decisions):
- **1,000 decisions/month**: ~$4
- **10,000 decisions/month**: ~$40
- **100,000 decisions/month**: ~$400

**Free Tier**: Bedrock has no free tier, but costs are very low for typical MSP usage.

---

## 🐛 Troubleshooting

### Issue: "boto3 not available"

**Solution:**
```bash
cd /app/backend
pip install boto3 botocore
sudo supervisorctl restart backend
```

### Issue: "Bedrock client initialization failed"

**Possible causes:**
1. AWS credentials not set correctly
2. AWS region not set
3. IAM permissions missing

**Solution:**
```bash
# Check credentials are loaded
python3 -c "import os; print(os.getenv('AWS_ACCESS_KEY_ID'))"

# Should output your access key (first few characters)
# If empty, credentials are not loaded
```

### Issue: "Model access error" or 403

**Possible causes:**
1. Model access not requested in Bedrock console
2. Model ID incorrect
3. Region doesn't support that model

**Solution:**
1. Go to Bedrock console → Model access
2. Request access to Claude models
3. Wait for approval (usually instant)
4. Verify with: `aws bedrock list-foundation-models`

### Issue: Agent still using Gemini

**Solution:**
```bash
# Check current configuration
curl http://localhost:8001/api/agent/ping | jq '.provider'

# Should show "bedrock-runtime"
# If shows "gemini", env vars not loaded

# Force reload:
sudo supervisorctl restart backend
```

---

## 🚀 Deployment to AWS AgentCore Runtime

### Container Preparation:

```bash
# Build Docker image
cd /app/backend
docker build -t alert-whisperer-agent:latest .

# Tag for ECR
docker tag alert-whisperer-agent:latest \
  your-account.dkr.ecr.us-east-1.amazonaws.com/alert-whisperer-agent:latest

# Push to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  your-account.dkr.ecr.us-east-1.amazonaws.com

docker push your-account.dkr.ecr.us-east-1.amazonaws.com/alert-whisperer-agent:latest
```

### AgentCore Deployment:

```bash
# Deploy to AgentCore Runtime
aws bedrock-agent-runtime deploy-agent \
  --agent-name alert-whisperer-decision-agent \
  --container-image your-account.dkr.ecr.us-east-1.amazonaws.com/alert-whisperer-agent:latest \
  --health-check-path /api/agent/ping \
  --port 8001 \
  --environment-variables \
    AWS_REGION=us-east-1 \
    AGENT_PROVIDER=bedrock-runtime \
    BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
```

---

## 📚 Additional Resources

- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- [Bedrock Agent Runtime API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_Operations_Agents_for_Amazon_Bedrock_Runtime.html)
- [Claude Model IDs](https://docs.aws.amazon.com/bedrock/latest/userguide/model-ids-arns.html)
- [AgentCore Runtime Guide](https://docs.aws.amazon.com/bedrock/latest/userguide/agentcore-runtime.html)

---

## ✅ Configuration Checklist

- [ ] AWS credentials configured in backend/.env
- [ ] AWS region set (e.g., us-east-1)
- [ ] IAM permissions policy created and attached
- [ ] Bedrock model access requested and approved
- [ ] AGENT_PROVIDER set to bedrock-runtime or bedrock-managed
- [ ] BEDROCK_MODEL_ID configured
- [ ] Backend restarted after configuration
- [ ] Health endpoint returns "bedrock" as provider
- [ ] Test decision request successful

---

**Need Help?** Check the troubleshooting section or verify each step in the checklist above.
