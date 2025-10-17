# 🚀 AWS Bedrock AgentCore Runtime Deployment Guide

> **Production-grade deployment of Alert Whisperer Decision Agent on AWS Bedrock AgentCore Runtime**

---

## 📋 Overview

This guide walks you through deploying the Alert Whisperer Decision Agent to AWS Bedrock AgentCore Runtime, which provides:

- ✅ **Managed Agent Hosting**: Serverless, auto-scaling agent runtime
- ✅ **Health-Probed**: Automatic health checks via `/api/agent/ping` endpoint
- ✅ **Streaming Capable**: Low-latency SSE streaming for real-time decisions
- ✅ **Memory Management**: Built-in sessionId/memoryId support
- ✅ **Long-Running Sessions**: Support for multi-turn conversations
- ✅ **Remote Invocation**: URL-addressable agent for distributed systems

---

## 🎯 Architecture Alignment

### Current Implementation → AWS Bedrock AgentCore

| Feature | Alert Whisperer | AgentCore Runtime | Status |
|---------|----------------|-------------------|---------|
| Health Endpoint | `GET /api/agent/ping` | Required | ✅ Implemented |
| Streaming | SSE format | SSE/WebSocket | ✅ Compatible |
| Memory | sessionId/memoryId | sessionId/memoryId | ✅ Aligned |
| Agent Runtime | FastAPI + Docker | Containerized | ✅ Ready |
| Model Support | Gemini + Bedrock | Any model | ✅ Multi-provider |
| Tools/Actions | Tools registry | External tools | ✅ Integrated |

---

## 🐳 Container Preparation

### Step 1: Review Dockerfile

Alert Whisperer backend already has a production Dockerfile:

```bash
# View current Dockerfile
cat /app/backend/Dockerfile.production
```

### Step 2: Build Container Image

```bash
cd /app/backend

# Build Docker image for AgentCore
docker build -f Dockerfile.production -t alert-whisperer-agent:latest .

# Test locally first
docker run -p 8001:8001 \
  -e AWS_REGION=us-east-1 \
  -e AGENT_PROVIDER=bedrock-runtime \
  -e BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0 \
  -e MONGO_URL=mongodb://your-mongo-host:27017 \
  alert-whisperer-agent:latest

# Test health endpoint
curl http://localhost:8001/api/agent/ping
```

Expected response:
```json
{
  "status": "ok",
  "uptime_s": 10,
  "version": "dev",
  "commit": "dev",
  "provider": "bedrock-runtime",
  "providers_available": {
    "gemini": false,
    "bedrock": true,
    "rules": true
  },
  "ready_for_agentcore": true
}
```

---

## 📦 Push to AWS ECR

### Step 1: Create ECR Repository

```bash
# Set your AWS account ID and region
AWS_ACCOUNT_ID=123456789012
AWS_REGION=us-east-1

# Create ECR repository
aws ecr create-repository \
  --repository-name alert-whisperer-agent \
  --region $AWS_REGION \
  --image-scanning-configuration scanOnPush=true
```

### Step 2: Authenticate Docker to ECR

```bash
# Get ECR login credentials
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
```

### Step 3: Tag and Push Image

```bash
# Tag image for ECR
docker tag alert-whisperer-agent:latest \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/alert-whisperer-agent:latest

# Push to ECR
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/alert-whisperer-agent:latest

# Verify
aws ecr describe-images \
  --repository-name alert-whisperer-agent \
  --region $AWS_REGION
```

---

## 🚀 Deploy to AgentCore Runtime

### Option 1: Using AWS Console

1. **Navigate to Bedrock Console**
   - Go to AWS Console → Amazon Bedrock
   - Click "Agents" → "Agent runtimes"

2. **Create New Agent Runtime**
   - Click "Create agent runtime"
   - Name: `alert-whisperer-decision-agent`
   - Description: "MSP incident decision agent with rules + AI"

3. **Configure Container**
   - Container image URI: `$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/alert-whisperer-agent:latest`
   - Port: `8001`
   - Health check path: `/api/agent/ping`
   - Health check interval: `30 seconds`
   - Health check timeout: `5 seconds`

4. **Environment Variables**
   ```
   AWS_REGION=us-east-1
   AGENT_PROVIDER=bedrock-runtime
   BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
   MONGO_URL=your-mongodb-connection-string
   MAX_TOKENS_PER_DECISION=2000
   MAX_DECISION_TIME_SECONDS=30
   ```

5. **IAM Role**
   - Create or select IAM role with:
     - `bedrock:InvokeModel` permission
     - `bedrock:InvokeModelWithResponseStream` permission
     - Access to your MongoDB (if using DocumentDB)

6. **Scaling Configuration**
   - Min instances: `1`
   - Max instances: `10`
   - Target CPU utilization: `70%`

7. **Deploy**
   - Click "Create agent runtime"
   - Wait for deployment (5-10 minutes)

### Option 2: Using AWS CLI/CloudFormation

Create a CloudFormation template (`agentcore-deployment.yaml`):

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Alert Whisperer Agent on Bedrock AgentCore Runtime'

Parameters:
  AgentImageUri:
    Type: String
    Description: 'ECR image URI for agent container'
  
  MongoDBConnectionString:
    Type: String
    Description: 'MongoDB connection string'
    NoEcho: true

Resources:
  AgentExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: bedrock.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonBedrockFullAccess
      Policies:
        - PolicyName: BedrockInvoke
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - bedrock:InvokeModel
                  - bedrock:InvokeModelWithResponseStream
                Resource: '*'

  AlertWhispererAgent:
    Type: AWS::Bedrock::AgentRuntime
    Properties:
      AgentName: alert-whisperer-decision-agent
      Description: 'MSP incident decision agent'
      ContainerConfiguration:
        Image: !Ref AgentImageUri
        Port: 8001
        HealthCheck:
          Path: /api/agent/ping
          IntervalSeconds: 30
          TimeoutSeconds: 5
          HealthyThresholdCount: 2
          UnhealthyThresholdCount: 3
      EnvironmentVariables:
        - Name: AWS_REGION
          Value: !Ref AWS::Region
        - Name: AGENT_PROVIDER
          Value: bedrock-runtime
        - Name: BEDROCK_MODEL_ID
          Value: anthropic.claude-3-5-sonnet-20241022-v2:0
        - Name: MONGO_URL
          Value: !Ref MongoDBConnectionString
      ExecutionRoleArn: !GetAtt AgentExecutionRole.Arn
      AutoScalingConfiguration:
        MinCapacity: 1
        MaxCapacity: 10
        TargetValue: 70

Outputs:
  AgentEndpoint:
    Description: 'Agent runtime endpoint URL'
    Value: !GetAtt AlertWhispererAgent.EndpointUrl
  
  AgentArn:
    Description: 'Agent runtime ARN'
    Value: !GetAtt AlertWhispererAgent.Arn
```

Deploy:

```bash
aws cloudformation create-stack \
  --stack-name alert-whisperer-agentcore \
  --template-body file://agentcore-deployment.yaml \
  --parameters \
    ParameterKey=AgentImageUri,ParameterValue=$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/alert-whisperer-agent:latest \
    ParameterKey=MongoDBConnectionString,ParameterValue="mongodb://..." \
  --capabilities CAPABILITY_IAM \
  --region $AWS_REGION

# Wait for completion
aws cloudformation wait stack-create-complete \
  --stack-name alert-whisperer-agentcore \
  --region $AWS_REGION

# Get agent endpoint
aws cloudformation describe-stacks \
  --stack-name alert-whisperer-agentcore \
  --query 'Stacks[0].Outputs[?OutputKey==`AgentEndpoint`].OutputValue' \
  --output text
```

---

## 🧪 Testing the Deployment

### 1. Health Check

```bash
# Get agent endpoint from CloudFormation outputs
AGENT_ENDPOINT=$(aws cloudformation describe-stacks \
  --stack-name alert-whisperer-agentcore \
  --query 'Stacks[0].Outputs[?OutputKey==`AgentEndpoint`].OutputValue' \
  --output text)

# Test health
curl $AGENT_ENDPOINT/api/agent/ping | jq
```

### 2. Make a Decision Request

```bash
# Non-streaming decision
curl -X POST $AGENT_ENDPOINT/api/agent/decide \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "inc-test-001",
    "company_id": "comp-acme",
    "incident_data": {
      "severity": "critical",
      "signature": "disk_full_critical",
      "alert_count": 15,
      "affected_assets": ["server-prod-01", "server-prod-02"],
      "priority_score": 95
    },
    "stream": false
  }' | jq
```

### 3. Test Streaming

```bash
# Streaming decision (SSE)
curl -N -X POST $AGENT_ENDPOINT/api/agent/decide \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "inc-test-002",
    "company_id": "comp-acme",
    "incident_data": {
      "severity": "high",
      "signature": "memory_leak",
      "alert_count": 8
    },
    "stream": true
  }'

# Should stream chunks in SSE format:
# event: start
# data: {}
# 
# event: memory
# data: {"session_id": "inc-test-002", "memory_id": "comp-acme"}
# 
# data: "Analyzing incident..."
# ...
```

### 4. Verify Memory Persistence

```bash
# Make first decision
curl -X POST $AGENT_ENDPOINT/api/agent/decide \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "inc-memory-test",
    "company_id": "comp-acme",
    "incident_data": {"severity": "high", "signature": "test"}
  }' | jq '.decision_id'

# Make another decision with same incident_id (should have context)
curl -X POST $AGENT_ENDPOINT/api/agent/decide \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "inc-memory-test",
    "company_id": "comp-acme",
    "incident_data": {"severity": "high", "signature": "test_followup"}
  }' | jq '.reasoning'

# Should reference previous decision in reasoning
```

---

## 🔄 Update Strategy

### Rolling Updates:

```bash
# Build new version
docker build -f Dockerfile.production -t alert-whisperer-agent:v2 .

# Tag for ECR
docker tag alert-whisperer-agent:v2 \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/alert-whisperer-agent:v2

# Push
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/alert-whisperer-agent:v2

# Update CloudFormation stack
aws cloudformation update-stack \
  --stack-name alert-whisperer-agentcore \
  --use-previous-template \
  --parameters \
    ParameterKey=AgentImageUri,ParameterValue=$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/alert-whisperer-agent:v2 \
  --capabilities CAPABILITY_IAM

# AgentCore will perform rolling update with zero downtime
```

---

## 📊 Monitoring & Observability

### CloudWatch Metrics:

```bash
# View agent runtime metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Bedrock/AgentRuntime \
  --metric-name RequestCount \
  --dimensions Name=AgentName,Value=alert-whisperer-decision-agent \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 300 \
  --statistics Sum
```

### Key Metrics to Monitor:

- **RequestCount**: Total agent invocations
- **Latency**: P50, P95, P99 response times
- **ErrorRate**: Failed requests percentage
- **HealthCheckStatus**: Agent health
- **TokensUsed**: Bedrock model tokens consumed
- **StreamingDuration**: Time for streaming responses

### CloudWatch Logs:

```bash
# View agent logs
aws logs tail /aws/bedrock/agentruntime/alert-whisperer-decision-agent \
  --follow \
  --format short
```

---

## 💰 Cost Optimization

### Bedrock Model Costs:

| Model | Input (per 1M tokens) | Output (per 1M tokens) | Typical Decision Cost |
|-------|----------------------|------------------------|----------------------|
| Claude 3.5 Sonnet v2 | $3.00 | $15.00 | $0.004 |
| Claude 3 Haiku | $0.25 | $1.25 | $0.0003 |

### AgentCore Runtime Costs:

- **Compute**: Pay for container uptime (similar to Fargate)
- **Requests**: Minimal per-request charge
- **Data Transfer**: Standard AWS data transfer rates

### Cost Optimization Tips:

1. **Use Haiku for Simple Cases**: Route low-severity incidents to Claude 3 Haiku
2. **Implement Caching**: Cache common decisions for 5-10 minutes
3. **Adjust Auto-Scaling**: Set appropriate min/max instances
4. **Use Deterministic Rules**: Fallback to rules engine when possible

---

## 🔒 Security Best Practices

### 1. Secrets Management

Use AWS Secrets Manager for sensitive values:

```bash
# Store MongoDB connection string
aws secretsmanager create-secret \
  --name alert-whisperer/mongodb-url \
  --secret-string "mongodb://..."

# Update container to use secret
# Add to CloudFormation:
# EnvironmentVariables:
#   - Name: MONGO_URL
#     ValueFrom: arn:aws:secretsmanager:region:account:secret:alert-whisperer/mongodb-url
```

### 2. IAM Least Privilege

Ensure agent role only has necessary permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet-*",
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-haiku-*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/bedrock/agentruntime/*"
    }
  ]
}
```

### 3. Network Security

- Deploy in private subnets with NAT gateway
- Use VPC endpoints for Bedrock and Secrets Manager
- Implement API Gateway with WAF for public access

---

## 📚 Additional Resources

- [AWS Bedrock Agent Runtime Documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-runtime.html)
- [Bedrock Agent Runtime API Reference](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_Operations_Agents_for_Amazon_Bedrock_Runtime.html)
- [Claude Model Documentation](https://docs.anthropic.com/claude/docs)
- [AgentCore Best Practices](https://docs.aws.amazon.com/bedrock/latest/userguide/agentcore-best-practices.html)

---

## ✅ Deployment Checklist

- [ ] Container image built and tested locally
- [ ] ECR repository created
- [ ] Image pushed to ECR
- [ ] IAM role created with Bedrock permissions
- [ ] MongoDB connection string secured in Secrets Manager
- [ ] CloudFormation stack deployed
- [ ] Health check endpoint responding
- [ ] Test decision request successful
- [ ] Streaming endpoint working
- [ ] Memory persistence verified
- [ ] CloudWatch metrics visible
- [ ] CloudWatch logs accessible
- [ ] Auto-scaling configured
- [ ] Cost monitoring enabled

---

**Ready for production!** 🎉

Your Alert Whisperer Decision Agent is now running on AWS Bedrock AgentCore Runtime with:
- Managed infrastructure
- Auto-scaling
- Health monitoring
- Streaming support
- Memory management
- AWS-native integration
