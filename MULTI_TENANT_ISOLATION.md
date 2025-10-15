# 🔐 Multi-Tenant Isolation Patterns for Alert Whisperer

> **Production-Grade MSP Data Isolation Strategies**
> How to securely isolate customer data in a multi-tenant SaaS architecture

---

## 🎯 Overview

**Challenge:** MSPs manage multiple clients (tenants) with strict data isolation requirements.

**Solution:** Implement defense-in-depth isolation using multiple layers:
1. API Key Authentication (Application Layer)
2. Database Partitioning (Data Layer)
3. AWS IAM Policies (Infrastructure Layer)
4. Cross-Account Roles (AWS Layer)

---

## 🛡️ Layer 1: API Key Authentication

### Current Implementation

**API Key Structure:**
```
awapi_comp-acme_abc123def456...
  └──────────────┬─────────────┘
          company_id (embedded for lookup)
```

**Authentication Flow:**
```python
# Webhook endpoint with API key
@app.post("/api/webhooks/alerts")
async def receive_alert(api_key: str = Query(...), alert: AlertWebhook):
    # 1. Extract company_id from API key
    company = await db.companies.find_one({"api_key": api_key})
    if not company:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # 2. Inject company_id into alert data
    alert_data = alert.dict()
    alert_data["company_id"] = company["id"]
    
    # 3. Store with tenant isolation
    await db.alerts.insert_one(alert_data)
    
    # All subsequent queries automatically filtered by company_id
    return {"status": "success", "company_id": company["id"]}
```

**Per-Tenant API Keys:**
- Each company has unique API key
- Keys stored securely (hashed + AWS Secrets Manager)
- Rotation supported without downtime
- Revocation immediate

---

## 📊 Layer 2: Database Isolation

### Current: MongoDB with Company ID Filtering

**All queries scoped by company_id:**
```python
# ❌ WRONG - No tenant isolation
await db.alerts.find({})

# ✅ CORRECT - Tenant-scoped query
await db.alerts.find({"company_id": "comp-acme"})

# ✅ CORRECT - Index for performance
await db.alerts.create_index([("company_id", 1), ("created_at", -1)])
```

**Data Model:**
```json
{
  "_id": "alert_12345",
  "company_id": "comp-acme",  // ← Tenant isolation key
  "asset_name": "server-prod-01",
  "signature": "disk_full",
  "severity": "critical",
  "message": "Disk usage 95%",
  "created_at": "2024-01-15T10:00:00Z"
}
```

**Isolation Guarantees:**
- Application-level enforcement
- All queries include `company_id` filter
- Indexes include `company_id` as first key
- Middleware validates tenant access

### Recommended: DynamoDB Multi-Tenant Patterns

**Why DynamoDB for Multi-Tenant SaaS:**
- Built-in tenant isolation via partition keys
- Automatic scaling per tenant
- Fine-grained IAM access control
- No cross-tenant query risk

**Single-Table Design:**

| PK (Partition Key) | SK (Sort Key) | Type | Attributes |
|--------------------|---------------|------|------------|
| TENANT#comp-acme | ALERT#2024-01-15#abc123 | alert | {severity, message, ...} |
| TENANT#comp-acme | INCIDENT#2024-01-15#def456 | incident | {priority, status, ...} |
| TENANT#comp-acme | CONFIG#webhook-security | config | {hmac_enabled, secret, ...} |
| TENANT#comp-acme | CONFIG#correlation | config | {time_window, auto, ...} |
| TENANT#comp-techstart | ALERT#2024-01-15#ghi789 | alert | {severity, message, ...} |

**Query Examples:**
```python
import boto3

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('alert-whisperer')

# Get all alerts for a company (single partition query)
response = table.query(
    KeyConditionExpression=Key('PK').eq('TENANT#comp-acme') & 
                          Key('SK').begins_with('ALERT#')
)

# Get specific incident
response = table.get_item(
    Key={
        'PK': 'TENANT#comp-acme',
        'SK': 'INCIDENT#2024-01-15#def456'
    }
)

# Cross-tenant query IMPOSSIBLE by design
# Each tenant is a separate partition
```

**Benefits:**
- **Physical Isolation:** Each tenant's data in separate partition
- **Performance:** No cross-tenant index scans
- **Cost Attribution:** Request metrics per tenant
- **Scalability:** Auto-scaling per partition key

**GSI (Global Secondary Index) for Cross-Tenant Queries (Admin Only):**
```
GSI: StatusIndex
PK: STATUS#new
SK: CREATED_AT#2024-01-15T10:00:00Z#TENANT#comp-acme

// Allows admin to query "all new incidents across all tenants"
// Still includes tenant ID for filtering
```

---

## 🔑 Layer 3: AWS IAM Policies

### Application-Level IAM

**Backend Service IAM Role:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:Query",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/alert-whisperer",
      "Condition": {
        "ForAllValues:StringLike": {
          "dynamodb:LeadingKeys": ["TENANT#*"]
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:alertwhisperer/*"
    },
    {
      "Effect": "Allow",
      "Action": ["ssm:SendCommand", "ssm:GetCommandInvocation"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {"ssm:resourceTag/ManagedBy": "AlertWhisperer"}
      }
    }
  ]
}
```

**Per-Tenant Service Accounts (Advanced):**
```json
// For strict isolation, create IAM user per tenant
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["dynamodb:*"],
    "Resource": "arn:aws:dynamodb:*:*:table/alert-whisperer",
    "Condition": {
      "ForAllValues:StringEquals": {
        "dynamodb:LeadingKeys": ["TENANT#comp-acme"]
      }
    }
  }]
}
```

---

## 🌍 Layer 4: Cross-Account IAM Roles (MSP → Client AWS)

### Architecture

```
┌─────────────────────────────────────────────────────┐
│           MSP ACCOUNT (111111111111)                    │
│                                                          │
│  Alert Whisperer Backend                                │
│  IAM Role: AlertWhispererServiceRole                    │
│                                                          │
│  When incident detected for Client A:                   │
│    1. Lookup Client A's AWS Account: 222222222222       │
│    2. Lookup External ID: "unique-ext-id-client-a"      │
│    3. AssumeRole into Client A's account                │
└─────────────────────────┬─────────────────────────┘
                         │ AssumeRole
                         │ (with External ID)
                         ▼
┌─────────────────────────┬─────────────────────────┐
│    CLIENT A ACCOUNT    │    CLIENT B ACCOUNT    │
│    (222222222222)      │    (333333333333)      │
│                        │                        │
│  IAM Role:            │  IAM Role:            │
│  AlertWhispererMSP    │  AlertWhispererMSP    │
│                        │                        │
│  Trust Policy:        │  Trust Policy:        │
│  - Principal: MSP     │  - Principal: MSP     │
│  - External ID:       │  - External ID:       │
│    "unique-ext-id-    │    "unique-ext-id-    │
│     client-a"         │     client-b"         │
│                        │                        │
│  Permissions:         │  Permissions:         │
│  - SSM Run Command    │  - SSM Run Command    │
│  - Patch Manager Read │  - Patch Manager Read │
│  - EC2 Describe       │  - EC2 Describe       │
└─────────────────────────┴─────────────────────────┘
```

### Setup Guide

**Step 1: Client Creates IAM Role (Trust Policy)**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-client-a-12345"
        }
      }
    }
  ]
}
```

**Critical: External ID prevents Confused Deputy attack**
- Unique per client
- Generated by MSP, shared securely with client
- Stored in Alert Whisperer database
- Never reused across clients

**Step 2: Client Attaches Permission Policy**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SSMRunCommand",
      "Effect": "Allow",
      "Action": [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:ListCommands"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PatchManagerReadOnly",
      "Effect": "Allow",
      "Action": [
        "ssm:DescribeInstancePatchStates",
        "ssm:DescribeInstancePatchStatesForPatchGroup",
        "ssm:DescribePatchBaselines",
        "ssm:GetPatchBaseline"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2ReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogsRead",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

**Step 3: MSP Stores Client Configuration**

```python
# In Alert Whisperer database
company = {
    "id": "comp-acme",
    "name": "Acme Corp",
    "api_key": "awapi_comp-acme_...",
    "aws_integration": {
        "enabled": True,
        "account_id": "222222222222",
        "role_arn": "arn:aws:iam::222222222222:role/AlertWhispererMSP",
        "external_id": "unique-external-id-client-a-12345",
        "region": "us-east-1"
    }
}
```

**Step 4: MSP Assumes Role When Needed**

```python
import boto3
from botocore.exceptions import ClientError

async def execute_ssm_runbook(company_id: str, instance_id: str, runbook: str):
    # 1. Get company AWS configuration
    company = await db.companies.find_one({"id": company_id})
    if not company.get("aws_integration", {}).get("enabled"):
        raise Exception("AWS integration not configured")
    
    aws_config = company["aws_integration"]
    
    # 2. Assume role into client account
    sts = boto3.client('sts')
    try:
        assumed_role = sts.assume_role(
            RoleArn=aws_config["role_arn"],
            RoleSessionName=f'AlertWhisperer-{company_id}-{int(time.time())}',
            ExternalId=aws_config["external_id"],
            DurationSeconds=900  # 15 minutes
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            raise Exception("AssumeRole failed - check External ID and trust policy")
        raise
    
    # 3. Create SSM client with temporary credentials
    ssm = boto3.client(
        'ssm',
        region_name=aws_config["region"],
        aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_role['Credentials']['SessionToken']
    )
    
    # 4. Execute runbook in CLIENT's AWS account
    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName=runbook,
        Comment=f'Executed by Alert Whisperer for incident resolution',
        CloudWatchOutputConfig={
            'CloudWatchLogGroupName': '/aws/ssm/alert-whisperer',
            'CloudWatchOutputEnabled': True
        }
    )
    
    command_id = response['Command']['CommandId']
    
    # 5. Store execution record
    await db.incidents.update_one(
        {"company_id": company_id, "asset_name": instance_id},
        {"$set": {
            "runbook_execution": {
                "command_id": command_id,
                "runbook": runbook,
                "executed_at": datetime.utcnow(),
                "aws_account": aws_config["account_id"]
            }
        }}
    )
    
    return command_id
```

### Security Benefits

**✅ No Long-Lived Credentials:**
- Temporary credentials (15-minute expiry)
- Automatically rotated each assume-role call
- No API keys to store or leak

**✅ Auditable:**
- CloudTrail logs in BOTH accounts
  - MSP account: `sts:AssumeRole` calls
  - Client account: All actions taken
- Session name includes company_id and timestamp

**✅ Easily Revocable:**
- Client can remove trust policy immediately
- In-flight sessions expire within 15 minutes
- No credential cleanup needed

**✅ Least Privilege:**
- Client controls exact permissions
- Can restrict to specific resources
- Can add conditions (e.g., MFA, source IP)

**✅ External ID Prevents Confused Deputy:**
- Unique secret per client
- Prevents MSP from being tricked into assuming wrong role
- Industry best practice for third-party access

---

## 📋 Data Model Examples

### MongoDB (Current)

```javascript
// Companies Collection
{
  "_id": "comp-acme",
  "name": "Acme Corp",
  "api_key": "awapi_comp-acme_abc123...",
  "aws_integration": {
    "enabled": true,
    "account_id": "222222222222",
    "role_arn": "arn:aws:iam::222222222222:role/AlertWhispererMSP",
    "external_id": "unique-ext-id-12345"
  }
}

// Alerts Collection (tenant-scoped)
{
  "_id": "alert_12345",
  "company_id": "comp-acme",  // ← Isolation key
  "asset_name": "server-prod-01",
  "signature": "disk_full",
  "severity": "critical"
}

// Incidents Collection (tenant-scoped)
{
  "_id": "incident_67890",
  "company_id": "comp-acme",  // ← Isolation key
  "alert_ids": ["alert_12345", "alert_12346"],
  "priority_score": 92.0,
  "status": "resolved",
  "runbook_execution": {
    "command_id": "abc-123-def",
    "runbook": "SSM-DiskCleanup-001"
  }
}
```

### DynamoDB (Recommended)

```javascript
// Single Table - Alerts
{
  "PK": "TENANT#comp-acme",
  "SK": "ALERT#2024-01-15T10:00:00Z#alert_12345",
  "Type": "alert",
  "asset_name": "server-prod-01",
  "signature": "disk_full",
  "severity": "critical",
  "GSI1PK": "SEVERITY#critical",  // For cross-tenant queries
  "GSI1SK": "2024-01-15T10:00:00Z#TENANT#comp-acme"
}

// Single Table - Incidents
{
  "PK": "TENANT#comp-acme",
  "SK": "INCIDENT#2024-01-15T10:05:00Z#incident_67890",
  "Type": "incident",
  "alert_ids": ["alert_12345", "alert_12346"],
  "priority_score": 92,
  "status": "resolved",
  "runbook_execution": {
    "command_id": "abc-123-def",
    "runbook": "SSM-DiskCleanup-001"
  },
  "GSI1PK": "STATUS#resolved",
  "GSI1SK": "2024-01-15T10:15:00Z#TENANT#comp-acme"
}

// Single Table - Configuration
{
  "PK": "TENANT#comp-acme",
  "SK": "CONFIG#aws-integration",
  "Type": "config",
  "aws_account_id": "222222222222",
  "role_arn": "arn:aws:iam::222222222222:role/AlertWhispererMSP",
  "external_id": "unique-ext-id-12345"
}
```

---

## ✅ Isolation Verification Checklist

### Application Code Review
- [ ] All database queries include `company_id` filter
- [ ] API endpoints validate company_id from API key
- [ ] No direct tenant ID passed from client (derive from auth)
- [ ] Middleware enforces tenant context
- [ ] Unit tests verify cross-tenant access fails

### Database Configuration
- [ ] Indexes include tenant ID as first key
- [ ] No queries without tenant filter
- [ ] Connection pooling doesn't leak tenant context
- [ ] Query logging includes tenant ID

### AWS IAM
- [ ] Service role has minimal permissions
- [ ] Cross-account roles use External ID
- [ ] CloudTrail logging enabled
- [ ] Session names include tenant identifier
- [ ] Temporary credentials with short expiry

### Testing
- [ ] Attempt to access other tenant's data (should fail)
- [ ] Verify query performance with tenant filter
- [ ] Test AssumeRole with wrong External ID (should fail)
- [ ] Load test tenant isolation under concurrency

---

## 📚 References

- [AWS Multi-Tenant SaaS Patterns](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-api-access-authorization/welcome.html)
- [DynamoDB Multi-Tenant Design](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-api-access-authorization/dynamodb.html)
- [Cross-Account IAM Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html)
- [External ID Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)
- [Confused Deputy Problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)

---

**Document Version:** 1.0  
**Last Updated:** 2024-01-15  
**Security Level:** Production-Ready
