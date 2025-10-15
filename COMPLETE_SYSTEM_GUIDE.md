# Alert Whisperer - Complete System Guide

## 🎯 Overview

Alert Whisperer is a **production-grade MSP platform** with **AWS Agent Core** integration for intelligent incident response. This guide covers architecture, deployment, and reproduction steps for judges and developers.

---

## 📋 Table of Contents

1. [System Architecture](#system-architecture)
2. [Agent Core Pattern](#agent-core-pattern)
3. [Authentication & Security](#authentication--security)
4. [Memory System](#memory-system)
5. [Tool Interfaces](#tool-interfaces)
6. [Deployment](#deployment)
7. [API Reference](#api-reference)
8. [How to Reproduce](#how-to-reproduce)
9. [Production Checklist](#production-checklist)

---

## 🏗️ System Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Alert Whisperer Platform                 │
├─────────────────────────────────────────────────────────────┤
│  Frontend (React)                                            │
│  ├── Real-Time Dashboard (WebSocket)                        │
│  ├── Incident Management                                     │
│  ├── Approval Workflows                                      │
│  └── RBAC & Audit Logs                                       │
├─────────────────────────────────────────────────────────────┤
│  Backend (FastAPI)                                           │
│  ├── REST API (/api/*)                                       │
│  ├── WebSocket Real-Time (/ws)                              │
│  ├── Agent Core (/api/agent/*)                              │
│  ├── Webhook Ingestion (HMAC-SHA256)                        │
│  └── Multi-Tenant Isolation                                 │
├─────────────────────────────────────────────────────────────┤
│  Agent Services                                              │
│  ├── Decision Engine (Local or Bedrock)                     │
│  ├── Memory Service (Short-term + Long-term)                │
│  ├── Tool Registry (SSM, CloudWatch, Approvals)             │
│  └── Streaming Decisions (SSE)                              │
├─────────────────────────────────────────────────────────────┤
│  Data Layer (MongoDB)                                        │
│  ├── Alerts, Incidents, Companies                           │
│  ├── Short-term Memory (TTL 48h)                            │
│  ├── Long-term Memory (Indexed)                             │
│  └── Audit Logs (Immutable)                                 │
├─────────────────────────────────────────────────────────────┤
│  AWS Integrations                                            │
│  ├── Systems Manager (SSM Run Command)                      │
│  ├── CloudWatch (Alarms + Metrics)                          │
│  ├── Secrets Manager (API Keys)                             │
│  └── Bedrock Agent (Optional)                               │
└─────────────────────────────────────────────────────────────┘
```

### Key Patterns

1. **Multi-Tenant Isolation**
   - Per-company API keys
   - Data partitioning by `company_id`
   - Role-based access control (RBAC)

2. **Event-Driven Correlation**
   - Deterministic rule engine with optional AI
   - Configurable time windows (5-15 min)
   - Aggregation keys for intelligent grouping

3. **Hybrid AI + Rules**
   - Deterministic fallback for simple cases
   - AI-powered decisions for complex scenarios (Gemini 2.5 Pro, optional)
   - Confidence scoring for transparency

---

## 🤖 Agent Core Pattern

### Architecture Alignment

Alert Whisperer implements the **AWS Agent Core** pattern:

```
┌───────────────────────────────────────────────────────┐
│                    Agent Runtime                       │
│  ├── Health Probes (/ping)                            │
│  ├── Lifecycle Management (SIGTERM)                   │
│  ├── Version Tracking (GIT_SHA)                       │
│  └── Session Continuity (8-hour cap)                  │
└───────────────────────────────────────────────────────┘
         ↓
┌───────────────────────────────────────────────────────┐
│              Decision Agent (/api/agent/decide)       │
│  ├── Streaming Mode (SSE)                             │
│  ├── Non-streaming Mode (JSON)                        │
│  ├── Memory Context (short + long-term)               │
│  └── Tool Calls (SSM, CloudWatch, Approvals)          │
└───────────────────────────────────────────────────────┘
         ↓
┌───────────────────────────────────────────────────────┐
│                    Tool Registry                       │
│  ├── ssm.execute(commands, instance_ids)              │
│  ├── cloudwatch.get_alarm(alarm_name)                 │
│  ├── cloudwatch.query_metrics(...)                    │
│  ├── approvals.request(runbook_id, risk_level)        │
│  ├── approvals.status(approval_id)                    │
│  └── kpi.snapshot() → before/after impact             │
└───────────────────────────────────────────────────────┘
```

### Agent Endpoints

#### Health Check
```bash
GET /api/agent/ping
Response: {
  "status": "ok",
  "uptime_s": 3600,
  "version": "abc123",
  "commit": "abc123",
  "mode": "local"  # or "remote"
}
```

#### Decision Request (Non-Streaming)
```bash
POST /api/agent/decide
Content-Type: application/json

{
  "incident_id": "inc-123",
  "company_id": "comp-acme",
  "incident_data": {
    "severity": "high",
    "signature": "disk-space-critical",
    "alert_count": 5,
    "affected_assets": ["server-01"]
  },
  "memory_context": {},
  "stream": false
}

Response: {
  "decision_id": "dec-abc123",
  "incident_id": "inc-123",
  "recommendation": "Execute disk cleanup runbook",
  "confidence": 0.9,
  "tool_calls": [{
    "tool_name": "ssm.execute",
    "parameters": {"runbook": "disk-cleanup"}
  }],
  "reasoning": "Deterministic rule matched: disk-space-critical",
  "tokens_used": 0,
  "duration_ms": 45,
  "created_at": "2025-01-25T10:30:00Z"
}
```

#### Streaming Decision (SSE)
```bash
POST /api/agent/decide
Content-Type: application/json
Accept: text/event-stream

{
  "incident_id": "inc-123",
  "company_id": "comp-acme",
  "incident_data": {...},
  "stream": true
}

# SSE Response:
event: start
data: {}

event: memory
data: {"loaded": true}

data: "Analyzing incident..."
data: "Disk space critical on server-01"
data: "Recommending: Execute disk cleanup runbook"

event: end
data: {}
```

### Remote Invocation (Bedrock Agent)

```python
import boto3
import json

def invoke_remote_agent(agent_arn: str, incident_data: dict):
    bedrock = boto3.client("bedrock-agent-runtime", region_name="us-east-1")
    
    response = bedrock.invoke_agent(
        agentAliasId=agent_arn.split("/")[-1],
        agentId=agent_arn.split("/")[-3],
        sessionId=incident_data.get("incident_id", "demo"),
        inputText=json.dumps(incident_data)
    )
    
    return response
```

**Feature Flag:**
```bash
# .env
AGENT_MODE=local   # Use local deterministic + Gemini (optional)
AGENT_MODE=remote  # Use Bedrock Agent
```

---

## 🔐 Authentication & Security

### OWASP-Compliant Token System

**Before (OLD - Non-compliant):**
- Access token: 720 hours (30 days) ❌

**After (NEW - OWASP-compliant):**
- Access token: 30 minutes ✅
- Refresh token: 7 days ✅

### Token Flow

```bash
# 1. Login
POST /api/auth/login
{
  "email": "admin@alertwhisperer.com",
  "password": "admin123"
}

Response:
{
  "access_token": "eyJhbGci...",  # 30 minutes
  "refresh_token": "eyJhbGci...",  # 7 days
  "token_type": "bearer",
  "user": {...}
}

# 2. Use access token (expires after 30 minutes)
GET /api/incidents
Authorization: Bearer <access_token>

# 3. Refresh when access token expires
POST /api/auth/refresh
Authorization: Bearer <refresh_token>

Response:
{
  "access_token": "eyJhbGci...",  # NEW 30-minute token
  "refresh_token": "eyJhbGci...",  # NEW 7-day token
  "token_type": "bearer"
}
# Old refresh token is automatically revoked

# 4. Logout all devices
POST /api/auth/logout-all
Authorization: Bearer <access_token>
# Revokes ALL refresh tokens for user
```

### Webhook Security (HMAC-SHA256)

**GitHub-style pattern with replay protection:**

```python
import hmac
import hashlib
import time

def compute_signature(secret: str, timestamp: str, body: str) -> str:
    message = f"{timestamp}.{body}"
    signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"sha256={signature}"

# Send webhook alert
timestamp = str(int(time.time()))
body = json.dumps(alert_data)

headers = {
    "X-Signature": compute_signature(secret, timestamp, body),
    "X-Timestamp": timestamp,
    "X-Delivery-ID": "unique-id-123"  # Idempotency
}

response = requests.post(
    "https://api.alertwhisperer.com/api/webhooks/alerts?api_key=xxx",
    headers=headers,
    data=body
)
```

**Security Features:**
- HMAC-SHA256 cryptographic signing
- 5-minute timestamp window (replay protection)
- Constant-time comparison (anti-timing-attack)
- Idempotency (X-Delivery-ID, 24-hour lookback)

**Response Codes:**
- `200` - Success
- `401` - Invalid signature or expired timestamp
- `429` - Rate limit exceeded (with `Retry-After` header)
- `{duplicate: true}` - Idempotent request (already processed)

---

## 🧠 Memory System

### Short-Term Memory (TTL 48 hours)

**Use case:** Conversational context for active incidents

```javascript
{
  "incident_id": "inc-123",
  "company_id": "comp-acme",
  "messages": [
    {"role": "user", "content": "Disk space critical"},
    {"role": "agent", "content": "Running cleanup runbook"},
    {"role": "system", "content": "Runbook completed successfully"}
  ],
  "expires_at": "2025-01-30T00:00:00Z"
}
```

**MongoDB TTL Index (auto-cleanup):**
```javascript
db.short_memory.createIndex(
  {"expires_at": 1},
  {expireAfterSeconds: 0}
)
```

### Long-Term Memory (Indexed, Searchable)

**Use case:** Post-mortems, runbook effectiveness, pattern matching

```javascript
{
  "memory_id": "mem-abc123",
  "company_id": "comp-acme",
  "signature": "disk-space-critical",
  "tags": ["disk", "critical", "auto-remediated"],
  "resolution": "Executed disk cleanup runbook. Freed 50GB.",
  "outcome": "success",
  "runbook_used": "disk-cleanup-v1",
  "incident_id": "inc-123",
  "created_at": "2025-01-25T10:00:00Z"
}
```

**Performance Indexes:**
```javascript
db.long_memory.createIndex(
  {"company_id": 1, "signature": 1, "created_at": -1}
)
db.long_memory.createIndex({"tags": 1})
```

---

## 🛠️ Tool Interfaces

All tools follow **JSON-schema I/O** pattern for agent core compatibility.

### 1. SSM Execute

```json
{
  "tool_name": "ssm.execute",
  "input": {
    "commands": ["df -h", "du -sh /var/log"],
    "instance_ids": ["i-1234567890abcdef0"],
    "runbook_id": "disk-cleanup-v1",
    "timeout_seconds": 300
  },
  "output": {
    "command_id": "cmd-abc123",
    "status": "InProgress",
    "instance_ids": ["i-1234567890abcdef0"]
  }
}
```

### 2. CloudWatch Get Alarm

```json
{
  "tool_name": "cloudwatch.get_alarm",
  "input": {
    "alarm_name": "DiskSpaceCritical-server-01"
  },
  "output": {
    "alarm_name": "DiskSpaceCritical-server-01",
    "state": "ALARM",
    "reason": "Threshold Crossed",
    "timestamp": "2025-01-25T10:30:00Z"
  }
}
```

### 3. Approval Request

```json
{
  "tool_name": "approvals.request",
  "input": {
    "runbook_id": "reboot-production-server",
    "risk_level": "high",
    "reason": "Server unresponsive",
    "requester_id": "user-123"
  },
  "output": {
    "approval_id": "apr-xyz789",
    "status": "pending",
    "expires_at": "2025-01-25T11:30:00Z"
  }
}
```

### 4. KPI Snapshot

```json
{
  "tool_name": "kpi.snapshot",
  "output": {
    "timestamp": "2025-01-25T10:00:00Z",
    "noise_reduction_pct": 65.0,
    "mttr_minutes": 12.5,
    "self_healed_pct": 25.0,
    "patch_compliance_pct": 95.0
  }
}
```

**Impact Tracking (Before/After):**
```python
# Before remediation
kpi_before = await tools.get_kpi_snapshot()

# Execute runbook
await tools.execute_ssm(...)

# After remediation
kpi_after = await tools.get_kpi_snapshot()

# Calculate impact
mttr_improvement = ((kpi_before.mttr - kpi_after.mttr) / kpi_before.mttr) * 100
print(f"MTTR improved by {mttr_improvement}%")
```

---

## 🚀 Deployment

### Production Dockerfile

```dockerfile
FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py /app/
COPY .env /app/

ENV PORT=8001
ENV GIT_SHA="production"
ENV AGENT_MODE="local"

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:8001/api/agent/ping || exit 1

EXPOSE 8001
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]
```

### Deploy to AWS ECR

```bash
#!/bin/bash
REGION="us-east-1"
ACCOUNT_ID="123456789012"
REPO_NAME="alert-whisperer-agent"
GIT_SHA=$(git rev-parse --short HEAD)

# Login to ECR
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin \
  $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# Build and push
docker build -f Dockerfile.production -t $REPO_NAME:$GIT_SHA .
docker tag $REPO_NAME:$GIT_SHA \
  $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:$GIT_SHA
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:$GIT_SHA
```

---

## 📚 API Reference

### Base URL
```
https://your-domain.com/api
```

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Login (returns access + refresh tokens) |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout-all` | Revoke all refresh tokens |

### Agent Core

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/agent/ping` | Health check |
| GET | `/agent/version` | Get agent version |
| POST | `/agent/decide` | Make decision (streaming or JSON) |
| GET | `/agent/decisions/{incident_id}` | Get decision history |

### Incidents

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/incidents` | List incidents |
| POST | `/incidents/correlate` | Trigger correlation |
| POST | `/incidents/{id}/execute-runbook-ssm` | Execute runbook |

---

## 🔄 How to Reproduce

### Local Setup

```bash
# 1. Clone and install
git clone https://github.com/your-org/alert-whisperer.git
cd alert-whisperer/backend
pip install -r requirements.txt

# 2. Setup environment
cp .env.example .env
# Edit .env: MONGO_URL, SECRET_KEY, GEMINI_API_KEY

# 3. Initialize database indexes
python db_init.py

# 4. Start backend
uvicorn server:app --host 0.0.0.0 --port 8001 --reload

# 5. Test agent health
curl http://localhost:8001/api/agent/ping

# 6. Make a decision
curl -X POST http://localhost:8001/api/agent/decide \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "test-123",
    "company_id": "comp-acme",
    "incident_data": {
      "severity": "high",
      "signature": "disk-space-critical",
      "alert_count": 3
    }
  }'
```

---

## ✅ Production Checklist

### Security
- [x] OWASP JWT (30m access, 7d refresh)
- [x] HMAC-SHA256 webhook signing
- [x] Replay protection (5-min window)
- [x] Constant-time comparison
- [x] Per-company API keys
- [x] RBAC (3 roles)
- [x] Audit logs

### Agent Core
- [x] Health endpoint
- [x] Version tracking (GIT_SHA)
- [x] Graceful shutdown (SIGTERM)
- [x] Streaming decisions (SSE)
- [x] Memory (short TTL + long indexed)
- [x] Tool interfaces (JSON-schema)
- [x] Remote invocation (Bedrock ready)
- [x] Cost guardrails

### Data
- [x] MongoDB TTL indexes
- [x] Performance indexes
- [x] Idempotency (24h)
- [x] Rate limiting (Retry-After header)
- [x] Multi-tenant isolation

---

## 🎯 Key Differentiators

1. **Production-Grade**: OWASP auth, GitHub-style webhooks, RFC rate limiting
2. **AWS Agent Core**: Health probes, streaming, memory, tool interfaces
3. **Hybrid AI + Rules**: Deterministic fallback + optional AI (Gemini 2.5 Pro)
4. **Enterprise MSP**: Cross-account IAM, SSM, Patch Manager, approval workflows

**Built for SuperOps/Superhack 2025** 🚀
