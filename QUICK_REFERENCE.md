# Alert Whisperer - Quick Reference Guide

## 🚀 Common Tasks

### Login
```
URL: https://your-domain.com
Email: admin@alertwhisperer.com
Password: admin123
```

### Send Alert via Webhook
```bash
curl -X POST "https://your-domain.com/api/webhooks/alerts?api_key=YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_name": "srv-app-01",
    "signature": "cpu_high",
    "severity": "critical",
    "message": "CPU usage above 90%",
    "tool_source": "Datadog"
  }'
```

### Send Alert with HMAC Security
```python
import requests
import hmac
import hashlib
import json
import time

# Configuration
webhook_url = "https://your-domain.com/api/webhooks/alerts?api_key=YOUR_KEY"
hmac_secret = "your_hmac_secret"

# Payload
payload = {
    "asset_name": "srv-app-01",
    "signature": "disk_full",
    "severity": "high",
    "message": "Disk usage 95%",
    "tool_source": "Monitoring"
}

# Create signature
timestamp = str(int(time.time()))
body = json.dumps(payload)
message = f"{timestamp}.{body}"
signature = hmac.new(
    hmac_secret.encode(),
    message.encode(),
    hashlib.sha256
).hexdigest()

# Send request
headers = {
    "Content-Type": "application/json",
    "X-Signature": f"sha256={signature}",
    "X-Timestamp": timestamp,
    "X-Delivery-ID": "unique-id-123"  # Optional, for idempotency
}

response = requests.post(webhook_url, json=payload, headers=headers)
print(response.json())
```

---

## 📊 API Endpoints Reference

### Authentication
```
POST   /api/auth/login          # Login
GET    /api/profile             # Get profile
PUT    /api/profile             # Update profile
PUT    /api/profile/password    # Change password
```

### Companies
```
GET    /api/companies                                    # List all
GET    /api/companies/{id}                               # Get one
POST   /api/companies                                    # Create
PUT    /api/companies/{id}                               # Update
DELETE /api/companies/{id}                               # Delete
POST   /api/companies/{id}/regenerate-api-key            # New API key
```

### Alerts
```
GET    /api/alerts                                       # List alerts
POST   /api/webhooks/alerts?api_key=KEY                  # Create alert (webhook)
```

### Incidents
```
GET    /api/incidents                                    # List incidents
GET    /api/incidents/{id}                               # Get one
PUT    /api/incidents/{id}                               # Update
POST   /api/incidents/correlate?company_id=ID            # Trigger correlation
POST   /api/incidents/{id}/assign                        # Assign to technician
```

### Runbooks
```
GET    /api/runbooks                                     # List runbooks
POST   /api/runbooks/{id}/execute                        # Execute runbook
GET    /api/runbooks/executions/{id}                     # Get execution status
```

### Real-Time Metrics
```
GET    /api/metrics/realtime?company_id=ID               # Live dashboard metrics
```

### Chat
```
GET    /api/chat/{company_id}                            # Get messages
POST   /api/chat/{company_id}                            # Send message
PUT    /api/chat/{company_id}/mark-read                  # Mark as read
```

### Notifications
```
GET    /api/notifications                                # List notifications
GET    /api/notifications/unread-count                   # Count unread
PUT    /api/notifications/{id}/read                      # Mark as read
PUT    /api/notifications/mark-all-read                  # Mark all read
```

### Webhook Security (HMAC)
```
GET    /api/companies/{id}/webhook-security              # Get config
POST   /api/companies/{id}/webhook-security/enable       # Enable HMAC
POST   /api/companies/{id}/webhook-security/disable      # Disable HMAC
POST   /api/companies/{id}/webhook-security/regenerate-secret  # New secret
```

### Correlation Configuration
```
GET    /api/companies/{id}/correlation-config            # Get config
PUT    /api/companies/{id}/correlation-config            # Update config
GET    /api/correlation/dedup-keys                       # Get dedup patterns
```

### Rate Limiting
```
GET    /api/companies/{id}/rate-limit                    # Get config
PUT    /api/companies/{id}/rate-limit                    # Update config
```

### Approval Gates
```
GET    /api/approval-requests                            # List pending
POST   /api/approval-requests/{id}/approve               # Approve
POST   /api/approval-requests/{id}/reject                # Reject
```

### Audit Logs
```
GET    /api/audit-logs                                   # List all
GET    /api/audit-logs/summary                           # Get summary
```

### Patch Compliance
```
GET    /api/companies/{id}/patch-compliance              # Get compliance data
GET    /api/patch-compliance/summary?company_id=ID       # Get summary
```

### Patches
```
GET    /api/patches?company_id=ID                        # List patch plans
POST   /api/patches/{id}/canary                          # Start canary
POST   /api/patches/{id}/rollout                         # Rollout patch
POST   /api/patches/{id}/complete                        # Mark complete
```

### Users
```
GET    /api/users                                        # List all (admin)
POST   /api/users                                        # Create user (admin)
PUT    /api/users/{id}                                   # Update user (admin)
DELETE /api/users/{id}                                   # Delete user (admin)
```

### WebSocket
```
WS     /ws                                               # Real-time updates
```

---

## 🎨 Severity Levels

| Severity | Score | Use Case | Example |
|----------|-------|----------|---------|
| **critical** | 90 | System down, data loss | Database offline, disk full |
| **high** | 60 | Degraded service | High CPU, memory leak |
| **medium** | 30 | Warning signs | Elevated latency, minor errors |
| **low** | 10 | Informational | Config change, backup complete |

---

## 🔑 Aggregation Key Patterns

### Pattern 1: `asset|signature` (Default)
**Use:** Most common scenarios
```
Alert 1: srv-app-01 | cpu_high
Alert 2: srv-app-01 | cpu_high
Alert 3: srv-app-02 | cpu_high
```
**Result:** 2 incidents (one per asset)

### Pattern 2: `asset|signature|tool`
**Use:** Multiple monitoring tools
```
Alert 1: srv-app-01 | cpu_high | Datadog
Alert 2: srv-app-01 | cpu_high | Zabbix
```
**Result:** 2 incidents (different tools)

### Pattern 3: `signature`
**Use:** Infrastructure-wide issues
```
Alert 1: srv-app-01 | network_down
Alert 2: srv-app-02 | network_down
Alert 3: srv-db-01 | network_down
```
**Result:** 1 incident (same root cause)

### Pattern 4: `asset`
**Use:** Asset-specific investigation
```
Alert 1: srv-app-01 | cpu_high
Alert 2: srv-app-01 | memory_high
Alert 3: srv-app-01 | disk_high
```
**Result:** 1 incident (asset in distress)

---

## 📈 Priority Score Calculation

```python
def calculate_priority_score(incident):
    # Base severity score
    severity_scores = {
        "critical": 90,
        "high": 60,
        "medium": 30,
        "low": 10
    }
    score = severity_scores[incident.severity]
    
    # Critical asset bonus
    if incident.asset_is_critical:
        score += 20
    
    # Duplicate factor (max 20)
    duplicates = len(incident.alerts) - 1
    score += min(duplicates * 2, 20)
    
    # Multi-tool bonus
    if len(incident.tool_sources) >= 2:
        score += 10
    
    # Age decay (max -10)
    age_hours = (now - incident.created_at).hours
    score -= min(age_hours, 10)
    
    return score
```

**Examples:**
```
Incident A:
- Severity: critical (90)
- Critical asset: yes (+20)
- Duplicates: 5 (+10)
- Tools: [Datadog, Zabbix] (+10)
- Age: 2h (-2)
= Score: 128

Incident B:
- Severity: medium (30)
- Critical asset: no (+0)
- Duplicates: 1 (+2)
- Tools: [Datadog] (+0)
- Age: 1h (-1)
= Score: 31
```

---

## 🔐 RBAC Permission Matrix

| Action | MSP Admin | Company Admin | Technician |
|--------|-----------|---------------|------------|
| View all companies | ✅ | ❌ | ❌ |
| View own company | ✅ | ✅ | ✅ |
| Create company | ✅ | ❌ | ❌ |
| Delete company | ✅ | ❌ | ❌ |
| Manage users | ✅ | ✅ (own company) | ❌ |
| View incidents | ✅ | ✅ (own company) | ✅ (assigned) |
| Assign incidents | ✅ | ✅ (own company) | ❌ |
| Execute runbooks | ✅ | ✅ | ✅ (approved only) |
| Approve high-risk | ✅ | ❌ | ❌ |
| Approve medium-risk | ✅ | ✅ | ❌ |
| Configure settings | ✅ | ✅ (own company) | ❌ |
| View audit logs | ✅ | ✅ (own company) | ❌ |
| Regenerate API key | ✅ | ✅ (own company) | ❌ |

---

## 🚦 HTTP Status Codes

| Code | Meaning | Example |
|------|---------|---------|
| **200** | Success | Alert received successfully |
| **201** | Created | Company created |
| **400** | Bad Request | Invalid payload format |
| **401** | Unauthorized | Invalid API key or credentials |
| **403** | Forbidden | Insufficient permissions |
| **404** | Not Found | Company/asset not found |
| **409** | Conflict | Duplicate resource |
| **429** | Too Many Requests | Rate limit exceeded |
| **500** | Internal Error | Server error |

---

## ⏱️ Time Windows

### Correlation Window
```
5 minutes  → Tight grouping (frequent deploys)
10 minutes → Balanced (default for most)
15 minutes → Loose grouping (legacy systems)
```

### Replay Protection
```
5 minutes → HMAC timestamp must be within 5 min
24 hours  → Idempotency duplicate detection window
1 hour    → Approval request expiration
```

---

## 📱 WebSocket Event Types

### Events Received
```javascript
{
  "type": "alert_received",
  "data": { alert object }
}

{
  "type": "incident_created",
  "data": { incident object }
}

{
  "type": "incident_updated",
  "data": { incident object }
}

{
  "type": "notification",
  "data": { notification object }
}

{
  "type": "chat_message",
  "data": { message object }
}
```

### Connect to WebSocket
```javascript
const ws = new WebSocket('wss://your-domain.com/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Event:', data.type);
  console.log('Data:', data.data);
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};

ws.onclose = () => {
  console.log('WebSocket closed, reconnecting...');
  // Implement reconnection logic
};
```

---

## 🎯 KPI Targets

| Metric | Target | Good | Needs Improvement |
|--------|--------|------|-------------------|
| **Noise Reduction %** | 40-70% | 20-40% | <20% |
| **Self-Healed %** | 20-30% | 10-20% | <10% |
| **MTTR Reduction** | 30-50% | 15-30% | <15% |
| **Patch Compliance** | 95%+ | 90-95% | <90% |

---

## 🔧 Troubleshooting

### Issue: Login 401 Error
**Solution:** Database not seeded
```bash
curl -X POST http://localhost:8001/api/seed
```

### Issue: Webhook 401 Error
**Causes:**
1. Invalid API key
2. HMAC signature mismatch (if enabled)
3. Timestamp expired (>5 min old)

**Check:**
```bash
# Test API key
curl "http://localhost:8001/api/companies/comp-acme?api_key=YOUR_KEY"

# Test webhook without HMAC
curl -X POST "http://localhost:8001/api/webhooks/alerts?api_key=YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"asset_name":"srv-app-01","signature":"test","severity":"low","message":"Test","tool_source":"Test"}'
```

### Issue: Webhook 429 Error
**Solution:** Rate limit exceeded
```bash
# Check rate limit config
curl "http://localhost:8001/api/companies/comp-acme/rate-limit"

# Increase limits (admin only)
curl -X PUT "http://localhost:8001/api/companies/comp-acme/rate-limit" \
  -H "Content-Type: application/json" \
  -d '{"requests_per_minute":120,"burst_size":200}'
```

### Issue: WebSocket Not Connecting
**Causes:**
1. Kubernetes ingress missing upgrade headers
2. Firewall blocking WebSocket
3. SSL/TLS certificate issues

**Workaround:** System works without WebSocket, uses polling instead

### Issue: No Correlation Happening
**Check:**
```bash
# Verify correlation config
curl "http://localhost:8001/api/companies/comp-acme/correlation-config"

# Trigger manual correlation
curl -X POST "http://localhost:8001/api/incidents/correlate?company_id=comp-acme"
```

### Issue: Runbook Not Executing
**Causes:**
1. Risk level requires approval
2. AWS SSM not configured
3. No matching signature

**Check:**
```bash
# List runbooks
curl "http://localhost:8001/api/runbooks?company_id=comp-acme"

# Check approval requests
curl "http://localhost:8001/api/approval-requests?company_id=comp-acme"
```

---

## 📋 Environment Variables

### Backend (.env)
```bash
# Database
MONGO_URL=mongodb://localhost:27017/alert_whisperer

# JWT
JWT_SECRET=your-secret-key-min-32-chars
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=720

# AWS (Optional)
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
AWS_DEFAULT_REGION=us-east-1
```

### Frontend (.env)
```bash
# Backend API URL
REACT_APP_BACKEND_URL=http://localhost:8001
```

---

## 🔄 Common Curl Commands

### Login and Get Token
```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@alertwhisperer.com","password":"admin123"}' \
  | jq -r '.access_token')

# Use token
curl http://localhost:8001/api/profile \
  -H "Authorization: Bearer $TOKEN"
```

### Create Company
```bash
curl -X POST http://localhost:8001/api/companies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "New Corp",
    "policy": {"auto_approve_low_risk": true},
    "assets": [
      {"id": "srv-01", "name": "srv-01", "type": "webserver", "os": "Ubuntu"}
    ]
  }'
```

### Send Test Alert
```bash
API_KEY="your-company-api-key"

curl -X POST "http://localhost:8001/api/webhooks/alerts?api_key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_name": "srv-app-01",
    "signature": "test_alert",
    "severity": "low",
    "message": "This is a test alert",
    "tool_source": "Manual"
  }'
```

### Trigger Correlation
```bash
curl -X POST "http://localhost:8001/api/incidents/correlate?company_id=comp-acme" \
  -H "Authorization: Bearer $TOKEN"
```

### Get Real-Time Metrics
```bash
curl "http://localhost:8001/api/metrics/realtime?company_id=comp-acme" | jq
```

### Enable HMAC Security
```bash
curl -X POST "http://localhost:8001/api/companies/comp-acme/webhook-security/enable" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🎓 Training Scenarios

### Scenario 1: Handle Alert Storm
1. Simulate 100 alerts: `for i in {1..100}; do curl ...; done`
2. Watch correlation reduce to ~30 incidents
3. Check noise reduction % on dashboard
4. Review correlated incidents
5. Verify priority scores

### Scenario 2: Test Self-Healing
1. Create runbook for disk_full
2. Send disk_full alert
3. Watch runbook execute automatically
4. Check execution status
5. Verify incident marked as "Self-Healed"

### Scenario 3: Approval Workflow
1. Create high-risk runbook
2. Send matching alert
3. Approval request generated
4. Admin reviews and approves
5. Runbook executes
6. Check audit log

---

## 📞 Quick Help

**Dashboard Not Loading?**
- Check backend is running: `curl http://localhost:8001/api/health`
- Check frontend is running: `curl http://localhost:3000`
- Clear browser cache

**Alerts Not Appearing?**
- Verify API key is correct
- Check webhook payload format
- Look for 4xx errors in response
- Review backend logs

**Can't Login?**
- Seed database: `curl -X POST http://localhost:8001/api/seed`
- Check credentials: admin@alertwhisperer.com / admin123
- Verify backend is running

**Need More Help?**
- Check COMPLETE_SYSTEM_GUIDE.md for detailed explanations
- Review AWS_INTEGRATION_GUIDE.md for AWS setup
- See test_result.md for testing history

---

**Last Updated:** January 25, 2025
**Version:** 1.0 SuperHack Edition
