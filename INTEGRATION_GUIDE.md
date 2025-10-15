# Alert Whisperer - Integration Guide

## Overview
Alert Whisperer is an advanced MSP operations intelligence platform that reduces alert noise, automates incident remediation, and manages safe patching workflows.

## 🚀 Key Features

### 1. **Alert Correlation Engine**
- Reduces noise by grouping duplicate alerts (50 alerts → 5-15 incidents)
- Correlates by signature + asset within configurable time windows
- Real-time processing with visual feedback

### 2. **AI-Powered Decision Engine**
- Gemini 2.5-pro integration for intelligent decision explanations
- Outputs strict JSON format with action recommendations
- Hybrid auto-processing: low-risk auto-approved, high-risk requires approval
- Priority scoring based on severity and correlation

### 3. **Patch Management**
- Safe canary deployment workflow
- Maintenance window scheduling
- Rollback capabilities

### 4. **Company Management**
- Multi-tenant MSP dashboard
- Role-based access control
- Dynamic company creation with assets and policies

### 5. **Real-Time Activity Feed**
- Live operations monitoring
- Auto-refresh every 5 seconds
- Activity logging for all operations

---

## 🔌 API Integration Guide

### Base URL
```
Production: https://msp-remedy.preview.emergentagent.com/api
Development: http://localhost:8001/api
```

### Authentication
All API requests require a Bearer token obtained from login:

```bash
curl -X POST https://msp-remedy.preview.emergentagent.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@alertwhisperer.com",
    "password": "admin123"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "user": { "id": "...", "name": "Admin User", "role": "admin" }
}
```

Use the token in subsequent requests:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://msp-remedy.preview.emergentagent.com/api/companies
```

---

## 📡 Webhook Integration for External Monitoring Tools

### Send Alerts via Webhook

Alert Whisperer accepts alerts from external monitoring tools (Prometheus, Datadog, Zabbix, etc.) via webhook.

**Endpoint:** `POST /api/webhooks/alerts`

**Request Body:**
```json
{
  "company_id": "comp-acme",
  "asset_name": "srv-app-01",
  "signature": "high_cpu_usage",
  "severity": "critical",
  "message": "CPU usage exceeded 90% on srv-app-01",
  "tool_source": "Prometheus"
}
```

**Response:**
```json
{
  "message": "Alert received",
  "alert_id": "c5c2afed-8003-4db3-9c20-8f8c34a0d5c4"
}
```

**Severity Levels:**
- `low` - Informational
- `medium` - Warning
- `high` - Urgent
- `critical` - Emergency

**Example Integrations:**

#### Prometheus Alertmanager
```yaml
receivers:
  - name: 'alert-whisperer'
    webhook_configs:
      - url: 'https://msp-remedy.preview.emergentagent.com/api/webhooks/alerts'
        send_resolved: true
        http_config:
          headers:
            Content-Type: application/json
```

#### Datadog Webhook
```json
{
  "webhook_url": "https://msp-remedy.preview.emergentagent.com/api/webhooks/alerts",
  "payload": {
    "company_id": "comp-acme",
    "asset_name": "$HOSTNAME",
    "signature": "$ALERT_TYPE",
    "severity": "$PRIORITY",
    "message": "$EVENT_TITLE: $EVENT_MSG",
    "tool_source": "Datadog"
  }
}
```

#### Curl Example
```bash
curl -X POST https://msp-remedy.preview.emergentagent.com/api/webhooks/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "company_id": "comp-acme",
    "asset_name": "srv-db-01",
    "signature": "disk_full",
    "severity": "critical",
    "message": "Disk usage at 95% on srv-db-01",
    "tool_source": "Custom Monitor"
  }'
```

---

## 🏢 Company Management API

### Create Company
```bash
POST /api/companies
```

**Request:**
```json
{
  "name": "New Client Corp",
  "policy": {
    "auto_approve_low_risk": true,
    "maintenance_window": "Sat 22:00-02:00"
  },
  "assets": [
    {
      "id": "srv-web-01",
      "name": "srv-web-01",
      "type": "webserver",
      "os": "Ubuntu 22.04"
    },
    {
      "id": "srv-db-01",
      "name": "srv-db-01",
      "type": "database",
      "os": "Ubuntu 22.04"
    }
  ]
}
```

### Update Company
```bash
PUT /api/companies/{company_id}
```

### Delete Company
```bash
DELETE /api/companies/{company_id}
```
⚠️ **Warning:** This deletes all associated alerts, incidents, runbooks, and patches.

---

## 📊 Real-Time Stats API

Get live statistics for dashboard updates:

```bash
GET /api/realtime/stats/{company_id}
```

**Response:**
```json
{
  "active_alerts": 25,
  "total_incidents": 8,
  "active_incidents": 3,
  "resolved_incidents": 5,
  "recent_activities": [
    {
      "id": "...",
      "type": "incident_created",
      "message": "Incident created: service_down:nginx on srv-app-01",
      "timestamp": "2025-10-14T19:08:21.322484+00:00",
      "severity": "high"
    }
  ],
  "kpis": {
    "noise_reduction_pct": 36.0,
    "self_healed_count": 2,
    "self_healed_pct": 25.0
  }
}
```

---

## 🔧 Runbook Management API

### Create Runbook
```bash
POST /api/runbooks
```

**Request:**
```json
{
  "name": "Restart Apache",
  "description": "Restart Apache web server and verify health",
  "risk_level": "low",
  "signature": "service_down:apache",
  "actions": [
    "sudo systemctl restart apache2",
    "curl -f http://localhost/healthz"
  ],
  "health_checks": {
    "type": "http",
    "url": "http://localhost/healthz",
    "status": 200
  },
  "auto_approve": true,
  "company_id": "comp-acme"
}
```

### List Runbooks
```bash
GET /api/runbooks?company_id=comp-acme
```

### Update Runbook
```bash
PUT /api/runbooks/{runbook_id}
```

### Delete Runbook
```bash
DELETE /api/runbooks/{runbook_id}
```

---

## 🎯 Incident Management Workflow

### 1. Generate Alerts (Testing)
```bash
POST /api/alerts/generate?company_id=comp-acme&count=50
```

### 2. Correlate Alerts into Incidents
```bash
POST /api/incidents/correlate?company_id=comp-acme
```

**Response:**
```json
{
  "total_alerts": 50,
  "incidents_created": 8,
  "noise_reduction_pct": 36.0,
  "incidents": [...]
}
```

### 3. Generate AI Decision
```bash
POST /api/incidents/{incident_id}/decide
```

**Response:**
```json
{
  "action": "EXECUTE",
  "reason": "Correlated 2 alerts; low-risk runbook auto-approved",
  "incident_id": "...",
  "priority_score": 14,
  "runbook_id": "...",
  "approval_required": false,
  "health_check": {...},
  "escalation": {...},
  "ai_explanation": "This agent correlated two 'service_down' alerts..."
}
```

### 4. Execute/Approve Incident
```bash
POST /api/incidents/{incident_id}/approve
```

### 5. Escalate Incident
```bash
POST /api/incidents/{incident_id}/escalate
```

---

## 📈 Activity Feed API

Get real-time activity stream:

```bash
GET /api/activities?company_id=comp-acme&limit=20
```

**Response:**
```json
[
  {
    "id": "...",
    "company_id": "comp-acme",
    "type": "alert_received",
    "message": "New critical alert: CPU usage exceeded 90%",
    "timestamp": "2025-10-14T19:25:13.867536+00:00",
    "severity": "critical"
  }
]
```

**Activity Types:**
- `alert_received` - New alert from webhook
- `incident_created` - Incident created from correlation
- `incident_resolved` - Incident marked as resolved
- `runbook_executed` - Runbook execution completed
- `patch_deployed` - Patch deployment status update

---

## 🔐 Security Best Practices

1. **API Keys:** Store JWT tokens securely, never in code
2. **HTTPS Only:** All production traffic should use HTTPS
3. **Rate Limiting:** Webhooks are rate-limited to prevent abuse
4. **Audit Logs:** All operations are logged for compliance
5. **RBAC:** Use role-based access (admin vs technician)

---

## 📱 Frontend Integration

The React frontend is available at:
```
https://msp-remedy.preview.emergentagent.com
```

**Demo Credentials:**
- **Admin:** admin@alertwhisperer.com / admin123
- **Technician:** tech@acme.com / tech123

---

## 🧪 Testing & Development

### Local Development Setup
```bash
# Backend
cd /app/backend
pip install -r requirements.txt
uvicorn server:app --reload --host 0.0.0.0 --port 8001

# Frontend
cd /app/frontend
yarn install
yarn start
```

### Seed Sample Data
```bash
curl -X POST http://localhost:8001/api/seed
```

This creates:
- 3 demo companies
- 3 users (admin, 2 technicians)
- 5 runbooks
- 2 patch plans

---

## 🎨 Customization

### Custom Alert Signatures
Define custom alert signatures in your company policy:
```json
{
  "custom_signatures": [
    "database_replication_lag",
    "ssl_certificate_expiring",
    "backup_job_failed"
  ]
}
```

### Custom Decision Criteria
Modify decision engine priority scoring in `/app/backend/server.py`:
```python
severity_scores = {"low": 10, "medium": 30, "high": 60, "critical": 90}
duplicate_bonus = min(incident.alert_count * 2, 20)
priority_score = base_score + duplicate_bonus
```

---

## 📞 Support & Troubleshooting

### Common Issues

**Webhook not receiving alerts:**
- Verify company_id and asset_name match exactly
- Check CORS settings if calling from browser
- Ensure Content-Type: application/json header

**Decision engine not generating:**
- Verify Gemini API key is set in backend/.env
- Check incident has matching runbook signature
- Review backend logs for errors

**Activity feed not updating:**
- Auto-refresh runs every 5 seconds
- Check browser console for errors
- Verify company_id is selected

### Logs
```bash
# Backend logs
tail -f /var/log/supervisor/backend.out.log
tail -f /var/log/supervisor/backend.err.log

# Frontend logs (browser console)
```

---

## 🚀 Production Deployment Checklist

- [ ] Set strong JWT secret in production
- [ ] Configure proper CORS origins
- [ ] Set up SSL certificates
- [ ] Configure rate limiting for webhooks
- [ ] Set up monitoring for the platform itself
- [ ] Configure backup for MongoDB
- [ ] Set up proper logging and alerting
- [ ] Review and adjust auto-approval policies
- [ ] Train team on runbook creation
- [ ] Set up incident escalation contacts

---

## 📝 License & Credits

Built with:
- **FastAPI** - High-performance Python backend
- **React 19** - Modern frontend framework
- **MongoDB** - Flexible NoSQL database
- **Gemini 2.5-pro** - AI-powered decision explanations
- **Shadcn/UI** - Beautiful component library
- **Tailwind CSS** - Utility-first styling

---

## 🔄 Version History

**v2.0.0** (Current)
- ✅ Company management system
- ✅ Real-time activity feed
- ✅ Webhook integration for external tools
- ✅ Runbook CRUD operations
- ✅ Enhanced UI with live updates

**v1.0.0**
- ✅ Alert correlation engine
- ✅ AI-powered decision engine
- ✅ Patch management
- ✅ Multi-tenant dashboard
- ✅ Role-based access control
