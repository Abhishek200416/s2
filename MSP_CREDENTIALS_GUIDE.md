# MSP Company Onboarding - Credentials Guide

## How Real MSPs Collect Company Credentials

When onboarding a new company/client, MSPs need to collect credentials to monitor and manage their infrastructure. This document explains what credentials are needed and why.

---

## 🔐 Credentials Collection Flow

### **Step 1: Basic Company Information**
- Company name
- Maintenance window (when can we perform updates?)
- Contact information

### **Step 2: Company Credentials (NEW TAB)**

This is where you collect the company's infrastructure access credentials.

#### **A. AWS/Cloud Credentials (For PULL Mode)**

**What to collect from the company:**

1. **AWS Access Key ID** (e.g., `AKIA...`)
   - How company provides: AWS Console → IAM → Users → Security credentials
   - Purpose: Programmatic access to their AWS account

2. **AWS Secret Access Key**
   - One-time secret shown during key creation
   - Purpose: Authentication with AWS services

3. **AWS Region** (e.g., `us-east-1`, `us-west-2`)
   - Where their resources are deployed
   - Purpose: Know which region to query for alarms

4. **AWS Account ID** (12-digit number)
   - Found in: AWS Console → Account dropdown
   - Purpose: Identify their specific AWS account

**What you can do with these credentials:**
- ✅ Pull CloudWatch alarms automatically (PULL mode)
- ✅ Monitor EC2 instances for patches
- ✅ Execute SSM runbooks for auto-remediation
- ✅ Track resource compliance

**Security Best Practices:**
- Request **least-privilege IAM policy** (ReadOnly + specific actions)
- Prefer **cross-account IAM roles** over access keys
- Store in **AWS Secrets Manager**
- Rotate every 90 days

---

#### **B. Alternative: Webhook Mode (For PUSH Mode)**

If the company **doesn't want to share credentials**, they can send alerts to you via webhook:

**What you provide to the company:**
1. **Webhook URL**: `https://your-msp.com/api/webhooks/alerts`
2. **API Key**: Auto-generated when you create the company
3. **HMAC Secret**: (if security enabled) For signing requests

**What the company configures:**
- They configure their monitoring tools (Datadog, Zabbix, CloudWatch, etc.) to send alerts to your webhook
- They include the API key in requests
- No credential sharing needed!

---

#### **C. Monitoring Tools API Keys (Optional)**

If the company uses specific monitoring tools:

1. **Datadog**
   - API Key + App Key
   - Purpose: Pull metrics and alerts from Datadog

2. **Zabbix**
   - Server URL + Username + Password
   - Purpose: Query Zabbix for alerts

3. **Prometheus**
   - Endpoint URL (+ auth if needed)
   - Purpose: Scrape metrics

---

### **Step 3: Security Settings**
- Enable HMAC webhook authentication
- Configure rate limiting
- Set burst size for alert storms

### **Step 4: AI Correlation Settings**
- Configure correlation time window (5-15 min)
- Enable/disable auto-correlation
- AI-powered pattern detection (Bedrock + Gemini)

### **Step 5: Review & Create**
- Summary of all settings
- Shows what credentials were collected
- Confirms what you can do with them
- Creates company with all settings applied

---

## 📊 Two Integration Modes

### **PULL Mode (MSP Pulls Data)**
- MSP uses company's AWS credentials
- MSP polls CloudWatch for alarms
- MSP executes SSM commands
- **Requires**: AWS credentials from company

### **PUSH Mode (Company Pushes Alerts)**
- Company sends alerts via webhook
- No credential sharing
- Company configures their tools
- **Requires**: API key (you provide)

---

## 🎯 Summary: What Happens After Onboarding

1. **Company Created**: API key + HMAC secret generated
2. **Credentials Stored**: AWS credentials (if provided) stored securely
3. **Settings Applied**: Security, correlation, rate limiting configured
4. **Ready to Monitor**:
   - PULL mode: Start polling CloudWatch
   - PUSH mode: Provide webhook details to company
5. **AI Active**: Real-time correlation and pattern detection enabled

---

## 🔑 Default Credentials for Testing

**MSP Admin Login:**
- Email: `admin@alertwhisperer.com`
- Password: `admin123`

**Test Company (Pre-seeded):**
- Acme Corp: `comp-acme`
- TechStart: `comp-techstart`
- Global IT: `comp-global`

---

## 📝 Notes

- All credentials encrypted at rest
- AWS credentials can be rotated anytime
- Webhook API keys can be regenerated
- HMAC secrets can be regenerated
- Company settings can be modified after creation
