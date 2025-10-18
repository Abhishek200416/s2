# 🔐 AWS SSO Integration Guide for Alert Whisperer

## Overview

You're using **AWS SSO (Single Sign-On)** which provides temporary credentials. For Alert Whisperer to monitor your infrastructure 24/7, we need **long-lived credentials** or an **IAM role** that the backend service can assume.

**Your AWS Account Details:**
- **Region:** us-east-2
- **Account ID:** 728925775278

---

## ✅ Recommended Approach: Create IAM User for Alert Whisperer

### Step 1: Create IAM User with Programmatic Access

```bash
# Using AWS CLI (from your SSO session)
aws iam create-user \
  --user-name AlertWhispererService \
  --tags Key=Purpose,Value=MSP-Monitoring
```

### Step 2: Attach Required Policies

Create a custom policy for Alert Whisperer:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SSMReadAndExecute",
      "Effect": "Allow",
      "Action": [
        "ssm:DescribeInstanceInformation",
        "ssm:ListCommands",
        "ssm:ListCommandInvocations",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:DescribeInstanceProperties"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2ReadInstances",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchReadMetrics",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics"
      ],
      "Resource": "*"
    }
  ]
}
```

Save this as `alert-whisperer-policy.json` and create the policy:

```bash
aws iam create-policy \
  --policy-name AlertWhispererServicePolicy \
  --policy-document file://alert-whisperer-policy.json \
  --region us-east-2
```

Attach the policy to the user:

```bash
aws iam attach-user-policy \
  --user-name AlertWhispererService \
  --policy-arn arn:aws:iam::728925775278:policy/AlertWhispererServicePolicy
```

### Step 3: Create Access Keys

```bash
aws iam create-access-key \
  --user-name AlertWhispererService \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' \
  --output text
```

**⚠️ IMPORTANT:** Save these credentials securely! You'll need them to configure Alert Whisperer.

Example output:
```
AKIAIOSFODNN7EXAMPLE   wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

---

## 🚀 Alternative Approach: IAM Role with AssumeRole

If you prefer using IAM roles instead of long-lived credentials:

### Step 1: Create IAM Role

```bash
# Create trust policy for EC2 (if Alert Whisperer runs on EC2)
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name AlertWhispererServiceRole \
  --assume-role-policy-document file://trust-policy.json \
  --region us-east-2
```

### Step 2: Attach Policy to Role

```bash
aws iam attach-role-policy \
  --role-name AlertWhispererServiceRole \
  --policy-arn arn:aws:iam::728925775278:policy/AlertWhispererServicePolicy
```

### Step 3: Create Instance Profile (if running on EC2)

```bash
aws iam create-instance-profile \
  --instance-profile-name AlertWhispererProfile

aws iam add-role-to-instance-profile \
  --instance-profile-name AlertWhispererProfile \
  --role-name AlertWhispererServiceRole

# Attach to EC2 instance
aws ec2 associate-iam-instance-profile \
  --instance-id i-1234567890abcdef0 \
  --iam-instance-profile Name=AlertWhispererProfile
```

---

## 📋 Configure Alert Whisperer with Credentials

### Option A: Via UI (Recommended)

1. Login to Alert Whisperer
2. Navigate to **Dashboard** → **Companies**
3. Select your company → **Company Settings**
4. Go to **AWS Credentials** tab
5. Enter:
   - **Access Key ID:** AKIAIOSFODNN7EXAMPLE
   - **Secret Access Key:** wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   - **Region:** us-east-2
6. Click **Save** → **Test Connection**

### Option B: Via API

```bash
curl -X POST "http://localhost:8001/api/companies/{company_id}/aws-credentials" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "region": "us-east-2"
  }'
```

---

## 🖥️ Install SSM Agent on Your Instances

Alert Whisperer uses **AWS Systems Manager (SSM)** to execute commands on your servers without SSH access.

### Ubuntu/Debian Servers

```bash
sudo snap install amazon-ssm-agent --classic
sudo snap start amazon-ssm-agent
sudo snap services amazon-ssm-agent
```

### Amazon Linux 2 / Amazon Linux 2023

```bash
# SSM Agent is pre-installed, just start it
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent
sudo systemctl status amazon-ssm-agent
```

### CentOS/RHEL 7/8

```bash
sudo yum install -y https://s3.us-east-2.amazonaws.com/amazon-ssm-us-east-2/latest/linux_amd64/amazon-ssm-agent.rpm
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent
```

### Windows Server

```powershell
$dir = $env:TEMP + "\ssm"
New-Item -ItemType directory -Path $dir
cd $dir
(New-Object System.Net.WebClient).DownloadFile("https://amazon-ssm-us-east-2.s3.us-east-2.amazonaws.com/latest/windows_amd64/AmazonSSMAgentSetup.exe", $dir + "\AmazonSSMAgentSetup.exe")
Start-Process .\AmazonSSMAgentSetup.exe -ArgumentList @("/q", "/log", "install.log") -Wait
Restart-Service AmazonSSMAgent
```

### Verify SSM Agent Installation

```bash
# Check if your instances appear in SSM
aws ssm describe-instance-information \
  --region us-east-2 \
  --query "InstanceInformationList[*].[InstanceId,PingStatus,PlatformName]" \
  --output table
```

Expected output:
```
--------------------------------------------
|       DescribeInstanceInformation       |
+----------------+--------------+----------+
|  i-0abc123... |    Online    | Ubuntu   |
|  i-0def456... |    Online    | AmazonLinux |
+----------------+--------------+----------+
```

---

## 🏥 On-Premise/Hybrid Servers (Non-AWS)

For servers outside AWS, use **SSM Hybrid Activations**:

```bash
# Create activation
aws ssm create-activation \
  --default-instance-name "OnPrem-Server" \
  --iam-role service-role/AmazonSSMRoleForManagedInstancesQuickSetup \
  --registration-limit 10 \
  --region us-east-2 \
  --tags Key=Environment,Value=Production

# Output: Activation Code and Activation ID
# Use these to register on-premise servers
```

**On your on-premise server:**

```bash
# Ubuntu/Debian
sudo mkdir /tmp/ssm
cd /tmp/ssm
wget https://s3.us-east-2.amazonaws.com/amazon-ssm-us-east-2/latest/debian_amd64/amazon-ssm-agent.deb
sudo dpkg -i amazon-ssm-agent.deb

# Register with SSM
sudo amazon-ssm-agent -register \
  -code "ACTIVATION_CODE_HERE" \
  -id "ACTIVATION_ID_HERE" \
  -region "us-east-2"

sudo systemctl start amazon-ssm-agent
```

---

## ✅ Testing the Integration

### 1. Test AWS Connection

In Alert Whisperer UI:
- Go to **Company Settings** → **AWS Credentials**
- Click **Test Connection**
- Should see: ✅ "Successfully connected to AWS. Found X EC2 instances."

### 2. Test SSM Command Execution

```bash
# Via AWS CLI (to verify SSM is working)
aws ssm send-command \
  --instance-ids "i-0abc123def456" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["echo Hello from Alert Whisperer"]' \
  --region us-east-2
```

### 3. Test from Alert Whisperer

Once configured, Alert Whisperer can:
- ✅ List all your EC2 instances
- ✅ Check which instances have SSM Agent installed
- ✅ Install SSM Agent on instances that don't have it (bulk operation)
- ✅ Execute remediation commands when alerts fire
- ✅ Collect CloudWatch metrics

---

## 🔒 Security Best Practices

1. **Least Privilege:** Only grant necessary permissions
2. **MFA Delete:** Enable MFA on IAM user credentials
3. **Key Rotation:** Rotate access keys every 90 days
4. **Audit Logging:** Enable CloudTrail to log all API calls
5. **Encryption:** Credentials stored encrypted in Alert Whisperer database
6. **Network Security:** Restrict SSM access with VPC endpoints if possible

```bash
# Enable CloudTrail logging for IAM actions
aws cloudtrail create-trail \
  --name AlertWhispererAuditTrail \
  --s3-bucket-name my-cloudtrail-logs-bucket \
  --is-multi-region-trail

aws cloudtrail start-logging \
  --name AlertWhispererAuditTrail
```

---

## 📊 What Data Will Be Collected?

Alert Whisperer will:
- ✅ **Read** EC2 instance metadata (instance IDs, names, tags)
- ✅ **Read** SSM Agent status (online/offline)
- ✅ **Read** CloudWatch metrics (CPU, memory, disk)
- ✅ **Execute** remediation commands when approved (e.g., restart services)
- ✅ **NOT read** your application data or files
- ✅ **NOT modify** infrastructure (except approved remediation commands)

All command executions are:
- Logged in CloudTrail
- Logged in Alert Whisperer audit logs
- Require approval based on risk level

---

## 🆘 Troubleshooting

### Issue: "AWS credentials not configured"

**Solution:** Ensure credentials are saved in Alert Whisperer UI under Company Settings → AWS Credentials

### Issue: "No SSM-managed instances found"

**Solutions:**
1. Verify SSM Agent is installed and running on instances
2. Check IAM role attached to EC2 instances allows SSM communication
3. Verify instances appear in SSM console:
   ```bash
   aws ssm describe-instance-information --region us-east-2
   ```

### Issue: "Access Denied" when executing commands

**Solutions:**
1. Verify IAM user/role has `ssm:SendCommand` permission
2. Check target instances have SSM Agent online
3. Verify instances have IAM role with `AmazonSSMManagedInstanceCore` policy

### Issue: "SSM Agent offline"

**Solutions:**
1. Restart SSM Agent:
   ```bash
   sudo systemctl restart amazon-ssm-agent
   ```
2. Check internet connectivity (SSM requires outbound HTTPS)
3. Verify IAM instance profile attached to EC2 instance

---

## 🎯 Next Steps

1. ✅ Create IAM user with programmatic access
2. ✅ Save credentials in Alert Whisperer
3. ✅ Install SSM Agent on all servers
4. ✅ Verify connection in UI
5. ✅ Set up webhook integrations (Datadog, Zabbix, Prometheus)
6. ✅ Configure alert correlation settings
7. ✅ Start receiving and correlating alerts!

---

## 📞 Need Help?

- **AWS SSM Documentation:** https://docs.aws.amazon.com/systems-manager/
- **IAM Best Practices:** https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- **Alert Whisperer Integration Guide:** See `/app/AWS_INTEGRATION_GUIDE.md`

**Ready to start monitoring!** 🚀
