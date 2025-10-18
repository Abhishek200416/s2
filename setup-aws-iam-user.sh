#!/bin/bash

# Alert Whisperer - AWS IAM User Setup Script
# This script creates an IAM user with required permissions for Alert Whisperer
# Account: 728925775278
# Region: us-east-2

set -e

echo "=========================================="
echo "Alert Whisperer - AWS Setup Script"
echo "=========================================="
echo ""
echo "This script will create:"
echo "  1. IAM user: AlertWhispererService"
echo "  2. IAM policy with SSM, EC2, CloudWatch permissions"
echo "  3. Access keys for the service"
echo ""
echo "Prerequisites:"
echo "  - AWS CLI installed"
echo "  - Logged in with AWS SSO (with admin permissions)"
echo "  - Region: us-east-2"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    exit 1
fi

REGION="us-east-2"
ACCOUNT_ID="728925775278"
USER_NAME="AlertWhispererService"
POLICY_NAME="AlertWhispererServicePolicy"

echo ""
echo "Step 1: Creating IAM user..."
aws iam create-user \
  --user-name "$USER_NAME" \
  --tags Key=Purpose,Value=MSP-Monitoring Key=Service,Value=AlertWhisperer \
  --region "$REGION" 2>/dev/null || echo "User already exists"

echo ""
echo "Step 2: Creating IAM policy..."
cat > /tmp/alert-whisperer-policy.json <<'EOF'
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
        "ssm:DescribeInstanceProperties",
        "ssm:CreateActivation",
        "ssm:DeleteActivation",
        "ssm:DescribeActivations"
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
    },
    {
      "Sid": "IAMPassRoleForSSM",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::*:role/service-role/AmazonSSMRoleForManagedInstancesQuickSetup"
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name "$POLICY_NAME" \
  --policy-document file:///tmp/alert-whisperer-policy.json \
  --region "$REGION" 2>/dev/null || echo "Policy already exists"

POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

echo ""
echo "Step 3: Attaching policy to user..."
aws iam attach-user-policy \
  --user-name "$USER_NAME" \
  --policy-arn "$POLICY_ARN" \
  --region "$REGION"

echo ""
echo "Step 4: Creating access keys..."
echo ""
echo "⚠️  IMPORTANT: Save these credentials securely!"
echo "================================================================"
ACCESS_KEY_OUTPUT=$(aws iam create-access-key --user-name "$USER_NAME" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text 2>/dev/null || echo "ERROR: Access key may already exist. Delete old key first with: aws iam list-access-keys --user-name $USER_NAME")

if [[ $ACCESS_KEY_OUTPUT == ERROR* ]]; then
    echo "$ACCESS_KEY_OUTPUT"
    echo ""
    echo "To delete old access keys:"
    echo "  aws iam list-access-keys --user-name $USER_NAME"
    echo "  aws iam delete-access-key --user-name $USER_NAME --access-key-id AKIAXXXXX"
    echo ""
    echo "Then run this script again."
else
    ACCESS_KEY_ID=$(echo "$ACCESS_KEY_OUTPUT" | awk '{print $1}')
    SECRET_ACCESS_KEY=$(echo "$ACCESS_KEY_OUTPUT" | awk '{print $2}')
    
    echo "AWS Access Key ID:     $ACCESS_KEY_ID"
    echo "AWS Secret Access Key: $SECRET_ACCESS_KEY"
    echo "AWS Region:            $REGION"
    echo "AWS Account ID:        $ACCOUNT_ID"
    echo "================================================================"
    echo ""
    echo "✅ Setup complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Copy the credentials above"
    echo "  2. Open Alert Whisperer UI"
    echo "  3. Go to: Dashboard → Companies → Select Company → Company Settings"
    echo "  4. Navigate to: AWS Credentials tab"
    echo "  5. Paste the credentials and click 'Save'"
    echo "  6. Click 'Test Connection' to verify"
    echo ""
    echo "Or use the API:"
    echo ""
    echo "curl -X POST 'http://localhost:8001/api/companies/{company_id}/aws-credentials' \\"
    echo "  -H 'Authorization: Bearer YOUR_JWT_TOKEN' \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -d '{"
    echo "    \"access_key_id\": \"$ACCESS_KEY_ID\","
    echo "    \"secret_access_key\": \"$SECRET_ACCESS_KEY\","
    echo "    \"region\": \"$REGION\""
    echo "  }'"
    echo ""
    
    # Save to file for easy access
    cat > /tmp/alert-whisperer-credentials.txt <<CREDS
Alert Whisperer AWS Credentials
================================
AWS Access Key ID:     $ACCESS_KEY_ID
AWS Secret Access Key: $SECRET_ACCESS_KEY
AWS Region:            $REGION
AWS Account ID:        $ACCOUNT_ID

Created: $(date)
CREDS
    
    echo "Credentials also saved to: /tmp/alert-whisperer-credentials.txt"
fi

echo ""
echo "Done! 🚀"
