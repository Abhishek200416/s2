#!/bin/bash

# Alert Whisperer - DynamoDB Migration Quick Start Script
# This script helps you quickly migrate from MongoDB to DynamoDB

echo "=================================================="
echo "  ALERT WHISPERER - DYNAMODB MIGRATION"
echo "=================================================="
echo ""

# Check if .env file exists
if [ ! -f "/app/backend/.env" ]; then
    echo "❌ Error: /app/backend/.env file not found"
    echo "Please create the .env file with DynamoDB credentials first"
    exit 1
fi

# Check for required environment variables
source /app/backend/.env

if [ -z "$AWS_REGION" ] || [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "❌ Error: Missing required environment variables"
    echo ""
    echo "Please add the following to /app/backend/.env:"
    echo ""
    echo "AWS_REGION=us-east-1"
    echo "AWS_ACCESS_KEY_ID=your_access_key"
    echo "AWS_SECRET_ACCESS_KEY=your_secret_key"
    echo "DYNAMODB_TABLE_PREFIX=AlertWhisperer_"
    echo ""
    exit 1
fi

echo "✅ Environment variables found"
echo ""

# Install Python dependencies
echo "📦 Installing boto3 (AWS SDK)..."
cd /app/backend
pip install boto3 botocore --quiet
echo "✅ boto3 installed"
echo ""

# Test DynamoDB connection
echo "🔍 Testing DynamoDB connection..."
python3 << EOF
import boto3
import os
from dotenv import load_dotenv

load_dotenv()

try:
    dynamodb = boto3.resource(
        'dynamodb',
        region_name=os.environ.get('AWS_REGION'),
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
    
    # Try to access Users table
    table = dynamodb.Table(f"{os.environ.get('DYNAMODB_TABLE_PREFIX', 'AlertWhisperer_')}Users")
    table.load()
    print("✅ DynamoDB connection successful!")
    print(f"   Table: {table.name}")
    exit(0)
except Exception as e:
    print(f"❌ DynamoDB connection failed: {e}")
    print("")
    print("Please check:")
    print("1. AWS credentials are correct")
    print("2. AWS region is correct")
    print("3. DynamoDB tables have been created in AWS Console")
    print("4. IAM user has DynamoDB permissions")
    exit(1)
EOF

if [ $? -ne 0 ]; then
    exit 1
fi

echo ""

# Ask user if they want to seed data
echo "📊 Do you want to seed initial data? (y/n)"
read -r response

if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo ""
    echo "🌱 Seeding initial data..."
    python seed_dynamodb.py
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "=================================================="
        echo "  ✅ MIGRATION COMPLETED SUCCESSFULLY!"
        echo "=================================================="
        echo ""
        echo "Next steps:"
        echo "1. Restart the backend server:"
        echo "   sudo supervisorctl restart backend"
        echo ""
        echo "2. Test the login endpoint:"
        echo "   Email: admin@alertwhisperer.com"
        echo "   Password: admin123"
        echo ""
        echo "3. Check the migration guide for API testing:"
        echo "   cat /app/DYNAMODB_MIGRATION_GUIDE.txt"
        echo ""
    else
        echo "❌ Seeding failed. Please check the errors above."
        exit 1
    fi
else
    echo ""
    echo "⏭️  Skipping data seeding"
    echo ""
    echo "To seed data later, run:"
    echo "  cd /app/backend && python seed_dynamodb.py"
    echo ""
fi
