"""
DynamoDB Setup Script for Alert Whisperer
Creates all necessary DynamoDB tables
"""

import boto3
import os
from botocore.exceptions import ClientError
import sys

# AWS Credentials (from environment or direct)
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_SESSION_TOKEN = os.environ.get('AWS_SESSION_TOKEN')
TABLE_PREFIX = os.environ.get('DYNAMODB_TABLE_PREFIX', 'AlertWhisperer_')

# Initialize DynamoDB client
dynamodb = boto3.client(
    'dynamodb',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    aws_session_token=AWS_SESSION_TOKEN
)

def create_table(table_name, key_schema, attribute_definitions, global_secondary_indexes=None):
    """Create a DynamoDB table with on-demand billing"""
    try:
        params = {
            'TableName': table_name,
            'KeySchema': key_schema,
            'AttributeDefinitions': attribute_definitions,
            'BillingMode': 'PAY_PER_REQUEST'  # On-demand mode
        }
        
        if global_secondary_indexes:
            params['GlobalSecondaryIndexes'] = global_secondary_indexes
        
        response = dynamodb.create_table(**params)
        print(f"✅ Creating table: {table_name}")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print(f"⚠️  Table already exists: {table_name}")
            return True
        else:
            print(f"❌ Error creating table {table_name}: {e}")
            return False

def test_connection():
    """Test DynamoDB connection"""
    try:
        response = dynamodb.list_tables()
        print(f"✅ Connected to AWS DynamoDB in region: {AWS_REGION}")
        print(f"   Found {len(response['TableNames'])} existing tables")
        return True
    except Exception as e:
        print(f"❌ Failed to connect to DynamoDB: {e}")
        return False

def create_all_tables():
    """Create all required DynamoDB tables"""
    
    tables = [
        # 1. Users Table
        {
            'name': f'{TABLE_PREFIX}Users',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'},
                {'AttributeName': 'email', 'AttributeType': 'S'}
            ],
            'gsi': [{
                'IndexName': 'email-index',
                'KeySchema': [{'AttributeName': 'email', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'}
            }]
        },
        
        # 2. Companies Table
        {
            'name': f'{TABLE_PREFIX}Companies',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'},
                {'AttributeName': 'api_key', 'AttributeType': 'S'}
            ],
            'gsi': [{
                'IndexName': 'api_key-index',
                'KeySchema': [{'AttributeName': 'api_key', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'}
            }]
        },
        
        # 3. Alerts Table
        {
            'name': f'{TABLE_PREFIX}Alerts',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'},
                {'AttributeName': 'company_id', 'AttributeType': 'S'},
                {'AttributeName': 'timestamp', 'AttributeType': 'S'}
            ],
            'gsi': [{
                'IndexName': 'company_id-timestamp-index',
                'KeySchema': [
                    {'AttributeName': 'company_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}
                ],
                'Projection': {'ProjectionType': 'ALL'}
            }]
        },
        
        # 4. Incidents Table
        {
            'name': f'{TABLE_PREFIX}Incidents',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'},
                {'AttributeName': 'company_id', 'AttributeType': 'S'},
                {'AttributeName': 'status', 'AttributeType': 'S'}
            ],
            'gsi': [{
                'IndexName': 'company_id-status-index',
                'KeySchema': [
                    {'AttributeName': 'company_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'status', 'KeyType': 'RANGE'}
                ],
                'Projection': {'ProjectionType': 'ALL'}
            }]
        },
        
        # 5. AuditLogs Table
        {
            'name': f'{TABLE_PREFIX}AuditLogs',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ]
        },
        
        # 6. Notifications Table
        {
            'name': f'{TABLE_PREFIX}Notifications',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ]
        },
        
        # 7. ChatMessages Table
        {
            'name': f'{TABLE_PREFIX}ChatMessages',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ]
        },
        
        # 8. OnCallSchedules Table
        {
            'name': f'{TABLE_PREFIX}OnCallSchedules',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ]
        },
        
        # 9. Runbooks Table
        {
            'name': f'{TABLE_PREFIX}Runbooks',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ]
        },
        
        # 10. ApprovalRequests Table
        {
            'name': f'{TABLE_PREFIX}ApprovalRequests',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ]
        },
        
        # 11. CompanyConfigs Table
        {
            'name': f'{TABLE_PREFIX}CompanyConfigs',
            'key_schema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
            'attributes': [
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ]
        }
    ]
    
    print(f"\n{'='*70}")
    print(f"Creating {len(tables)} DynamoDB tables...")
    print(f"{'='*70}\n")
    
    success_count = 0
    for table_def in tables:
        if create_table(
            table_def['name'],
            table_def['key_schema'],
            table_def['attributes'],
            table_def.get('gsi')
        ):
            success_count += 1
    
    print(f"\n{'='*70}")
    print(f"✅ Successfully created/verified {success_count}/{len(tables)} tables")
    print(f"{'='*70}\n")
    
    return success_count == len(tables)

def list_tables():
    """List all DynamoDB tables"""
    try:
        response = dynamodb.list_tables()
        print(f"\n📊 DynamoDB Tables in region {AWS_REGION}:")
        print(f"{'='*70}")
        for table_name in response['TableNames']:
            if table_name.startswith(TABLE_PREFIX):
                print(f"  ✅ {table_name}")
        print(f"{'='*70}\n")
    except Exception as e:
        print(f"❌ Error listing tables: {e}")

if __name__ == "__main__":
    print(f"\n🚀 DynamoDB Setup Script")
    print(f"{'='*70}")
    print(f"Region: {AWS_REGION}")
    print(f"Table Prefix: {TABLE_PREFIX}")
    print(f"{'='*70}\n")
    
    # Test connection
    if not test_connection():
        print("\n❌ Failed to connect to DynamoDB. Please check your AWS credentials.")
        sys.exit(1)
    
    # Create tables
    if create_all_tables():
        print("✅ All tables created successfully!")
        
        # Wait for tables to be active
        print("\n⏳ Waiting for tables to become active (this may take 30-60 seconds)...")
        import time
        time.sleep(10)
        
        # List tables
        list_tables()
        
        print("✅ DynamoDB setup complete!")
        print("\n📝 Next steps:")
        print("  1. Run seed script: python3 seed_dynamodb.py")
        print("  2. Update server.py to use DynamoDB")
        print("  3. Restart backend service")
    else:
        print("\n❌ Some tables failed to create. Please check the errors above.")
        sys.exit(1)
