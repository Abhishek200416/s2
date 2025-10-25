import boto3
import os
from pprint import pprint

AWS_REGION = "us-east-1"
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN")
TABLE_PREFIX = "AlertWhisperer_"

dynamodb = boto3.resource(
    'dynamodb',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    aws_session_token=AWS_SESSION_TOKEN
)

# Test query
print("=" * 60)
print("Testing DynamoDB - Querying Companies Table")
print("=" * 60)

companies_table = dynamodb.Table(f'{TABLE_PREFIX}Companies')
response = companies_table.scan(Limit=10)

print(f"\nFound {len(response['Items'])} companies:\n")
for company in response['Items']:
    print(f"  ✅ {company['name']} (ID: {company['id']})")
    print(f"     API Key: {company.get('api_key', 'N/A')[:20]}...")
    print(f"     Assets: {len(company.get('assets', []))}")
    print()

print("=" * 60)
print("✅ DynamoDB is working correctly!")
print("=" * 60)
