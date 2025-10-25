"""
Seed Script for DynamoDB
Creates initial data for Alert Whisperer platform
Run this after creating DynamoDB tables
"""

import asyncio
import boto3
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
import uuid
import bcrypt
import secrets

load_dotenv()

# DynamoDB Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_SESSION_TOKEN = os.environ.get('AWS_SESSION_TOKEN')
TABLE_PREFIX = os.environ.get('DYNAMODB_TABLE_PREFIX', 'AlertWhisperer_')

# Initialize DynamoDB
dynamodb_params = {
    'region_name': AWS_REGION,
    'aws_access_key_id': AWS_ACCESS_KEY_ID,
    'aws_secret_access_key': AWS_SECRET_ACCESS_KEY
}
if AWS_SESSION_TOKEN:
    dynamodb_params['aws_session_token'] = AWS_SESSION_TOKEN

dynamodb = boto3.resource('dynamodb', **dynamodb_params)


def generate_api_key():
    """Generate a secure API key"""
    return f"ak_{secrets.token_urlsafe(32)}"


def generate_hmac_secret():
    """Generate a secure HMAC secret"""
    return secrets.token_urlsafe(48)


def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


async def seed_users():
    """Create initial users"""
    print("\n📝 Seeding Users...")
    
    users_table = dynamodb.Table(f'{TABLE_PREFIX}Users')
    
    users = [
        {
            'id': str(uuid.uuid4()),
            'email': 'admin@alertwhisperer.com',
            'name': 'Admin User',
            'hashed_password': hash_password('admin123'),
            'role': 'msp_admin',
            'permissions': ['*'],
            'company_id': 'all',
            'created_at': datetime.utcnow().isoformat()
        },
        {
            'id': str(uuid.uuid4()),
            'email': 'john@acmecorp.com',
            'name': 'John Doe',
            'hashed_password': hash_password('password123'),
            'role': 'company_admin',
            'permissions': ['view_alerts', 'manage_incidents', 'view_reports'],
            'company_id': 'comp-acme',
            'created_at': datetime.utcnow().isoformat()
        },
        {
            'id': str(uuid.uuid4()),
            'email': 'sarah@acmecorp.com',
            'name': 'Sarah Tech',
            'hashed_password': hash_password('password123'),
            'role': 'technician',
            'permissions': ['view_alerts', 'manage_assigned_incidents'],
            'company_id': 'comp-acme',
            'created_at': datetime.utcnow().isoformat()
        }
    ]
    
    for user in users:
        users_table.put_item(Item=user)
        print(f"  ✅ Created user: {user['email']} ({user['role']})")
    
    return users


async def seed_companies():
    """Create initial companies"""
    print("\n🏢 Seeding Companies...")
    
    companies_table = dynamodb.Table(f'{TABLE_PREFIX}Companies')
    
    companies = [
        {
            'id': 'comp-acme',
            'name': 'Acme Corporation',
            'api_key': generate_api_key(),
            'created_at': datetime.utcnow().isoformat(),
            'maintenance_window': 'Sunday 2:00 AM - 4:00 AM',
            'contact_email': 'ops@acmecorp.com'
        },
        {
            'id': 'comp-techstart',
            'name': 'TechStart Inc',
            'api_key': generate_api_key(),
            'created_at': datetime.utcnow().isoformat(),
            'maintenance_window': 'Saturday 1:00 AM - 3:00 AM',
            'contact_email': 'tech@techstart.io'
        },
        {
            'id': 'comp-global',
            'name': 'Global Systems',
            'api_key': generate_api_key(),
            'created_at': datetime.utcnow().isoformat(),
            'maintenance_window': 'Daily 3:00 AM - 4:00 AM',
            'contact_email': 'support@globalsystems.net'
        }
    ]
    
    for company in companies:
        companies_table.put_item(Item=company)
        print(f"  ✅ Created company: {company['name']}")
        print(f"     API Key: {company['api_key']}")
    
    return companies


async def seed_company_configs(companies):
    """Create initial company configurations"""
    print("\n⚙️  Seeding Company Configurations...")
    
    configs_table = dynamodb.Table(f'{TABLE_PREFIX}CompanyConfigs')
    
    for company in companies:
        company_id = company['id']
        
        # Webhook Security Config
        webhook_config = {
            'id': f'{company_id}_webhook_security',
            'company_id': company_id,
            'config_type': 'webhook_security',
            'config_data': {
                'enabled': False,
                'hmac_secret': generate_hmac_secret(),
                'signature_header': 'X-Signature',
                'timestamp_header': 'X-Timestamp',
                'max_timestamp_diff_seconds': 300
            },
            'updated_at': datetime.utcnow().isoformat()
        }
        configs_table.put_item(Item=webhook_config)
        
        # Correlation Config
        correlation_config = {
            'id': f'{company_id}_correlation',
            'company_id': company_id,
            'config_type': 'correlation',
            'config_data': {
                'time_window_minutes': 15,
                'aggregation_key': 'asset|signature',
                'auto_correlate': True,
                'min_alerts_for_incident': 2
            },
            'updated_at': datetime.utcnow().isoformat()
        }
        configs_table.put_item(Item=correlation_config)
        
        # Rate Limit Config
        rate_limit_config = {
            'id': f'{company_id}_rate_limit',
            'company_id': company_id,
            'config_type': 'rate_limit',
            'config_data': {
                'enabled': True,
                'requests_per_minute': 100,
                'burst_size': 20
            },
            'updated_at': datetime.utcnow().isoformat()
        }
        configs_table.put_item(Item=rate_limit_config)
        
        # SLA Config
        sla_config = {
            'id': f'{company_id}_sla',
            'company_id': company_id,
            'config_type': 'sla',
            'config_data': {
                'response_sla': {
                    'critical': 30,
                    'high': 120,
                    'medium': 480,
                    'low': 1440
                },
                'resolution_sla': {
                    'critical': 240,
                    'high': 480,
                    'medium': 1440,
                    'low': 2880
                },
                'business_hours_only': False,
                'escalation_enabled': True,
                'escalation_chain': [
                    {'level': 1, 'role': 'technician', 'delay_minutes': 30},
                    {'level': 2, 'role': 'company_admin', 'delay_minutes': 60},
                    {'level': 3, 'role': 'msp_admin', 'delay_minutes': 120}
                ],
                'warning_threshold_minutes': 30
            },
            'updated_at': datetime.utcnow().isoformat()
        }
        configs_table.put_item(Item=sla_config)
        
        print(f"  ✅ Created configs for: {company['name']}")


async def seed_oncall_schedules(users):
    """Create sample on-call schedules"""
    print("\n📅 Seeding On-Call Schedules...")
    
    schedules_table = dynamodb.Table(f'{TABLE_PREFIX}OnCallSchedules')
    
    # Find technician
    technician = next((u for u in users if u['role'] == 'technician'), None)
    
    if technician:
        schedules = [
            {
                'id': str(uuid.uuid4()),
                'company_id': technician['company_id'],
                'user_id': technician['id'],
                'user_name': technician['name'],
                'day_of_week': 'Monday',
                'start_time': '09:00',
                'end_time': '17:00',
                'created_at': datetime.utcnow().isoformat()
            },
            {
                'id': str(uuid.uuid4()),
                'company_id': technician['company_id'],
                'user_id': technician['id'],
                'user_name': technician['name'],
                'day_of_week': 'Tuesday',
                'start_time': '09:00',
                'end_time': '17:00',
                'created_at': datetime.utcnow().isoformat()
            }
        ]
        
        for schedule in schedules:
            schedules_table.put_item(Item=schedule)
            print(f"  ✅ Created schedule: {schedule['day_of_week']} for {schedule['user_name']}")


async def seed_runbooks():
    """Create sample runbooks"""
    print("\n📖 Seeding Runbooks...")
    
    runbooks_table = dynamodb.Table(f'{TABLE_PREFIX}Runbooks')
    
    runbooks = [
        {
            'id': str(uuid.uuid4()),
            'company_id': 'comp-acme',
            'name': 'Clear Disk Space',
            'description': 'Cleans up temporary files and logs to free disk space',
            'risk_level': 'low',
            'ssm_document_name': 'AWS-RunShellScript',
            'parameters': {
                'commands': [
                    'rm -rf /tmp/*',
                    'apt-get clean',
                    'journalctl --vacuum-time=7d',
                    'df -h'
                ]
            },
            'target_tag_key': 'Environment',
            'target_tag_value': 'Production',
            'created_at': datetime.utcnow().isoformat()
        },
        {
            'id': str(uuid.uuid4()),
            'company_id': 'comp-acme',
            'name': 'Restart Nginx',
            'description': 'Restarts the Nginx web server',
            'risk_level': 'medium',
            'ssm_document_name': 'AWS-RunShellScript',
            'parameters': {
                'commands': [
                    'systemctl restart nginx',
                    'systemctl status nginx'
                ]
            },
            'target_tag_key': 'Role',
            'target_tag_value': 'WebServer',
            'created_at': datetime.utcnow().isoformat()
        }
    ]
    
    for runbook in runbooks:
        runbooks_table.put_item(Item=runbook)
        print(f"  ✅ Created runbook: {runbook['name']} ({runbook['risk_level']} risk)")


async def main():
    """Run all seed functions"""
    print("\n" + "="*60)
    print("  ALERT WHISPERER - DYNAMODB SEED SCRIPT")
    print("="*60)
    
    try:
        # Test connection
        print("\n🔍 Testing DynamoDB connection...")
        users_table = dynamodb.Table(f'{TABLE_PREFIX}Users')
        users_table.load()
        print("  ✅ Connection successful!")
        
        # Seed data
        users = await seed_users()
        companies = await seed_companies()
        await seed_company_configs(companies)
        await seed_oncall_schedules(users)
        await seed_runbooks()
        
        print("\n" + "="*60)
        print("  ✅ SEED COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("\n📝 Login Credentials:")
        print("  Email: admin@alertwhisperer.com")
        print("  Password: admin123")
        print("\n📝 API Keys (for webhook testing):")
        for company in companies:
            print(f"  {company['name']}: {company['api_key']}")
        print("\n")
        
    except Exception as e:
        print(f"\n❌ Seed failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
