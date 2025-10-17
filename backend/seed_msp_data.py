"""Seed MSP Data - Initialize Global Runbooks and Default Settings
Run this to populate the database with pre-built runbooks
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime, timezone
import uuid

# Load environment
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Import runbook library
from runbook_library import get_global_runbooks
from msp_models import EnhancedRunbook


async def seed_global_runbooks(db):
    """Seed global runbooks into database"""
    print("Seeding global runbooks...")
    
    # Get runbooks from library
    runbooks_data = get_global_runbooks()
    
    # Clear existing global runbooks
    await db.enhanced_runbooks.delete_many({"is_global": True})
    
    # Insert new runbooks
    runbooks_inserted = 0
    for runbook_data in runbooks_data:
        runbook = EnhancedRunbook(
            id=str(uuid.uuid4()),
            name=runbook_data["name"],
            description=runbook_data["description"],
            category=runbook_data["category"],
            script_content=runbook_data["script_content"],
            script_type=runbook_data["script_type"],
            cloud_provider=runbook_data["cloud_provider"],
            risk_level=runbook_data["risk_level"],
            auto_approve=runbook_data["auto_approve"],
            parameters=runbook_data.get("parameters", []),
            tags=runbook_data["tags"],
            company_id=None,
            is_global=True,
            created_by="system",
            created_at=datetime.now(timezone.utc).isoformat(),
            updated_at=datetime.now(timezone.utc).isoformat(),
            execution_count=0,
            success_rate=0.0
        )
        
        await db.enhanced_runbooks.insert_one(runbook.model_dump())
        runbooks_inserted += 1
        print(f"  ✅ {runbook.name}")
    
    print(f"\n🎉 Seeded {runbooks_inserted} global runbooks!")


async def create_default_escalation_policy(db, company_id: str):
    """Create default escalation policy for a company"""
    from msp_models import EscalationPolicy
    
    # Check if already exists
    existing = await db.escalation_policies.find_one({"company_id": company_id})
    if existing:
        return
    
    policy = EscalationPolicy(
        id=str(uuid.uuid4()),
        company_id=company_id,
        name="Default Escalation Policy",
        enabled=True,
        trigger_conditions={
            "unacknowledged_minutes": 30,
            "priority_min": 80
        },
        escalation_levels=[
            {
                "level": 1,
                "delay_minutes": 30,
                "notify_roles": ["technician"],
                "notify_users": []
            },
            {
                "level": 2,
                "delay_minutes": 60,
                "notify_roles": ["company_admin"],
                "notify_users": []
            },
            {
                "level": 3,
                "delay_minutes": 120,
                "notify_roles": ["msp_admin"],
                "notify_users": []
            }
        ],
        sla_breach_action="escalate",
        created_at=datetime.now(timezone.utc).isoformat()
    )
    
    await db.escalation_policies.insert_one(policy.model_dump())
    print(f"  ✅ Created default escalation policy for {company_id}")


async def create_default_sla_policy(db, company_id: str):
    """Create default SLA policy for a company"""
    from msp_models import SLAPolicy
    
    # Check if already exists
    existing = await db.sla_policies.find_one({"company_id": company_id})
    if existing:
        return
    
    policy = SLAPolicy(
        id=str(uuid.uuid4()),
        company_id=company_id,
        name="Default SLA Policy",
        enabled=True,
        priority_slas={
            "critical": 60,      # 1 hour
            "high": 240,         # 4 hours
            "medium": 480,       # 8 hours
            "low": 1440          # 24 hours
        },
        acknowledgment_sla_minutes=15,
        breach_notification_enabled=True,
        breach_notification_recipients=[],
        created_at=datetime.now(timezone.utc).isoformat()
    )
    
    await db.sla_policies.insert_one(policy.model_dump())
    print(f"  ✅ Created default SLA policy for {company_id}")


async def create_default_auto_assignment_rule(db, company_id: str):
    """Create default auto-assignment rule for a company"""
    from msp_models import AutoAssignmentRule
    
    # Check if already exists
    existing = await db.auto_assignment_rules.find_one({"company_id": company_id})
    if existing:
        return
    
    rule = AutoAssignmentRule(
        id=str(uuid.uuid4()),
        company_id=company_id,
        enabled=True,
        priority=1,
        conditions={},  # Match all incidents
        assignment_strategy="load_balance",
        required_skills=[],
        target_technicians=[],
        escalation_time_minutes=30,
        created_at=datetime.now(timezone.utc).isoformat()
    )
    
    await db.auto_assignment_rules.insert_one(rule.model_dump())
    print(f"  ✅ Created default auto-assignment rule for {company_id}")


async def seed_company_defaults(db):
    """Create default policies for all existing companies"""
    print("\nSeeding company defaults...")
    
    # Get all companies
    companies = await db.companies.find({}, {"_id": 0}).to_list(100)
    
    for company in companies:
        company_id = company["id"]
        print(f"\nConfiguring {company['name']}...")
        
        await create_default_escalation_policy(db, company_id)
        await create_default_sla_policy(db, company_id)
        await create_default_auto_assignment_rule(db, company_id)


async def main():
    """Main seed function"""
    print("=" * 60)
    print("MSP PLATFORM DATA SEEDING")
    print("=" * 60)
    
    # Connect to MongoDB
    mongo_url = os.environ['MONGO_URL']
    client = AsyncIOMotorClient(mongo_url)
    db = client[os.environ['DB_NAME']]
    
    # Seed global runbooks
    await seed_global_runbooks(db)
    
    # Seed company defaults
    await seed_company_defaults(db)
    
    print("\n" + "=" * 60)
    print("✅ MSP DATA SEEDING COMPLETE!")
    print("=" * 60)
    
    client.close()


if __name__ == "__main__":
    asyncio.run(main())
