"""Database initialization and index management"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timezone, timedelta
import os

async def init_indexes(db):
    """
    Initialize all MongoDB indexes including TTL indexes
    Called on application startup
    """
    
    # ============= TTL Indexes for Auto-Cleanup =============
    
    # Refresh tokens - expire based on expires_at field
    await db["refresh_tokens"].create_index(
        "expires_at",
        expireAfterSeconds=0,
        name="refresh_token_ttl"
    )
    
    # Short-term memory - expire after 48 hours
    await db["short_memory"].create_index(
        "expires_at",
        expireAfterSeconds=0,
        name="short_memory_ttl"
    )
    
    # Idempotency keys - expire after 24 hours
    await db["webhook_idempotency"].create_index(
        "expires_at",
        expireAfterSeconds=0,
        name="idempotency_ttl"
    )
    
    # Agent decisions - keep for 30 days
    await db["agent_decisions"].create_index(
        "created_at",
        expireAfterSeconds=30*24*60*60,  # 30 days
        name="decisions_ttl"
    )
    
    # ============= Performance Indexes =============
    
    # Alerts - compound index for company + status queries
    await db["alerts"].create_index(
        [("company_id", 1), ("status", 1), ("created_at", -1)],
        name="alerts_company_status"
    )
    
    # Incidents - compound index for company + status queries
    await db["incidents"].create_index(
        [("company_id", 1), ("status", 1), ("priority_score", -1)],
        name="incidents_company_priority"
    )
    
    # Incidents - index for correlation queries
    await db["incidents"].create_index(
        [("company_id", 1), ("aggregation_key", 1), ("created_at", -1)],
        name="incidents_correlation"
    )
    
    # Users - unique email index
    await db["users"].create_index(
        "email",
        unique=True,
        name="users_email_unique"
    )
    
    # Companies - API key index for webhook auth
    await db["companies"].create_index(
        "api_key",
        name="companies_api_key"
    )
    
    # Audit logs - compound index for queries
    await db["audit_logs"].create_index(
        [("company_id", 1), ("action", 1), ("timestamp", -1)],
        name="audit_company_action"
    )
    
    # Approval requests - status + expiry index
    await db["approval_requests"].create_index(
        [("status", 1), ("expires_at", 1)],
        name="approvals_status_expiry"
    )
    
    # Rate limiting - compound index with TTL
    await db["rate_limit_windows"].create_index(
        [("company_id", 1), ("window_start", 1)],
        name="rate_limit_windows"
    )
    await db["rate_limit_windows"].create_index(
        "window_start",
        expireAfterSeconds=300,  # 5 minutes
        name="rate_limit_ttl"
    )
    
    # Memory collections - compound indexes
    await db["short_memory"].create_index(
        [("incident_id", 1), ("company_id", 1)],
        name="memory_incident"
    )
    
    await db["long_memory"].create_index(
        [("company_id", 1), ("signature", 1), ("created_at", -1)],
        name="memory_company_signature"
    )
    
    # SSM executions - command tracking
    await db["ssm_executions"].create_index(
        [("company_id", 1), ("status", 1), ("created_at", -1)],
        name="ssm_company_status"
    )
    
    # Webhook security configs - company index
    await db["webhook_security_configs"].create_index(
        "company_id",
        unique=True,
        name="webhook_security_company"
    )
    
    # Correlation configs - company index
    await db["correlation_configs"].create_index(
        "company_id",
        unique=True,
        name="correlation_company"
    )
    
    print("✅ All database indexes created successfully")
    print("   - TTL indexes: refresh_tokens, short_memory, idempotency, decisions")
    print("   - Performance indexes: alerts, incidents, users, companies, audit_logs")
    print("   - Unique indexes: users.email, webhook_security, correlation_configs")

async def cleanup_expired_data(db):
    """
    Manual cleanup function for data that doesn't use TTL indexes
    Can be called periodically or on-demand
    """
    now = datetime.now(timezone.utc)
    
    # Clean up expired approval requests
    result = await db["approval_requests"].update_many(
        {"expires_at": {"$lt": now}, "status": "pending"},
        {"$set": {"status": "expired"}}
    )
    print(f"✅ Expired {result.modified_count} approval requests")
    
    # Clean up old rate limit windows (MongoDB TTL should handle this, but backup)
    cutoff = now - timedelta(minutes=10)
    result = await db["rate_limit_windows"].delete_many(
        {"window_start": {"$lt": cutoff}}
    )
    print(f"✅ Cleaned up {result.deleted_count} old rate limit windows")
    
    # Clean up old idempotency records (MongoDB TTL should handle this, but backup)
    cutoff = now - timedelta(hours=25)  # 24h + 1h buffer
    result = await db["webhook_idempotency"].delete_many(
        {"created_at": {"$lt": cutoff}}
    )
    print(f"✅ Cleaned up {result.deleted_count} old idempotency records")
    
    return {
        "expired_approvals": result.modified_count,
        "cleaned_rate_windows": result.deleted_count,
        "cleaned_idempotency": result.deleted_count
    }

if __name__ == "__main__":
    # Test script to run index creation
    import asyncio
    from dotenv import load_dotenv
    from pathlib import Path
    
    ROOT_DIR = Path(__file__).parent
    load_dotenv(ROOT_DIR / '.env')
    
    async def main():
        mongo_url = os.environ['MONGO_URL']
        client = AsyncIOMotorClient(mongo_url)
        db = client[os.environ['DB_NAME']]
        
        await init_indexes(db)
        print("\n✅ Database initialization complete")
    
    asyncio.run(main())
