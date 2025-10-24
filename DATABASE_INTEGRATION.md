# Database Integration Guide

This application supports both **MongoDB** and **AWS DynamoDB** as database backends. You can switch between them or migrate data from MongoDB to DynamoDB.

## Table of Contents
- [Architecture](#architecture)
- [MongoDB Setup (Default)](#mongodb-setup-default)
- [DynamoDB Setup](#dynamodb-setup)
- [Migration from MongoDB to DynamoDB](#migration-from-mongodb-to-dynamodb)
- [Configuration](#configuration)
- [Database Adapter API](#database-adapter-api)

---

## Architecture

The application uses a **Database Adapter Pattern** that provides a unified interface for both MongoDB and DynamoDB. This allows seamless switching between databases without code changes.

```
Application Code
       ↓
DatabaseAdapter (Abstract)
    ↓           ↓
MongoDBAdapter  DynamoDBAdapter
    ↓           ↓
  MongoDB     DynamoDB
```

---

## MongoDB Setup (Default)

MongoDB is the default database. No additional configuration needed.

### Connection
Set the `MONGO_URL` environment variable in `backend/.env`:
```bash
MONGO_URL=mongodb://localhost:27017/alertwhisperer
```

### Collections
The application uses these collections:
- `companies` - Company/client data
- `users` - User accounts
- `alerts` - Alert data from monitoring tools
- `incidents` - Correlated incidents
- `runbooks` - Automation runbooks
- `notifications` - User notifications
- `chat_messages` - Chat messages
- `audit_logs` - System audit trail
- `correlation_config` - Correlation settings
- `webhook_security_config` - Webhook security
- `rate_limit_config` - Rate limiting settings
- `sla_config` - SLA configuration
- `aws_credentials` - Encrypted AWS credentials

---

## DynamoDB Setup

To use DynamoDB instead of MongoDB:

### 1. Install AWS SDK
```bash
pip install boto3
```

### 2. Configure AWS Credentials
Set up AWS credentials using one of these methods:

**Method A: AWS CLI**
```bash
aws configure
```

**Method B: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
```

**Method C: IAM Role** (for EC2/ECS)
The application will automatically use the instance role.

### 3. Create DynamoDB Tables

**Option A: Using Migration Script**
```bash
# This will create tables and migrate data if MongoDB exists
python backend/migrate_to_dynamodb.py migrate
```

**Option B: Using CloudFormation**
```bash
# Generate CloudFormation template
python backend/migrate_to_dynamodb.py cloudformation

# Deploy the template
aws cloudformation create-stack \
  --stack-name alert-whisperer-dynamodb \
  --template-body file://dynamodb_tables.json
```

**Option C: Manual Creation via AWS Console**
Create tables with these specifications:
- **Primary Key**: `id` (String)
- **Billing Mode**: On-Demand
- **Global Secondary Indexes**:
  - For `alerts` table:
    - `company-timestamp-index`: company_id (HASH), timestamp (RANGE)
    - `status-index`: status (HASH)
  - For `incidents` table:
    - `company-created-index`: company_id (HASH), created_at (RANGE)
    - `status-index`: status (HASH)

### 4. Configure Application
Set environment variables in `backend/.env`:
```bash
DATABASE_TYPE=dynamodb
AWS_REGION=us-east-1
DYNAMODB_TABLE_PREFIX=AlertWhisperer
```

### 5. Restart Services
```bash
sudo supervisorctl restart backend
```

---

## Migration from MongoDB to DynamoDB

### Prerequisites
- MongoDB instance with existing data
- AWS credentials configured
- boto3 installed (`pip install boto3`)

### Migration Steps

1. **Full Migration** (all collections):
```bash
python backend/migrate_to_dynamodb.py migrate
```

2. **Single Collection Migration**:
```bash
python backend/migrate_to_dynamodb.py migrate-collection alerts
```

3. **Verify Migration**:
```bash
python backend/migrate_to_dynamodb.py verify
```

Output example:
```
Verifying migration...
✓ companies: MongoDB=3, DynamoDB=3
✓ users: MongoDB=5, DynamoDB=5
✓ alerts: MongoDB=1250, DynamoDB=1250
✓ incidents: MongoDB=85, DynamoDB=85
```

4. **Switch to DynamoDB**:
After successful verification, update `backend/.env`:
```bash
DATABASE_TYPE=dynamodb
```

5. **Restart Backend**:
```bash
sudo supervisorctl restart backend
```

### Migration Features

- **Batch Processing**: Migrates 25 documents at a time for efficiency
- **Error Handling**: Continues migration even if individual documents fail
- **Progress Tracking**: Real-time progress display
- **Data Conversion**: Automatically converts MongoDB documents to DynamoDB items
- **Datetime Handling**: Converts datetime objects to ISO strings
- **GSI Creation**: Creates optimized Global Secondary Indexes

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_TYPE` | `mongodb` | Database type: `mongodb` or `dynamodb` |
| `MONGO_URL` | `mongodb://localhost:27017/alertwhisperer` | MongoDB connection URL |
| `AWS_REGION` | `us-east-1` | AWS region for DynamoDB |
| `DYNAMODB_TABLE_PREFIX` | `AlertWhisperer` | Prefix for DynamoDB table names |

### Backend Configuration

In `server.py`, the database adapter is initialized like this:

```python
# MongoDB (default)
from motor.motor_asyncio import AsyncIOMotorClient
from database_adapter import get_database_adapter

mongo_client = AsyncIOMotorClient(os.getenv('MONGO_URL'))
db = mongo_client.get_default_database()
db_adapter = get_database_adapter('mongodb', db=db)

# Or for DynamoDB
db_adapter = get_database_adapter('dynamodb', 
    region='us-east-1',
    table_prefix='AlertWhisperer'
)
```

---

## Database Adapter API

The `DatabaseAdapter` class provides a unified interface:

### Methods

#### `insert_one(collection, document) -> str`
Insert a single document and return its ID.

```python
alert_id = await db_adapter.insert_one('alerts', {
    'id': 'alert-123',
    'company_id': 'comp-1',
    'severity': 'high',
    'message': 'CPU usage high'
})
```

#### `find_one(collection, query, projection=None) -> dict`
Find a single document.

```python
alert = await db_adapter.find_one('alerts', {'id': 'alert-123'})
```

#### `find(collection, query, projection=None, sort=None, limit=None) -> list`
Find multiple documents.

```python
alerts = await db_adapter.find(
    'alerts',
    {'company_id': 'comp-1', 'status': 'active'},
    sort=[('timestamp', -1)],
    limit=10
)
```

#### `update_one(collection, query, update) -> int`
Update a single document.

```python
count = await db_adapter.update_one(
    'alerts',
    {'id': 'alert-123'},
    {'$set': {'status': 'acknowledged'}}
)
```

#### `delete_one(collection, query) -> int`
Delete a single document.

```python
count = await db_adapter.delete_one('alerts', {'id': 'alert-123'})
```

#### `count_documents(collection, query) -> int`
Count documents matching query.

```python
count = await db_adapter.count_documents('alerts', {'status': 'active'})
```

### Query Operators

Both adapters support MongoDB-style query operators:

| Operator | Description | Example |
|----------|-------------|---------|
| `$gt` | Greater than | `{'priority': {'$gt': 50}}` |
| `$gte` | Greater than or equal | `{'priority': {'$gte': 50}}` |
| `$lt` | Less than | `{'priority': {'$lt': 30}}` |
| `$lte` | Less than or equal | `{'priority': {'$lte': 30}}` |
| `$ne` | Not equal | `{'status': {'$ne': 'resolved'}}` |
| `$in` | In array | `{'severity': {'$in': ['high', 'critical']}}` |

---

## Cost Comparison

### MongoDB Atlas
- **Free Tier**: 512 MB storage
- **Basic**: ~$57/month for 10GB
- **Scaling**: Linear cost increase

### DynamoDB
- **Free Tier**: 25 GB storage, 25 WCU, 25 RCU
- **On-Demand**: Pay per request
  - Write: $1.25 per million
  - Read: $0.25 per million
- **Provisioned**: Fixed capacity
  - Write: $0.47 per WCU per month
  - Read: $0.09 per RCU per month

**Recommendation**: 
- Use **MongoDB** for development and small deployments
- Use **DynamoDB** for production AWS deployments with auto-scaling needs

---

## Troubleshooting

### MongoDB Connection Issues
```bash
# Check MongoDB is running
sudo systemctl status mongod

# Check connection
mongo --eval "db.adminCommand('ping')"
```

### DynamoDB Issues

**Access Denied**:
- Check IAM permissions
- Ensure tables exist in the correct region
- Verify AWS credentials

**Table Not Found**:
```bash
# List tables
aws dynamodb list-tables --region us-east-1

# Create tables
python backend/migrate_to_dynamodb.py migrate
```

**Slow Performance**:
- Check if using appropriate indexes
- Consider switching from scan to query operations
- Enable DynamoDB Accelerator (DAX) for caching

---

## Best Practices

1. **Development**: Use MongoDB for faster iteration
2. **Production**: Use DynamoDB for AWS deployments
3. **Backup**: Enable Point-in-Time Recovery for DynamoDB
4. **Monitoring**: Use CloudWatch for DynamoDB metrics
5. **Cost**: Start with on-demand pricing, switch to provisioned for predictable workloads
6. **Security**: Enable encryption at rest for both databases

---

## Support

For issues or questions:
- MongoDB: Check logs at `/var/log/mongodb/mongod.log`
- DynamoDB: Check CloudWatch logs
- Application: Check backend logs at `/var/log/supervisor/backend.err.log`
