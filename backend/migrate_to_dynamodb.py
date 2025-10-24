"""
Migration Script: MongoDB to DynamoDB
This script migrates data from MongoDB to AWS DynamoDB
"""

import asyncio
import os
import sys
from motor.motor_asyncio import AsyncIOMotorClient
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import json


class MongoToDynamoDBMigrator:
    """Handles migration from MongoDB to DynamoDB"""
    
    def __init__(self, mongo_url: str, aws_region: str = 'us-east-1', table_prefix: str = 'AlertWhisperer'):
        """
        Initialize migrator
        
        Args:
            mongo_url: MongoDB connection URL
            aws_region: AWS region for DynamoDB
            table_prefix: Prefix for DynamoDB table names
        """
        self.mongo_client = AsyncIOMotorClient(mongo_url)
        self.mongo_db = self.mongo_client.get_default_database()
        self.dynamodb = boto3.resource('dynamodb', region_name=aws_region)
        self.dynamodb_client = boto3.client('dynamodb', region_name=aws_region)
        self.table_prefix = table_prefix
        self.aws_region = aws_region
    
    def get_table_schema(self, collection_name: str) -> dict:
        """
        Get DynamoDB table schema for a given collection
        
        Args:
            collection_name: Name of MongoDB collection
            
        Returns:
            Table schema definition
        """
        # Base schema - all tables use 'id' as primary key
        base_schema = {
            'AttributeDefinitions': [
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ],
            'KeySchema': [
                {'AttributeName': 'id', 'KeyType': 'HASH'}
            ],
            'BillingMode': 'PAY_PER_REQUEST',  # On-demand pricing
            'Tags': [
                {'Key': 'Application', 'Value': 'AlertWhisperer'},
                {'Key': 'MigratedFrom', 'Value': 'MongoDB'}
            ]
        }
        
        # Add GSIs (Global Secondary Indexes) for specific collections
        if collection_name == 'alerts':
            base_schema['GlobalSecondaryIndexes'] = [
                {
                    'IndexName': 'company-timestamp-index',
                    'KeySchema': [
                        {'AttributeName': 'company_id', 'KeyType': 'HASH'},
                        {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'}
                },
                {
                    'IndexName': 'status-index',
                    'KeySchema': [
                        {'AttributeName': 'status', 'KeyType': 'HASH'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'}
                }
            ]
            # Add attributes for GSI
            base_schema['AttributeDefinitions'].extend([
                {'AttributeName': 'company_id', 'AttributeType': 'S'},
                {'AttributeName': 'timestamp', 'AttributeType': 'S'},
                {'AttributeName': 'status', 'AttributeType': 'S'}
            ])
        
        elif collection_name == 'incidents':
            base_schema['GlobalSecondaryIndexes'] = [
                {
                    'IndexName': 'company-created-index',
                    'KeySchema': [
                        {'AttributeName': 'company_id', 'KeyType': 'HASH'},
                        {'AttributeName': 'created_at', 'KeyType': 'RANGE'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'}
                },
                {
                    'IndexName': 'status-index',
                    'KeySchema': [
                        {'AttributeName': 'status', 'KeyType': 'HASH'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'}
                }
            ]
            base_schema['AttributeDefinitions'].extend([
                {'AttributeName': 'company_id', 'AttributeType': 'S'},
                {'AttributeName': 'created_at', 'AttributeType': 'S'},
                {'AttributeName': 'status', 'AttributeType': 'S'}
            ])
        
        elif collection_name == 'companies':
            # No additional indexes needed for companies
            pass
        
        return base_schema
    
    async def create_table(self, collection_name: str) -> bool:
        """
        Create DynamoDB table for a MongoDB collection
        
        Args:
            collection_name: Name of MongoDB collection
            
        Returns:
            True if created successfully
        """
        table_name = f"{self.table_prefix}_{collection_name}"
        
        try:
            # Check if table already exists
            existing_tables = self.dynamodb_client.list_tables()['TableNames']
            if table_name in existing_tables:
                print(f"✓ Table {table_name} already exists")
                return True
            
            # Create table
            schema = self.get_table_schema(collection_name)
            schema['TableName'] = table_name
            
            print(f"Creating table {table_name}...")
            self.dynamodb_client.create_table(**schema)
            
            # Wait for table to be created
            waiter = self.dynamodb_client.get_waiter('table_exists')
            waiter.wait(TableName=table_name)
            
            print(f"✓ Table {table_name} created successfully")
            return True
            
        except ClientError as e:
            print(f"✗ Error creating table {table_name}: {e}")
            return False
    
    def convert_document(self, doc: dict) -> dict:
        """
        Convert MongoDB document to DynamoDB item
        
        Args:
            doc: MongoDB document
            
        Returns:
            DynamoDB item
        """
        # Remove MongoDB _id field
        item = {k: v for k, v in doc.items() if k != '_id'}
        
        # Convert datetime objects to ISO strings
        for key, value in list(item.items()):
            if isinstance(value, datetime):
                item[key] = value.isoformat()
            elif isinstance(value, dict):
                item[key] = self.convert_document(value)
            elif value is None:
                # DynamoDB doesn't support null values in certain contexts
                item[key] = ''
        
        return item
    
    async def migrate_collection(self, collection_name: str) -> dict:
        """
        Migrate a single collection from MongoDB to DynamoDB
        
        Args:
            collection_name: Name of collection to migrate
            
        Returns:
            Migration statistics
        """
        print(f"\n{'='*60}")
        print(f"Migrating collection: {collection_name}")
        print(f"{'='*60}")
        
        # Create table
        if not await self.create_table(collection_name):
            return {'error': f'Failed to create table for {collection_name}'}
        
        # Get collection
        collection = self.mongo_db[collection_name]
        table_name = f"{self.table_prefix}_{collection_name}"
        table = self.dynamodb.Table(table_name)
        
        # Count documents
        total_docs = await collection.count_documents({})
        print(f"Found {total_docs} documents to migrate")
        
        if total_docs == 0:
            print("No documents to migrate")
            return {'migrated': 0, 'errors': 0}
        
        # Migrate documents in batches
        migrated_count = 0
        error_count = 0
        batch_size = 25  # DynamoDB batch write limit
        
        cursor = collection.find({})
        batch = []
        
        async for doc in cursor:
            try:
                item = self.convert_document(doc)
                batch.append(item)
                
                # Write batch when it reaches size limit
                if len(batch) >= batch_size:
                    with table.batch_writer() as writer:
                        for item in batch:
                            writer.put_item(Item=item)
                    migrated_count += len(batch)
                    print(f"  Migrated {migrated_count}/{total_docs} documents...", end='\r')
                    batch = []
                    
            except Exception as e:
                print(f"\n  Error migrating document: {e}")
                error_count += 1
        
        # Write remaining documents
        if batch:
            try:
                with table.batch_writer() as writer:
                    for item in batch:
                        writer.put_item(Item=item)
                migrated_count += len(batch)
            except Exception as e:
                print(f"\n  Error migrating final batch: {e}")
                error_count += len(batch)
        
        print(f"\n✓ Migration complete: {migrated_count} documents migrated, {error_count} errors")
        
        return {'migrated': migrated_count, 'errors': error_count, 'total': total_docs}
    
    async def migrate_all(self, collections: list = None) -> dict:
        """
        Migrate all or specified collections
        
        Args:
            collections: List of collection names to migrate. If None, migrates all
            
        Returns:
            Overall migration statistics
        """
        if collections is None:
            # Default collections to migrate
            collections = [
                'companies',
                'users',
                'alerts',
                'incidents',
                'runbooks',
                'notifications',
                'chat_messages',
                'audit_logs',
                'correlation_config',
                'webhook_security_config',
                'rate_limit_config',
                'sla_config',
                'aws_credentials'
            ]
        
        print(f"\n{'#'*60}")
        print("MongoDB to DynamoDB Migration")
        print(f"{'#'*60}")
        print(f"Source: MongoDB")
        print(f"Target: DynamoDB ({self.aws_region})")
        print(f"Table Prefix: {self.table_prefix}")
        print(f"Collections to migrate: {len(collections)}")
        print(f"{'#'*60}\n")
        
        overall_stats = {
            'collections_migrated': 0,
            'total_documents': 0,
            'total_migrated': 0,
            'total_errors': 0,
            'collection_stats': {}
        }
        
        for collection_name in collections:
            try:
                stats = await self.migrate_collection(collection_name)
                overall_stats['collection_stats'][collection_name] = stats
                overall_stats['collections_migrated'] += 1
                overall_stats['total_documents'] += stats.get('total', 0)
                overall_stats['total_migrated'] += stats.get('migrated', 0)
                overall_stats['total_errors'] += stats.get('errors', 0)
            except Exception as e:
                print(f"✗ Failed to migrate {collection_name}: {e}")
                overall_stats['collection_stats'][collection_name] = {'error': str(e)}
        
        # Print summary
        print(f"\n{'='*60}")
        print("MIGRATION SUMMARY")
        print(f"{'='*60}")
        print(f"Collections migrated: {overall_stats['collections_migrated']}/{len(collections)}")
        print(f"Total documents: {overall_stats['total_documents']}")
        print(f"Successfully migrated: {overall_stats['total_migrated']}")
        print(f"Errors: {overall_stats['total_errors']}")
        print(f"{'='*60}\n")
        
        return overall_stats
    
    async def verify_migration(self, collection_name: str) -> dict:
        """
        Verify migration by comparing document counts
        
        Args:
            collection_name: Name of collection to verify
            
        Returns:
            Verification results
        """
        mongo_count = await self.mongo_db[collection_name].count_documents({})
        
        table_name = f"{self.table_prefix}_{collection_name}"
        table = self.dynamodb.Table(table_name)
        
        try:
            response = table.scan(Select='COUNT')
            dynamo_count = response['Count']
        except ClientError as e:
            return {'error': str(e)}
        
        match = mongo_count == dynamo_count
        
        return {
            'collection': collection_name,
            'mongodb_count': mongo_count,
            'dynamodb_count': dynamo_count,
            'match': match
        }
    
    def generate_cloudformation_template(self) -> str:
        """
        Generate CloudFormation template for DynamoDB tables
        
        Returns:
            CloudFormation template as JSON string
        """
        collections = ['companies', 'users', 'alerts', 'incidents', 'runbooks', 
                      'notifications', 'chat_messages', 'audit_logs']
        
        template = {
            'AWSTemplateFormatVersion': '2010-09-09',
            'Description': 'DynamoDB tables for Alert Whisperer',
            'Resources': {}
        }
        
        for collection in collections:
            resource_name = f"{collection.capitalize()}Table"
            table_name = f"{self.table_prefix}_{collection}"
            schema = self.get_table_schema(collection)
            
            template['Resources'][resource_name] = {
                'Type': 'AWS::DynamoDB::Table',
                'Properties': {
                    **schema,
                    'TableName': table_name
                }
            }
        
        return json.dumps(template, indent=2)


async def main():
    """Main migration function"""
    # Get configuration from environment
    mongo_url = os.getenv('MONGO_URL', 'mongodb://localhost:27017/alertwhisperer')
    aws_region = os.getenv('AWS_REGION', 'us-east-1')
    table_prefix = os.getenv('DYNAMODB_TABLE_PREFIX', 'AlertWhisperer')
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        migrator = MongoToDynamoDBMigrator(mongo_url, aws_region, table_prefix)
        
        if command == 'migrate':
            # Migrate all collections
            await migrator.migrate_all()
        
        elif command == 'migrate-collection':
            # Migrate specific collection
            if len(sys.argv) < 3:
                print("Usage: python migrate_to_dynamodb.py migrate-collection <collection_name>")
                return
            collection_name = sys.argv[2]
            await migrator.migrate_collection(collection_name)
        
        elif command == 'verify':
            # Verify migration
            collections = ['companies', 'users', 'alerts', 'incidents']
            print("\nVerifying migration...")
            for collection in collections:
                result = await migrator.verify_migration(collection)
                status = "✓" if result.get('match') else "✗"
                print(f"{status} {collection}: MongoDB={result.get('mongodb_count')}, DynamoDB={result.get('dynamodb_count')}")
        
        elif command == 'cloudformation':
            # Generate CloudFormation template
            template = migrator.generate_cloudformation_template()
            output_file = 'dynamodb_tables.json'
            with open(output_file, 'w') as f:
                f.write(template)
            print(f"CloudFormation template written to {output_file}")
        
        else:
            print(f"Unknown command: {command}")
            print("Available commands: migrate, migrate-collection, verify, cloudformation")
    
    else:
        print("MongoDB to DynamoDB Migration Tool")
        print("\nUsage:")
        print("  python migrate_to_dynamodb.py migrate              # Migrate all collections")
        print("  python migrate_to_dynamodb.py migrate-collection <name>  # Migrate specific collection")
        print("  python migrate_to_dynamodb.py verify               # Verify migration")
        print("  python migrate_to_dynamodb.py cloudformation       # Generate CF template")
        print("\nEnvironment variables:")
        print("  MONGO_URL - MongoDB connection URL")
        print("  AWS_REGION - AWS region for DynamoDB")
        print("  DYNAMODB_TABLE_PREFIX - Prefix for table names")


if __name__ == '__main__':
    asyncio.run(main())
