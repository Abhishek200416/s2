"""
Database Adapter for MongoDB and DynamoDB
This module provides a unified interface to work with both MongoDB and DynamoDB
"""

import os
import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime
import boto3
from botocore.exceptions import ClientError


class DatabaseAdapter(ABC):
    """Abstract base class for database adapters"""
    
    @abstractmethod
    async def insert_one(self, collection: str, document: Dict[str, Any]) -> str:
        """Insert a single document"""
        pass
    
    @abstractmethod
    async def insert_many(self, collection: str, documents: List[Dict[str, Any]]) -> List[str]:
        """Insert multiple documents"""
        pass
    
    @abstractmethod
    async def find_one(self, collection: str, query: Dict[str, Any], projection: Optional[Dict[str, int]] = None) -> Optional[Dict[str, Any]]:
        """Find a single document"""
        pass
    
    @abstractmethod
    async def find(self, collection: str, query: Dict[str, Any], projection: Optional[Dict[str, int]] = None, 
                   sort: Optional[List[tuple]] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Find multiple documents"""
        pass
    
    @abstractmethod
    async def update_one(self, collection: str, query: Dict[str, Any], update: Dict[str, Any]) -> int:
        """Update a single document"""
        pass
    
    @abstractmethod
    async def update_many(self, collection: str, query: Dict[str, Any], update: Dict[str, Any]) -> int:
        """Update multiple documents"""
        pass
    
    @abstractmethod
    async def delete_one(self, collection: str, query: Dict[str, Any]) -> int:
        """Delete a single document"""
        pass
    
    @abstractmethod
    async def delete_many(self, collection: str, query: Dict[str, Any]) -> int:
        """Delete multiple documents"""
        pass
    
    @abstractmethod
    async def count_documents(self, collection: str, query: Dict[str, Any]) -> int:
        """Count documents matching query"""
        pass


class MongoDBAdapter(DatabaseAdapter):
    """MongoDB implementation of DatabaseAdapter"""
    
    def __init__(self, db):
        """
        Initialize with MongoDB database instance
        
        Args:
            db: MongoDB database instance from motor
        """
        self.db = db
    
    async def insert_one(self, collection: str, document: Dict[str, Any]) -> str:
        result = await self.db[collection].insert_one(document)
        return str(result.inserted_id)
    
    async def insert_many(self, collection: str, documents: List[Dict[str, Any]]) -> List[str]:
        result = await self.db[collection].insert_many(documents)
        return [str(id) for id in result.inserted_ids]
    
    async def find_one(self, collection: str, query: Dict[str, Any], projection: Optional[Dict[str, int]] = None) -> Optional[Dict[str, Any]]:
        return await self.db[collection].find_one(query, projection)
    
    async def find(self, collection: str, query: Dict[str, Any], projection: Optional[Dict[str, int]] = None,
                   sort: Optional[List[tuple]] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        cursor = self.db[collection].find(query, projection)
        if sort:
            cursor = cursor.sort(sort)
        if limit:
            cursor = cursor.limit(limit)
        return await cursor.to_list(length=None)
    
    async def update_one(self, collection: str, query: Dict[str, Any], update: Dict[str, Any]) -> int:
        result = await self.db[collection].update_one(query, update)
        return result.modified_count
    
    async def update_many(self, collection: str, query: Dict[str, Any], update: Dict[str, Any]) -> int:
        result = await self.db[collection].update_many(query, update)
        return result.modified_count
    
    async def delete_one(self, collection: str, query: Dict[str, Any]) -> int:
        result = await self.db[collection].delete_one(query)
        return result.deleted_count
    
    async def delete_many(self, collection: str, query: Dict[str, Any]) -> int:
        result = await self.db[collection].delete_many(query)
        return result.deleted_count
    
    async def count_documents(self, collection: str, query: Dict[str, Any]) -> int:
        return await self.db[collection].count_documents(query)


class DynamoDBAdapter(DatabaseAdapter):
    """DynamoDB implementation of DatabaseAdapter"""
    
    def __init__(self, region: str = 'us-east-1', table_prefix: str = 'AlertWhisperer'):
        """
        Initialize DynamoDB adapter
        
        Args:
            region: AWS region
            table_prefix: Prefix for table names
        """
        self.dynamodb = boto3.resource('dynamodb', region_name=region)
        self.table_prefix = table_prefix
        self.tables = {}
    
    def _get_table(self, collection: str):
        """Get or create DynamoDB table reference"""
        table_name = f"{self.table_prefix}_{collection}"
        if table_name not in self.tables:
            self.tables[table_name] = self.dynamodb.Table(table_name)
        return self.tables[table_name]
    
    def _convert_to_dynamodb(self, document: Dict[str, Any]) -> Dict[str, Any]:
        """Convert MongoDB-style document to DynamoDB item"""
        # Remove MongoDB-specific fields
        item = {k: v for k, v in document.items() if k != '_id'}
        
        # Convert datetime objects to ISO strings
        for key, value in item.items():
            if isinstance(value, datetime):
                item[key] = value.isoformat()
            elif isinstance(value, dict):
                item[key] = self._convert_to_dynamodb(value)
        
        return item
    
    def _convert_from_dynamodb(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert DynamoDB item to MongoDB-style document"""
        if not item:
            return None
        # DynamoDB items are already in dict format
        return item
    
    def _build_filter_expression(self, query: Dict[str, Any]):
        """Build DynamoDB filter expression from MongoDB-style query"""
        from boto3.dynamodb.conditions import Attr, And
        
        conditions = []
        for key, value in query.items():
            if isinstance(value, dict):
                # Handle operators like $gt, $lt, etc.
                for op, val in value.items():
                    if op == '$gt':
                        conditions.append(Attr(key).gt(val))
                    elif op == '$gte':
                        conditions.append(Attr(key).gte(val))
                    elif op == '$lt':
                        conditions.append(Attr(key).lt(val))
                    elif op == '$lte':
                        conditions.append(Attr(key).lte(val))
                    elif op == '$ne':
                        conditions.append(Attr(key).ne(val))
                    elif op == '$in':
                        conditions.append(Attr(key).is_in(val))
            else:
                conditions.append(Attr(key).eq(value))
        
        if len(conditions) == 0:
            return None
        elif len(conditions) == 1:
            return conditions[0]
        else:
            return And(*conditions)
    
    async def insert_one(self, collection: str, document: Dict[str, Any]) -> str:
        table = self._get_table(collection)
        item = self._convert_to_dynamodb(document)
        
        try:
            table.put_item(Item=item)
            return item.get('id', '')
        except ClientError as e:
            raise Exception(f"DynamoDB insert_one error: {e}")
    
    async def insert_many(self, collection: str, documents: List[Dict[str, Any]]) -> List[str]:
        table = self._get_table(collection)
        ids = []
        
        with table.batch_writer() as batch:
            for doc in documents:
                item = self._convert_to_dynamodb(doc)
                batch.put_item(Item=item)
                ids.append(item.get('id', ''))
        
        return ids
    
    async def find_one(self, collection: str, query: Dict[str, Any], projection: Optional[Dict[str, int]] = None) -> Optional[Dict[str, Any]]:
        results = await self.find(collection, query, projection, limit=1)
        return results[0] if results else None
    
    async def find(self, collection: str, query: Dict[str, Any], projection: Optional[Dict[str, int]] = None,
                   sort: Optional[List[tuple]] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        table = self._get_table(collection)
        
        # Check if querying by primary key
        if 'id' in query and len(query) == 1:
            try:
                response = table.get_item(Key={'id': query['id']})
                item = response.get('Item')
                return [self._convert_from_dynamodb(item)] if item else []
            except ClientError:
                return []
        
        # Otherwise scan with filter
        filter_expression = self._build_filter_expression(query)
        
        scan_kwargs = {}
        if filter_expression:
            scan_kwargs['FilterExpression'] = filter_expression
        if limit:
            scan_kwargs['Limit'] = limit
        
        try:
            response = table.scan(**scan_kwargs)
            items = [self._convert_from_dynamodb(item) for item in response.get('Items', [])]
            
            # Handle sorting (in-memory since DynamoDB scan doesn't support sort)
            if sort:
                for field, direction in reversed(sort):
                    items.sort(key=lambda x: x.get(field, ''), reverse=(direction == -1))
            
            return items
        except ClientError as e:
            raise Exception(f"DynamoDB find error: {e}")
    
    async def update_one(self, collection: str, query: Dict[str, Any], update: Dict[str, Any]) -> int:
        table = self._get_table(collection)
        
        # Find the item first
        items = await self.find(collection, query, limit=1)
        if not items:
            return 0
        
        item = items[0]
        key = {'id': item['id']}
        
        # Handle $set operator
        update_data = update.get('$set', update)
        
        # Build update expression
        update_expression = 'SET ' + ', '.join([f'#{k} = :{k}' for k in update_data.keys()])
        expression_attribute_names = {f'#{k}': k for k in update_data.keys()}
        expression_attribute_values = {f':{k}': v for k, v in update_data.items()}
        
        try:
            table.update_item(
                Key=key,
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values
            )
            return 1
        except ClientError as e:
            raise Exception(f"DynamoDB update_one error: {e}")
    
    async def update_many(self, collection: str, query: Dict[str, Any], update: Dict[str, Any]) -> int:
        # Find all matching items
        items = await self.find(collection, query)
        
        count = 0
        for item in items:
            result = await self.update_one(collection, {'id': item['id']}, update)
            count += result
        
        return count
    
    async def delete_one(self, collection: str, query: Dict[str, Any]) -> int:
        items = await self.find(collection, query, limit=1)
        if not items:
            return 0
        
        table = self._get_table(collection)
        key = {'id': items[0]['id']}
        
        try:
            table.delete_item(Key=key)
            return 1
        except ClientError as e:
            raise Exception(f"DynamoDB delete_one error: {e}")
    
    async def delete_many(self, collection: str, query: Dict[str, Any]) -> int:
        items = await self.find(collection, query)
        
        table = self._get_table(collection)
        count = 0
        
        with table.batch_writer() as batch:
            for item in items:
                batch.delete_item(Key={'id': item['id']})
                count += 1
        
        return count
    
    async def count_documents(self, collection: str, query: Dict[str, Any]) -> int:
        items = await self.find(collection, query)
        return len(items)


def get_database_adapter(db_type: str = None, **kwargs) -> DatabaseAdapter:
    """
    Factory function to get the appropriate database adapter
    
    Args:
        db_type: Type of database ('mongodb' or 'dynamodb'). If None, reads from env
        **kwargs: Additional arguments for adapter initialization
    
    Returns:
        DatabaseAdapter instance
    """
    if db_type is None:
        db_type = os.getenv('DATABASE_TYPE', 'mongodb').lower()
    
    if db_type == 'mongodb':
        # Expects 'db' parameter with MongoDB database instance
        db = kwargs.get('db')
        if not db:
            raise ValueError("MongoDB adapter requires 'db' parameter")
        return MongoDBAdapter(db)
    
    elif db_type == 'dynamodb':
        region = kwargs.get('region', os.getenv('AWS_REGION', 'us-east-1'))
        table_prefix = kwargs.get('table_prefix', os.getenv('DYNAMODB_TABLE_PREFIX', 'AlertWhisperer'))
        return DynamoDBAdapter(region=region, table_prefix=table_prefix)
    
    else:
        raise ValueError(f"Unsupported database type: {db_type}")
