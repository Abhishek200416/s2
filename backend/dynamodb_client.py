"""
DynamoDB Client and Helper Functions for Alert Whisperer
Replaces MongoDB with AWS DynamoDB
"""

import boto3
import os
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from decimal import Decimal
import json
from botocore.exceptions import ClientError

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# DynamoDB Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_SESSION_TOKEN = os.environ.get('AWS_SESSION_TOKEN')
TABLE_PREFIX = os.environ.get('DYNAMODB_TABLE_PREFIX', 'AlertWhisperer_')

# Initialize DynamoDB client and resource with session token support
client_params = {
    'region_name': AWS_REGION,
    'aws_access_key_id': AWS_ACCESS_KEY_ID,
    'aws_secret_access_key': AWS_SECRET_ACCESS_KEY
}
if AWS_SESSION_TOKEN:
    client_params['aws_session_token'] = AWS_SESSION_TOKEN

dynamodb_client = boto3.client('dynamodb', **client_params)
dynamodb_resource = boto3.resource('dynamodb', **client_params)

# Table References
class DynamoDBTables:
    """DynamoDB table references"""
    
    @staticmethod
    def users():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}Users')
    
    @staticmethod
    def companies():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}Companies')
    
    @staticmethod
    def alerts():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}Alerts')
    
    @staticmethod
    def incidents():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}Incidents')
    
    @staticmethod
    def audit_logs():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}AuditLogs')
    
    @staticmethod
    def notifications():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}Notifications')
    
    @staticmethod
    def chat_messages():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}ChatMessages')
    
    @staticmethod
    def oncall_schedules():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}OnCallSchedules')
    
    @staticmethod
    def runbooks():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}Runbooks')
    
    @staticmethod
    def approval_requests():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}ApprovalRequests')
    
    @staticmethod
    def company_configs():
        return dynamodb_resource.Table(f'{TABLE_PREFIX}CompanyConfigs')


# Helper Functions
def convert_to_dynamodb_format(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert Python dict to DynamoDB format
    - Converts floats to Decimal (required by DynamoDB)
    - Converts datetime to ISO string
    - Converts lists and nested dicts recursively
    """
    if isinstance(data, dict):
        return {k: convert_to_dynamodb_format(v) for k, v in data.items() if v is not None}
    elif isinstance(data, list):
        return [convert_to_dynamodb_format(item) for item in data]
    elif isinstance(data, float):
        return Decimal(str(data))
    elif isinstance(data, datetime):
        return data.isoformat()
    else:
        return data


def convert_from_dynamodb_format(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert DynamoDB format to Python dict
    - Converts Decimal to float
    - Keeps other types as-is
    """
    if isinstance(data, dict):
        return {k: convert_from_dynamodb_format(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_from_dynamodb_format(item) for item in data]
    elif isinstance(data, Decimal):
        return float(data)
    else:
        return data


def serialize_json_fields(item: Dict[str, Any], json_fields: List[str]) -> Dict[str, Any]:
    """
    Serialize specified fields to JSON strings before storing in DynamoDB
    DynamoDB doesn't support complex nested structures, so we store them as JSON strings
    """
    result = item.copy()
    for field in json_fields:
        if field in result and result[field] is not None:
            if isinstance(result[field], (dict, list)):
                result[field] = json.dumps(result[field])
    return result


def deserialize_json_fields(item: Dict[str, Any], json_fields: List[str]) -> Dict[str, Any]:
    """
    Deserialize JSON string fields back to Python objects
    """
    result = item.copy()
    for field in json_fields:
        if field in result and result[field] is not None:
            if isinstance(result[field], str):
                try:
                    result[field] = json.loads(result[field])
                except:
                    pass  # Keep as string if not valid JSON
    return result


# CRUD Operations

async def insert_one(table, item: Dict[str, Any], json_fields: List[str] = []) -> Dict[str, Any]:
    """
    Insert a single item into DynamoDB table
    """
    try:
        # Serialize JSON fields
        item = serialize_json_fields(item, json_fields)
        
        # Convert to DynamoDB format
        item = convert_to_dynamodb_format(item)
        
        # Put item
        table.put_item(Item=item)
        
        return item
    except ClientError as e:
        print(f"Error inserting item: {e}")
        raise


async def find_one(table, key: Dict[str, Any], json_fields: List[str] = []) -> Optional[Dict[str, Any]]:
    """
    Find a single item by primary key
    """
    try:
        response = table.get_item(Key=key)
        
        if 'Item' in response:
            item = convert_from_dynamodb_format(response['Item'])
            item = deserialize_json_fields(item, json_fields)
            return item
        return None
    except ClientError as e:
        print(f"Error finding item: {e}")
        return None


async def find_many(table, filter_expression=None, expression_values=None, 
                    index_name: Optional[str] = None, json_fields: List[str] = [],
                    limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Find multiple items using scan or query
    For better performance, use query with index_name when possible
    """
    try:
        scan_kwargs = {}
        
        if filter_expression:
            scan_kwargs['FilterExpression'] = filter_expression
        
        if expression_values:
            scan_kwargs['ExpressionAttributeValues'] = expression_values
        
        if index_name:
            scan_kwargs['IndexName'] = index_name
        
        if limit:
            scan_kwargs['Limit'] = limit
        
        response = table.scan(**scan_kwargs)
        items = response.get('Items', [])
        
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = table.scan(**scan_kwargs)
            items.extend(response.get('Items', []))
        
        # Convert and deserialize
        result = []
        for item in items:
            item = convert_from_dynamodb_format(item)
            item = deserialize_json_fields(item, json_fields)
            result.append(item)
        
        return result
    except ClientError as e:
        print(f"Error finding items: {e}")
        return []


async def query_items(table, key_condition_expression, expression_values,
                      filter_expression=None, index_name: Optional[str] = None,
                      json_fields: List[str] = [], limit: Optional[int] = None,
                      scan_forward: bool = True) -> List[Dict[str, Any]]:
    """
    Query items (more efficient than scan)
    Use this when you know the partition key
    """
    try:
        query_kwargs = {
            'KeyConditionExpression': key_condition_expression,
            'ExpressionAttributeValues': expression_values,
            'ScanIndexForward': scan_forward  # False for descending order
        }
        
        if filter_expression:
            query_kwargs['FilterExpression'] = filter_expression
        
        if index_name:
            query_kwargs['IndexName'] = index_name
        
        if limit:
            query_kwargs['Limit'] = limit
        
        response = table.query(**query_kwargs)
        items = response.get('Items', [])
        
        # Handle pagination
        while 'LastEvaluatedKey' in response and (not limit or len(items) < limit):
            query_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = table.query(**query_kwargs)
            items.extend(response.get('Items', []))
        
        # Convert and deserialize
        result = []
        for item in items:
            item = convert_from_dynamodb_format(item)
            item = deserialize_json_fields(item, json_fields)
            result.append(item)
        
        return result
    except ClientError as e:
        print(f"Error querying items: {e}")
        return []


async def update_one(table, key: Dict[str, Any], updates: Dict[str, Any],
                     json_fields: List[str] = []) -> Optional[Dict[str, Any]]:
    """
    Update a single item
    """
    try:
        # Serialize JSON fields
        updates = serialize_json_fields(updates, json_fields)
        
        # Convert to DynamoDB format
        updates = convert_to_dynamodb_format(updates)
        
        # Build update expression
        update_expr = "SET " + ", ".join([f"#{k} = :{k}" for k in updates.keys()])
        expr_attr_names = {f"#{k}": k for k in updates.keys()}
        expr_attr_values = {f":{k}": v for k, v in updates.items()}
        
        response = table.update_item(
            Key=key,
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_attr_names,
            ExpressionAttributeValues=expr_attr_values,
            ReturnValues="ALL_NEW"
        )
        
        if 'Attributes' in response:
            item = convert_from_dynamodb_format(response['Attributes'])
            item = deserialize_json_fields(item, json_fields)
            return item
        return None
    except ClientError as e:
        print(f"Error updating item: {e}")
        return None


async def delete_one(table, key: Dict[str, Any]) -> bool:
    """
    Delete a single item
    """
    try:
        table.delete_item(Key=key)
        return True
    except ClientError as e:
        print(f"Error deleting item: {e}")
        return False


async def count_items(table, filter_expression=None, expression_values=None) -> int:
    """
    Count items in table
    """
    try:
        scan_kwargs = {'Select': 'COUNT'}
        
        if filter_expression:
            scan_kwargs['FilterExpression'] = filter_expression
        
        if expression_values:
            scan_kwargs['ExpressionAttributeValues'] = expression_values
        
        response = table.scan(**scan_kwargs)
        count = response.get('Count', 0)
        
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = table.scan(**scan_kwargs)
            count += response.get('Count', 0)
        
        return count
    except ClientError as e:
        print(f"Error counting items: {e}")
        return 0


# Database initialization check
async def check_dynamodb_connection() -> bool:
    """
    Check if DynamoDB connection is working
    """
    try:
        table = DynamoDBTables.users()
        table.load()
        print(f"✅ DynamoDB connection successful! Table: {table.name}")
        return True
    except Exception as e:
        print(f"❌ DynamoDB connection failed: {e}")
        return False


# Export main objects
db = DynamoDBTables()
