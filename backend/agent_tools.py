"""Agent Tool Interfaces - Clean JSON-schema I/O for agent core"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError
import os

# ============= Tool Schemas =============

class SSMExecuteInput(BaseModel):
    """Input for SSM execution tool"""
    commands: List[str]
    instance_ids: List[str]
    runbook_id: Optional[str] = None
    timeout_seconds: int = 300

class SSMExecuteOutput(BaseModel):
    """Output from SSM execution"""
    command_id: str
    status: str  # InProgress, Success, Failed
    instance_ids: List[str]
    output: Optional[str] = None
    error: Optional[str] = None

class CloudWatchGetAlarmInput(BaseModel):
    """Input for CloudWatch get alarm"""
    alarm_name: str

class CloudWatchGetAlarmOutput(BaseModel):
    """Output from CloudWatch alarm"""
    alarm_name: str
    state: str  # OK, ALARM, INSUFFICIENT_DATA
    reason: str
    timestamp: str

class CloudWatchQueryMetricsInput(BaseModel):
    """Input for CloudWatch metrics query"""
    namespace: str
    metric_name: str
    dimensions: List[Dict[str, str]]
    start_time: str
    end_time: str
    period: int = 300

class CloudWatchQueryMetricsOutput(BaseModel):
    """Output from CloudWatch metrics"""
    datapoints: List[Dict[str, Any]]
    label: str

class ApprovalRequestInput(BaseModel):
    """Input for approval request"""
    runbook_id: str
    risk_level: str  # low, medium, high
    reason: str
    requester_id: str

class ApprovalRequestOutput(BaseModel):
    """Output from approval request"""
    approval_id: str
    status: str  # pending, approved, rejected
    expires_at: str

class ApprovalStatusInput(BaseModel):
    """Input for approval status check"""
    approval_id: str

class ApprovalStatusOutput(BaseModel):
    """Output from approval status"""
    approval_id: str
    status: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None

class KPISnapshotOutput(BaseModel):
    """Output from KPI snapshot"""
    timestamp: str
    noise_reduction_pct: float
    mttr_minutes: float
    self_healed_pct: float
    patch_compliance_pct: float
    alert_count: int
    incident_count: int

# ============= Tool Registry =============

class AgentToolRegistry:
    """Registry of tools the agent can call"""
    
    def __init__(self, db):
        self.db = db
        self.ssm_client = None
        self.cloudwatch_client = None
        
        # Initialize AWS clients if credentials available
        try:
            self.ssm_client = boto3.client('ssm')
            self.cloudwatch_client = boto3.client('cloudwatch')
        except Exception:
            pass  # Will use mock mode
    
    async def execute_ssm(self, input: SSMExecuteInput) -> SSMExecuteOutput:
        """Execute commands via AWS Systems Manager"""
        try:
            if self.ssm_client:
                # Real AWS SSM execution
                response = self.ssm_client.send_command(
                    InstanceIds=input.instance_ids,
                    DocumentName='AWS-RunShellScript',
                    Parameters={'commands': input.commands},
                    TimeoutSeconds=input.timeout_seconds
                )
                
                command_id = response['Command']['CommandId']
                
                return SSMExecuteOutput(
                    command_id=command_id,
                    status="InProgress",
                    instance_ids=input.instance_ids,
                    output=None
                )
            else:
                # Mock mode
                import uuid
                command_id = f"cmd-{uuid.uuid4().hex[:16]}"
                
                # Store in database for tracking
                await self.db["ssm_executions"].insert_one({
                    "command_id": command_id,
                    "instance_ids": input.instance_ids,
                    "commands": input.commands,
                    "status": "InProgress",
                    "created_at": datetime.now(timezone.utc),
                    "mock": True
                })
                
                return SSMExecuteOutput(
                    command_id=command_id,
                    status="InProgress",
                    instance_ids=input.instance_ids,
                    output="Mock execution started"
                )
        except ClientError as e:
            return SSMExecuteOutput(
                command_id="",
                status="Failed",
                instance_ids=input.instance_ids,
                error=str(e)
            )
    
    async def get_cloudwatch_alarm(self, input: CloudWatchGetAlarmInput) -> CloudWatchGetAlarmOutput:
        """Get CloudWatch alarm state"""
        try:
            if self.cloudwatch_client:
                response = self.cloudwatch_client.describe_alarms(
                    AlarmNames=[input.alarm_name]
                )
                
                if response['MetricAlarms']:
                    alarm = response['MetricAlarms'][0]
                    return CloudWatchGetAlarmOutput(
                        alarm_name=alarm['AlarmName'],
                        state=alarm['StateValue'],
                        reason=alarm['StateReason'],
                        timestamp=alarm['StateUpdatedTimestamp'].isoformat()
                    )
            
            # Mock mode
            return CloudWatchGetAlarmOutput(
                alarm_name=input.alarm_name,
                state="ALARM",
                reason="Mock alarm state",
                timestamp=datetime.now(timezone.utc).isoformat()
            )
        except Exception as e:
            return CloudWatchGetAlarmOutput(
                alarm_name=input.alarm_name,
                state="INSUFFICIENT_DATA",
                reason=str(e),
                timestamp=datetime.now(timezone.utc).isoformat()
            )
    
    async def query_cloudwatch_metrics(self, input: CloudWatchQueryMetricsInput) -> CloudWatchQueryMetricsOutput:
        """Query CloudWatch metrics"""
        try:
            if self.cloudwatch_client:
                from datetime import datetime
                response = self.cloudwatch_client.get_metric_statistics(
                    Namespace=input.namespace,
                    MetricName=input.metric_name,
                    Dimensions=input.dimensions,
                    StartTime=datetime.fromisoformat(input.start_time),
                    EndTime=datetime.fromisoformat(input.end_time),
                    Period=input.period,
                    Statistics=['Average', 'Sum', 'Maximum']
                )
                
                return CloudWatchQueryMetricsOutput(
                    datapoints=response['Datapoints'],
                    label=input.metric_name
                )
            
            # Mock mode
            return CloudWatchQueryMetricsOutput(
                datapoints=[
                    {"Timestamp": datetime.now(timezone.utc).isoformat(), "Average": 50.0}
                ],
                label=input.metric_name
            )
        except Exception:
            return CloudWatchQueryMetricsOutput(datapoints=[], label=input.metric_name)
    
    async def request_approval(self, input: ApprovalRequestInput) -> ApprovalRequestOutput:
        """Request approval for runbook execution"""
        from datetime import timedelta
        import uuid
        
        approval_id = f"apr-{uuid.uuid4().hex[:12]}"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        approval_doc = {
            "approval_id": approval_id,
            "runbook_id": input.runbook_id,
            "risk_level": input.risk_level,
            "reason": input.reason,
            "requester_id": input.requester_id,
            "status": "pending",
            "expires_at": expires_at,
            "created_at": datetime.now(timezone.utc)
        }
        
        await self.db["approval_requests"].insert_one(approval_doc)
        
        return ApprovalRequestOutput(
            approval_id=approval_id,
            status="pending",
            expires_at=expires_at.isoformat()
        )
    
    async def get_approval_status(self, input: ApprovalStatusInput) -> ApprovalStatusOutput:
        """Check approval status"""
        approval = await self.db["approval_requests"].find_one({
            "approval_id": input.approval_id
        })
        
        if not approval:
            return ApprovalStatusOutput(
                approval_id=input.approval_id,
                status="not_found"
            )
        
        return ApprovalStatusOutput(
            approval_id=input.approval_id,
            status=approval["status"],
            approved_by=approval.get("approved_by"),
            approved_at=approval.get("approved_at")
        )
    
    async def get_kpi_snapshot(self, company_id: Optional[str] = None) -> KPISnapshotOutput:
        """Get current KPI snapshot for impact tracking"""
        # Query alerts and incidents
        alert_filter = {"company_id": company_id} if company_id else {}
        incident_filter = {"company_id": company_id} if company_id else {}
        
        alert_count = await self.db["alerts"].count_documents(alert_filter)
        incident_count = await self.db["incidents"].count_documents(incident_filter)
        
        # Calculate KPIs
        noise_reduction = ((1 - (incident_count / max(alert_count, 1))) * 100) if alert_count > 0 else 0
        
        # Get average MTTR
        incidents = await self.db["incidents"].find(
            {**incident_filter, "status": "resolved"}
        ).limit(100).to_list(length=100)
        
        total_mttr = 0
        mttr_count = 0
        for inc in incidents:
            if inc.get("resolved_at") and inc.get("created_at"):
                from dateutil import parser
                created = parser.parse(inc["created_at"])
                resolved = parser.parse(inc["resolved_at"])
                mttr_minutes = (resolved - created).total_seconds() / 60
                total_mttr += mttr_minutes
                mttr_count += 1
        
        avg_mttr = total_mttr / max(mttr_count, 1) if mttr_count > 0 else 0
        
        # Self-healed percentage
        auto_resolved = await self.db["incidents"].count_documents({
            **incident_filter,
            "auto_remediated": True
        })
        self_healed_pct = (auto_resolved / max(incident_count, 1)) * 100 if incident_count > 0 else 0
        
        # Patch compliance (mock)
        patch_compliance_pct = 95.0
        
        return KPISnapshotOutput(
            timestamp=datetime.now(timezone.utc).isoformat(),
            noise_reduction_pct=round(noise_reduction, 2),
            mttr_minutes=round(avg_mttr, 2),
            self_healed_pct=round(self_healed_pct, 2),
            patch_compliance_pct=patch_compliance_pct,
            alert_count=alert_count,
            incident_count=incident_count
        )
    
    def get_tool_schema(self) -> Dict[str, Any]:
        """Get JSON schema for all available tools"""
        return {
            "ssm.execute": {
                "description": "Execute commands on EC2 instances via AWS Systems Manager",
                "input_schema": SSMExecuteInput.model_json_schema(),
                "output_schema": SSMExecuteOutput.model_json_schema()
            },
            "cloudwatch.get_alarm": {
                "description": "Get CloudWatch alarm state",
                "input_schema": CloudWatchGetAlarmInput.model_json_schema(),
                "output_schema": CloudWatchGetAlarmOutput.model_json_schema()
            },
            "cloudwatch.query_metrics": {
                "description": "Query CloudWatch metrics",
                "input_schema": CloudWatchQueryMetricsInput.model_json_schema(),
                "output_schema": CloudWatchQueryMetricsOutput.model_json_schema()
            },
            "approvals.request": {
                "description": "Request approval for runbook execution",
                "input_schema": ApprovalRequestInput.model_json_schema(),
                "output_schema": ApprovalRequestOutput.model_json_schema()
            },
            "approvals.status": {
                "description": "Check approval status",
                "input_schema": ApprovalStatusInput.model_json_schema(),
                "output_schema": ApprovalStatusOutput.model_json_schema()
            },
            "kpi.snapshot": {
                "description": "Get current KPI snapshot for before/after impact tracking",
                "input_schema": {},
                "output_schema": KPISnapshotOutput.model_json_schema()
            }
        }
