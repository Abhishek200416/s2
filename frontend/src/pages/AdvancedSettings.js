import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, Clock, Settings, Copy, Check, AlertTriangle, RefreshCw, Power, PowerOff, Activity, UserCheck, Clipboard } from 'lucide-react';
import { toast } from 'sonner';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import RateLimitSettings from './RateLimitSettings';
import RBACSettings from './RBACSettings';
import ApprovalGates from './ApprovalGates';

const AdvancedSettings = ({ companyId, companyName }) => {
  const [webhookSecurity, setWebhookSecurity] = useState(null);
  const [correlationConfig, setCorrelationConfig] = useState(null);
  const [crossAccountRole, setCrossAccountRole] = useState(null);
  const [crossAccountTemplate, setCrossAccountTemplate] = useState(null);
  const [roleArn, setRoleArn] = useState('');
  const [awsAccountId, setAwsAccountId] = useState('');
  const [loading, setLoading] = useState(true);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedItem, setCopiedItem] = useState(null);

  useEffect(() => {
    if (companyId) {
      loadSettings();
    }
  }, [companyId]);

  const loadSettings = async () => {
    try {
      const [securityRes, correlationRes] = await Promise.all([
        api.get(`/companies/${companyId}/webhook-security`),
        api.get(`/companies/${companyId}/correlation-config`)
      ]);
      setWebhookSecurity(securityRes.data);
      setCorrelationConfig(correlationRes.data);
    } catch (error) {
      console.error('Failed to load settings:', error);
      toast.error('Failed to load advanced settings');
    } finally {
      setLoading(false);
    }
  };

  const handleEnableHMAC = async () => {
    try {
      const response = await api.post(`/companies/${companyId}/webhook-security/enable`);
      setWebhookSecurity(response.data);
      toast.success('HMAC webhook security enabled');
    } catch (error) {
      toast.error('Failed to enable webhook security');
    }
  };

  const handleDisableHMAC = async () => {
    if (!window.confirm('Are you sure you want to disable HMAC security? Webhooks will only require API key authentication.')) {
      return;
    }
    try {
      await api.post(`/companies/${companyId}/webhook-security/disable`);
      setWebhookSecurity({ ...webhookSecurity, enabled: false });
      toast.success('HMAC webhook security disabled');
    } catch (error) {
      toast.error('Failed to disable webhook security');
    }
  };

  const handleRegenerateSecret = async () => {
    if (!window.confirm('Are you sure you want to regenerate the HMAC secret? This will invalidate the current secret and break existing integrations.')) {
      return;
    }
    try {
      const response = await api.post(`/companies/${companyId}/webhook-security/regenerate-secret`);
      setWebhookSecurity(response.data);
      toast.success('HMAC secret regenerated successfully');
    } catch (error) {
      toast.error('Failed to regenerate HMAC secret');
    }
  };

  const handleCopySecret = async () => {
    try {
      await navigator.clipboard.writeText(webhookSecurity.hmac_secret);
      setCopiedSecret(true);
      toast.success('HMAC secret copied to clipboard');
      setTimeout(() => setCopiedSecret(false), 2000);
    } catch (error) {
      toast.error('Failed to copy secret');
    }
  };

  const handleUpdateCorrelation = async (updates) => {
    try {
      const response = await api.put(`/companies/${companyId}/correlation-config`, updates);
      setCorrelationConfig(response.data);
      toast.success('Correlation settings updated');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to update correlation settings');
    }
  };

  const loadCrossAccountTemplate = async () => {
    try {
      const response = await api.get(`/companies/${companyId}/cross-account-role/template`);
      setCrossAccountTemplate(response.data);
    } catch (error) {
      console.error('Failed to load cross-account template:', error);
    }
  };

  const loadCrossAccountRole = async () => {
    try {
      const response = await api.get(`/companies/${companyId}/cross-account-role`);
      setCrossAccountRole(response.data);
      setRoleArn(response.data.role_arn);
      setAwsAccountId(response.data.aws_account_id);
    } catch (error) {
      // Role not configured yet, load template
      loadCrossAccountTemplate();
    }
  };

  const saveCrossAccountRole = async () => {
    try {
      const response = await api.post(`/companies/${companyId}/cross-account-role`, {
        role_arn: roleArn,
        external_id: crossAccountTemplate.external_id,
        aws_account_id: awsAccountId
      });
      setCrossAccountRole(response.data);
      toast.success('Cross-account role saved successfully');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to save cross-account role');
    }
  };

  const copyToClipboard = (text, item) => {
    navigator.clipboard.writeText(text);
    setCopiedItem(item);
    setTimeout(() => setCopiedItem(null), 2000);
    toast.success('Copied to clipboard');
  };

  useEffect(() => {
    if (companyId) {
      loadCrossAccountRole();
    }
  }, [companyId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-slate-950">
        <div className="text-cyan-400 text-xl">Loading advanced settings...</div>
      </div>
    );
  }

  const backendUrl = process.env.REACT_APP_BACKEND_URL || window.location.origin;

  return (
    <div className="min-h-screen bg-slate-950 py-8">
      <div className="max-w-7xl mx-auto px-6">
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-white mb-3">Advanced Security & Configuration</h1>
          <p className="text-lg text-slate-300 mb-2">Production-grade settings for {companyName}</p>
          <p className="text-slate-400">HMAC webhook authentication, event-driven correlation, and AWS integration patterns</p>
        </div>

        <Tabs defaultValue="webhook-security" className="space-y-6">
          <TabsList className="bg-slate-900/50 border border-slate-800">
            <TabsTrigger 
              value="webhook-security"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Shield className="w-4 h-4 mr-2" />
              Webhook Security
            </TabsTrigger>
            <TabsTrigger 
              value="correlation"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Clock className="w-4 h-4 mr-2" />
              Correlation
            </TabsTrigger>
            <TabsTrigger 
              value="rate-limiting"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Activity className="w-4 h-4 mr-2" />
              Rate Limiting
            </TabsTrigger>
            <TabsTrigger 
              value="approval-gates"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Clipboard className="w-4 h-4 mr-2" />
              Approval Gates
            </TabsTrigger>
            <TabsTrigger 
              value="rbac-audit"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <UserCheck className="w-4 h-4 mr-2" />
              RBAC & Audit
            </TabsTrigger>
            <TabsTrigger 
              value="aws-integration"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Settings className="w-4 h-4 mr-2" />
              AWS Integration
            </TabsTrigger>
            <TabsTrigger 
              value="cross-account"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Shield className="w-4 h-4 mr-2" />
              Cross-Account IAM
            </TabsTrigger>
          </TabsList>

          {/* Webhook Security Tab */}
          <TabsContent value="webhook-security">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-cyan-400" />
                  HMAC-SHA256 Webhook Authentication
                </CardTitle>
                <CardDescription className="text-slate-300">
                  Add cryptographic signature verification to webhooks for enhanced security and replay attack protection
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Status Card */}
                <div className={`p-4 rounded-lg border ${webhookSecurity?.enabled ? 'bg-green-500/10 border-green-500/30' : 'bg-slate-800/50 border-slate-700'}`}>
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-white font-semibold flex items-center gap-2">
                        {webhookSecurity?.enabled ? <Check className="w-5 h-5 text-green-400" /> : <AlertTriangle className="w-5 h-5 text-amber-400" />}
                        HMAC Security Status
                      </h3>
                      <p className="text-sm text-slate-300 mt-1">
                        {webhookSecurity?.enabled ? 'Enabled - All webhooks require HMAC signature' : 'Disabled - Webhooks use API key only'}
                      </p>
                    </div>
                    {webhookSecurity?.enabled ? (
                      <Button 
                        onClick={handleDisableHMAC}
                        variant="outline"
                        className="bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20"
                      >
                        <PowerOff className="w-4 h-4 mr-2" />
                        Disable HMAC
                      </Button>
                    ) : (
                      <Button 
                        onClick={handleEnableHMAC}
                        className="bg-green-500/20 border-green-500/30 text-green-400 hover:bg-green-500/30"
                      >
                        <Power className="w-4 h-4 mr-2" />
                        Enable HMAC
                      </Button>
                    )}
                  </div>
                </div>

                {webhookSecurity?.enabled && (
                  <>
                    {/* HMAC Secret */}
                    <div className="space-y-3">
                      <Label className="text-white">HMAC Secret Key</Label>
                      <div className="flex gap-2">
                        <Input
                          type="password"
                          value={webhookSecurity.hmac_secret}
                          readOnly
                          className="bg-slate-800 border-slate-700 text-white font-mono"
                        />
                        <Button
                          onClick={handleCopySecret}
                          variant="outline"
                          className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700"
                        >
                          {copiedSecret ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                        </Button>
                        <Button
                          onClick={handleRegenerateSecret}
                          variant="outline"
                          className="bg-orange-500/10 border-orange-500/30 text-orange-400 hover:bg-orange-500/20"
                        >
                          <RefreshCw className="w-4 h-4" />
                        </Button>
                      </div>
                      <p className="text-sm text-slate-400">
                        Store this secret securely. Use it to sign webhook payloads.
                      </p>
                    </div>

                    {/* Configuration Details */}
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label className="text-white">Signature Header</Label>
                        <Input
                          value={webhookSecurity.signature_header}
                          readOnly
                          className="bg-slate-800 border-slate-700 text-slate-300"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-white">Timestamp Header</Label>
                        <Input
                          value={webhookSecurity.timestamp_header}
                          readOnly
                          className="bg-slate-800 border-slate-700 text-slate-300"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-white">Replay Protection Window</Label>
                        <Input
                          value={`${webhookSecurity.max_timestamp_diff_seconds} seconds (${webhookSecurity.max_timestamp_diff_seconds / 60} minutes)`}
                          readOnly
                          className="bg-slate-800 border-slate-700 text-slate-300"
                        />
                      </div>
                    </div>

                    {/* Implementation Example */}
                    <div className="space-y-3">
                      <h3 className="text-white font-semibold">Implementation Example (Python)</h3>
                      <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 overflow-x-auto">
                        <code className="text-sm text-slate-300">
{`import hmac
import hashlib
import time
import requests
import json

# Your webhook payload
alert_data = {
    "asset_name": "web-server-01",
    "signature": "high_cpu_usage",
    "severity": "critical",
    "message": "CPU usage above 90%",
    "tool_source": "Datadog"
}

# Convert to JSON string
body = json.dumps(alert_data)

# Generate timestamp
timestamp = str(int(time.time()))

# Compute HMAC signature
message = f"{timestamp}.{body}"
signature = hmac.new(
    "${webhookSecurity.hmac_secret}".encode('utf-8'),
    message.encode('utf-8'),
    hashlib.sha256
).hexdigest()

# Send webhook with headers
response = requests.post(
    "${backendUrl}/api/webhooks/alerts?api_key=YOUR_API_KEY",
    headers={
        "Content-Type": "application/json",
        "${webhookSecurity.signature_header}": f"sha256={signature}",
        "${webhookSecurity.timestamp_header}": timestamp
    },
    data=body
)

print(response.json())`}
                        </code>
                      </pre>
                    </div>
                  </>
                )}

                {!webhookSecurity?.enabled && (
                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4">
                    <div className="flex gap-3">
                      <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <h4 className="text-amber-400 font-semibold">Enhanced Security Available</h4>
                        <p className="text-sm text-slate-300 mt-1">
                          Enable HMAC authentication to add cryptographic signature verification to your webhooks. 
                          This prevents unauthorized requests and replay attacks.
                        </p>
                        <ul className="text-sm text-slate-400 mt-2 space-y-1 list-disc list-inside">
                          <li>Prevents spoofed webhook requests</li>
                          <li>5-minute replay protection window</li>
                          <li>Constant-time signature comparison</li>
                          <li>No additional latency</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Correlation Settings Tab */}
          <TabsContent value="correlation">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Clock className="w-5 h-5 text-cyan-400" />
                  Event Correlation Configuration (NOT AI)
                </CardTitle>
                <CardDescription className="text-slate-300">
                  Rule-based alert grouping with configurable time windows. Similar to Datadog Event Aggregation and PagerDuty Alert Grouping.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Time Window Slider */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <Label className="text-white font-semibold">Correlation Time Window</Label>
                    <span className="text-2xl font-bold text-cyan-400">{correlationConfig.time_window_minutes} min</span>
                  </div>
                  <input
                    type="range"
                    min="5"
                    max="15"
                    value={correlationConfig.time_window_minutes}
                    onChange={(e) => {
                      const newValue = parseInt(e.target.value);
                      setCorrelationConfig({ ...correlationConfig, time_window_minutes: newValue });
                    }}
                    onMouseUp={(e) => {
                      const newValue = parseInt(e.target.value);
                      handleUpdateCorrelation({ time_window_minutes: newValue });
                    }}
                    className="w-full h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                  />
                  <div className="flex justify-between text-xs text-slate-400">
                    <span>5 min (faster)</span>
                    <span>10 min (balanced)</span>
                    <span>15 min (comprehensive)</span>
                  </div>
                  <p className="text-sm text-slate-400">
                    Alerts received within this time window will be grouped into the same incident if they match the same asset and signature.
                  </p>
                </div>

                {/* Aggregation Key */}
                <div className="space-y-3">
                  <Label className="text-white font-semibold">Aggregation Key</Label>
                  <Input
                    value={correlationConfig.aggregation_key}
                    readOnly
                    className="bg-slate-800 border-slate-700 text-slate-300"
                  />
                  <p className="text-sm text-slate-400">
                    Alerts are grouped by: <span className="text-cyan-400 font-mono">{correlationConfig.aggregation_key}</span>
                  </p>
                </div>

                {/* Auto-Correlate Toggle */}
                <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                  <div>
                    <Label className="text-white font-semibold">Auto-Correlation</Label>
                    <p className="text-sm text-slate-400 mt-1">
                      Automatically run correlation when new alerts arrive
                    </p>
                  </div>
                  <Switch
                    checked={correlationConfig.auto_correlate}
                    onCheckedChange={(checked) => {
                      setCorrelationConfig({ ...correlationConfig, auto_correlate: checked });
                      handleUpdateCorrelation({ auto_correlate: checked });
                    }}
                    className="data-[state=checked]:bg-cyan-500"
                  />
                </div>

                {/* Min Alerts for Incident */}
                <div className="space-y-3">
                  <Label className="text-white font-semibold">Minimum Alerts for Incident</Label>
                  <Input
                    type="number"
                    min="1"
                    max="10"
                    value={correlationConfig.min_alerts_for_incident}
                    onChange={(e) => {
                      const newValue = parseInt(e.target.value);
                      setCorrelationConfig({ ...correlationConfig, min_alerts_for_incident: newValue });
                    }}
                    onBlur={(e) => {
                      const newValue = parseInt(e.target.value);
                      if (newValue >= 1 && newValue <= 10) {
                        handleUpdateCorrelation({ min_alerts_for_incident: newValue });
                      }
                    }}
                    className="bg-slate-800 border-slate-700 text-white"
                  />
                  <p className="text-sm text-slate-400">
                    Only create incidents when at least this many alerts are correlated (1 = create incident for every alert)
                  </p>
                </div>

                {/* Info Box */}
                <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4">
                  <h4 className="text-cyan-400 font-semibold mb-2">How Correlation Works</h4>
                  <div className="space-y-2 text-sm text-slate-300">
                    <p>
                      <strong>Example:</strong> With a 10-minute window:
                    </p>
                    <ul className="list-disc list-inside space-y-1 ml-2">
                      <li>Alert 1: web-server-01 | high_cpu | 10:00:00 (Datadog)</li>
                      <li>Alert 2: web-server-01 | high_cpu | 10:03:00 (Zabbix)</li>
                      <li>Alert 3: web-server-01 | high_cpu | 10:07:00 (Prometheus)</li>
                    </ul>
                    <p className="text-cyan-400 font-semibold mt-2">
                      → Result: 1 Incident (3 alerts, 3 tool sources, priority score boosted)
                    </p>
                  </div>
                </div>

                {/* Deduplication Key Patterns */}
                <div className="space-y-3">
                  <h4 className="text-white font-semibold">Available Deduplication Key Patterns</h4>
                  <div className="space-y-2">
                    <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-700">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-cyan-400 font-mono text-sm">asset|signature</span>
                        <span className="text-xs text-green-400 border border-green-400 px-2 py-0.5 rounded">DEFAULT</span>
                      </div>
                      <p className="text-xs text-slate-400">
                        Groups alerts from same asset with same signature. Best for most scenarios.
                      </p>
                    </div>

                    <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-700">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-cyan-400 font-mono text-sm">asset|signature|tool</span>
                      </div>
                      <p className="text-xs text-slate-400">
                        Separate incidents per monitoring tool. Use when you want distinct incidents for same issue from different sources.
                      </p>
                    </div>

                    <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-700">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-cyan-400 font-mono text-sm">signature</span>
                      </div>
                      <p className="text-xs text-slate-400">
                        Groups all alerts with same signature across all assets. Ideal for infrastructure-wide issues (e.g., network outage).
                      </p>
                    </div>

                    <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-700">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-cyan-400 font-mono text-sm">asset</span>
                      </div>
                      <p className="text-xs text-slate-400">
                        Groups all alerts from same asset. Use for asset-centric monitoring.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Time Window Rationale */}
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                  <h4 className="text-blue-400 font-semibold mb-2">Time Window Best Practices</h4>
                  <div className="space-y-2 text-xs text-slate-300">
                    <div className="flex items-center gap-2">
                      <span className="text-blue-400 font-bold">5 min:</span>
                      <span>Fast-changing environments, quick incident creation for critical production systems</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-blue-400 font-bold">10 min:</span>
                      <span>Balanced approach for most use cases, good noise reduction without delays</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-blue-400 font-bold">15 min:</span>
                      <span>Reduces noise in stable environments, suitable for dev/staging (default)</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* AWS Integration Tab */}
          <TabsContent value="aws-integration">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Settings className="w-5 h-5 text-cyan-400" />
                  AWS Integration Patterns
                </CardTitle>
                <CardDescription className="text-slate-300">
                  Production-grade AWS services integration for MSP operations
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Quick Links */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <a
                    href="/AWS_INTEGRATION_GUIDE.md"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-4 bg-slate-800/50 rounded-lg border border-slate-700 hover:border-cyan-500/50 transition-colors"
                  >
                    <h4 className="text-white font-semibold mb-2">📚 Complete AWS Integration Guide</h4>
                    <p className="text-sm text-slate-400">
                      Full documentation for AWS services integration including Secrets Manager, SSM, and API Gateway
                    </p>
                  </a>

                  <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                    <h4 className="text-white font-semibold mb-2">🔐 AWS Secrets Manager</h4>
                    <p className="text-sm text-slate-400 mb-2">
                      Store API keys and HMAC secrets securely
                    </p>
                    <code className="text-xs text-cyan-400 bg-slate-950 px-2 py-1 rounded">
                      /alert-whisperer/company/{companyId}/*
                    </code>
                  </div>

                  <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                    <h4 className="text-white font-semibold mb-2">⚙️ AWS Systems Manager (SSM)</h4>
                    <p className="text-sm text-slate-400">
                      Execute remote commands without SSH or bastion hosts. Secure, audited, IAM-controlled.
                    </p>
                  </div>

                  <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                    <h4 className="text-white font-semibold mb-2">🌐 API Gateway WebSocket</h4>
                    <p className="text-sm text-slate-400">
                      Scale real-time updates to thousands of connections with AWS-managed WebSocket API
                    </p>
                  </div>

                  <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                    <h4 className="text-white font-semibold mb-2">🔑 Cross-Account IAM Roles</h4>
                    <p className="text-sm text-slate-400">
                      Securely manage client AWS resources with assumable roles and External IDs
                    </p>
                  </div>

                  <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                    <h4 className="text-white font-semibold mb-2">📊 Patch Manager Compliance</h4>
                    <p className="text-sm text-slate-400">
                      Track security patch status across all managed instances
                    </p>
                  </div>
                </div>

                {/* Key Benefits */}
                <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                  <h4 className="text-green-400 font-semibold mb-3">✅ Production-Grade Benefits</h4>
                  <ul className="space-y-2 text-sm text-slate-300">
                    <li className="flex items-start gap-2">
                      <Check className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Multi-Tenant Isolation:</strong> Per-tenant API keys, data partitioning, and scoped IAM</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Enhanced Security:</strong> HMAC signatures, replay protection, AWS Secrets Manager</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Scalable Real-Time:</strong> API Gateway WebSocket for thousands of connections</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Secure Remote Execution:</strong> SSM Run Command without SSH/bastion hosts</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Audit & Compliance:</strong> CloudTrail logging, Patch Manager compliance tracking</span>
                    </li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Cross-Account IAM Setup Tab */}
          <TabsContent value="cross-account">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-cyan-400" />
                  AWS Cross-Account IAM Role Setup
                </CardTitle>
                <CardDescription className="text-slate-300">
                  Secure cross-account access for MSP → Client AWS resources
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {crossAccountRole ? (
                  <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                    <p className="text-green-400 font-semibold mb-2">✓ Cross-Account Role Configured</p>
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="text-slate-400">Role ARN:</span>
                        <code className="ml-2 text-cyan-400">{crossAccountRole.role_arn}</code>
                      </div>
                      <div>
                        <span className="text-slate-400">AWS Account ID:</span>
                        <code className="ml-2 text-cyan-400">{crossAccountRole.aws_account_id}</code>
                      </div>
                      <div>
                        <span className="text-slate-400">Status:</span>
                        <span className="ml-2 text-green-400">{crossAccountRole.status}</span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                      <h3 className="text-white font-semibold mb-2">What is Cross-Account Access?</h3>
                      <p className="text-slate-300 text-sm">
                        Allows Alert Whisperer (MSP) to securely access client AWS resources using AssumeRole with ExternalId. 
                        This eliminates the need for long-lived access keys and provides better security and auditability.
                      </p>
                    </div>

                    {crossAccountTemplate && (
                      <>
                        <div>
                          <h3 className="text-white font-semibold mb-3">Step 1: Create IAM Role in Client AWS Account</h3>
                          
                          <div className="space-y-4">
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <Label className="text-white">Trust Policy JSON</Label>
                                <Button
                                  onClick={() => copyToClipboard(JSON.stringify(crossAccountTemplate.trust_policy, null, 2), 'trust')}
                                  size="sm"
                                  variant="ghost"
                                  className="text-cyan-400 hover:text-cyan-300"
                                >
                                  {copiedItem === 'trust' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                                </Button>
                              </div>
                              <pre className="bg-slate-950 border border-slate-700 rounded-lg p-4 text-xs text-slate-300 overflow-x-auto">
                                {JSON.stringify(crossAccountTemplate.trust_policy, null, 2)}
                              </pre>
                            </div>

                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <Label className="text-white">Permissions Policy JSON</Label>
                                <Button
                                  onClick={() => copyToClipboard(JSON.stringify(crossAccountTemplate.permissions_policy, null, 2), 'permissions')}
                                  size="sm"
                                  variant="ghost"
                                  className="text-cyan-400 hover:text-cyan-300"
                                >
                                  {copiedItem === 'permissions' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                                </Button>
                              </div>
                              <pre className="bg-slate-950 border border-slate-700 rounded-lg p-4 text-xs text-slate-300 overflow-x-auto">
                                {JSON.stringify(crossAccountTemplate.permissions_policy, null, 2)}
                              </pre>
                            </div>

                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <Label className="text-white">AWS CLI Commands</Label>
                                <Button
                                  onClick={() => copyToClipboard(crossAccountTemplate.cli_commands, 'cli')}
                                  size="sm"
                                  variant="ghost"
                                  className="text-cyan-400 hover:text-cyan-300"
                                >
                                  {copiedItem === 'cli' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                                </Button>
                              </div>
                              <pre className="bg-slate-950 border border-slate-700 rounded-lg p-4 text-xs text-slate-300 overflow-x-auto">
                                {crossAccountTemplate.cli_commands}
                              </pre>
                            </div>

                            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                              <p className="text-yellow-400 font-semibold mb-2">⚠️ Important Security Notes</p>
                              <ul className="list-disc list-inside text-slate-300 text-sm space-y-1">
                                <li>Keep the External ID secure: <code className="text-cyan-400">{crossAccountTemplate.external_id}</code></li>
                                <li>Never share your AWS Account credentials</li>
                                <li>Role can be revoked anytime from your AWS Console</li>
                                <li>All actions are logged in CloudTrail for auditing</li>
                              </ul>
                            </div>
                          </div>
                        </div>

                        <div>
                          <h3 className="text-white font-semibold mb-3">Step 2: Enter Role ARN After Creation</h3>
                          <div className="space-y-4">
                            <div>
                              <Label className="text-white">AWS Account ID</Label>
                              <Input
                                value={awsAccountId}
                                onChange={(e) => setAwsAccountId(e.target.value)}
                                placeholder="123456789012"
                                className="bg-slate-800 border-slate-700 text-white mt-1"
                              />
                            </div>
                            <div>
                              <Label className="text-white">Role ARN</Label>
                              <Input
                                value={roleArn}
                                onChange={(e) => setRoleArn(e.target.value)}
                                placeholder="arn:aws:iam::123456789012:role/AlertWhispererMSPAccess"
                                className="bg-slate-800 border-slate-700 text-white mt-1"
                              />
                            </div>
                            <Button
                              onClick={saveCrossAccountRole}
                              className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 text-white"
                            >
                              Save Cross-Account Configuration
                            </Button>
                          </div>
                        </div>

                        <div className="bg-slate-800/50 rounded-lg p-4">
                          <h4 className="text-white font-semibold mb-2">What happens after setup?</h4>
                          <ul className="space-y-2 text-slate-300 text-sm">
                            <li className="flex items-start gap-2">
                              <Check className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                              <span>Alert Whisperer can execute SSM Run Commands on your EC2 instances</span>
                            </li>
                            <li className="flex items-start gap-2">
                              <Check className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                              <span>Patch compliance data synced from AWS Patch Manager</span>
                            </li>
                            <li className="flex items-start gap-2">
                              <Check className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                              <span>Auto-remediation runbooks can restart services, clear disk, etc.</span>
                            </li>
                            <li className="flex items-start gap-2">
                              <Check className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                              <span>All actions auditable in CloudTrail (who, what, when)</span>
                            </li>
                          </ul>
                        </div>
                      </>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Rate Limiting Tab */}
          <TabsContent value="rate-limiting">
            <RateLimitSettings companyId={companyId} companyName={companyName} />
          </TabsContent>

          {/* Approval Gates Tab */}
          <TabsContent value="approval-gates">
            <ApprovalGates />
          </TabsContent>

          {/* RBAC & Audit Tab */}
          <TabsContent value="rbac-audit">
            <RBACSettings companyId={companyId} />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default AdvancedSettings;
