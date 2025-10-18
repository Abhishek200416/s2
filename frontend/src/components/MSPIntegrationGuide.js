import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  Building2, Webhook, Bell, Users, Settings, 
  CheckCircle, ArrowRight, Cloud, Monitor, Server
} from 'lucide-react';

/**
 * MSP Integration Guide - Explains how Alert Whisperer integrates clients
 * This component shows the complete flow of how MSPs onboard clients,
 * collect alerts, and manage their infrastructure
 */
const MSPIntegrationGuide = () => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-white mb-2">
          🚀 How Alert Whisperer Works Like Real MSP Software
        </h2>
        <p className="text-slate-400 text-lg">
          Complete integration workflow from client onboarding to alert resolution
        </p>
      </div>

      {/* Main Integration Flow */}
      <Card className="bg-gradient-to-br from-slate-800 to-slate-900 border-cyan-500/30">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Building2 className="w-6 h-6 text-cyan-400" />
            MSP Client Integration Flow
          </CardTitle>
          <CardDescription>
            How Alert Whisperer integrates with your client companies (just like ConnectWise, Datto, or Kaseya)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Step 1: Company Onboarding */}
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
              <span className="text-cyan-400 font-bold text-lg">1</span>
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-bold text-white mb-2">Company Onboarding</h3>
              <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                <p className="text-slate-300 mb-3">
                  <strong className="text-cyan-400">MSP Action:</strong> Add new client company in the "Companies" tab
                </p>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    System generates unique API key for the company
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    Webhook endpoint URL is created: <code className="bg-black px-2 py-1 rounded text-cyan-400">/api/webhooks/alerts?api_key=xxx</code>
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    HMAC security (optional) can be enabled for webhook authentication
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    Rate limiting configured (default: 60 requests/minute)
                  </div>
                </div>
              </div>
            </div>
          </div>

          <ArrowRight className="w-6 h-6 text-cyan-400 mx-auto" />

          {/* Step 2: Infrastructure Setup */}
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
              <span className="text-cyan-400 font-bold text-lg">2</span>
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-bold text-white mb-2">Infrastructure & Agent Setup</h3>
              <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                <p className="text-slate-300 mb-3">
                  <strong className="text-cyan-400">Client Action:</strong> Install AWS SSM agents on their servers
                </p>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
                  <div className="bg-slate-800 p-3 rounded border border-slate-700">
                    <Server className="w-8 h-8 text-cyan-400 mb-2" />
                    <p className="text-white font-medium text-sm">Ubuntu/Linux</p>
                    <code className="text-xs text-slate-400">snap install amazon-ssm-agent</code>
                  </div>
                  <div className="bg-slate-800 p-3 rounded border border-slate-700">
                    <Server className="w-8 h-8 text-cyan-400 mb-2" />
                    <p className="text-white font-medium text-sm">Amazon Linux</p>
                    <code className="text-xs text-slate-400">yum install amazon-ssm-agent</code>
                  </div>
                  <div className="bg-slate-800 p-3 rounded border border-slate-700">
                    <Server className="w-8 h-8 text-cyan-400 mb-2" />
                    <p className="text-white font-medium text-sm">Windows</p>
                    <code className="text-xs text-slate-400">Install-SSMAgent.ps1</code>
                  </div>
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    View agent health in "Agent Health" tab (real-time monitoring)
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    See all assets in "Assets" tab (EC2 inventory with SSM correlation)
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    No SSH, VPN, or firewall configuration needed
                  </div>
                </div>
              </div>
            </div>
          </div>

          <ArrowRight className="w-6 h-6 text-cyan-400 mx-auto" />

          {/* Step 3: Monitoring Tool Integration */}
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
              <span className="text-cyan-400 font-bold text-lg">3</span>
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-bold text-white mb-2">Connect Monitoring Tools</h3>
              <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                <p className="text-slate-300 mb-3">
                  <strong className="text-cyan-400">Client Action:</strong> Configure their monitoring tools to send alerts
                </p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                  {[
                    { name: 'Datadog', icon: Monitor },
                    { name: 'Zabbix', icon: Monitor },
                    { name: 'Prometheus', icon: Monitor },
                    { name: 'CloudWatch', icon: Cloud }
                  ].map((tool) => (
                    <div key={tool.name} className="bg-slate-800 p-3 rounded border border-slate-700 text-center">
                      <tool.icon className="w-8 h-8 text-cyan-400 mx-auto mb-1" />
                      <p className="text-white text-sm">{tool.name}</p>
                    </div>
                  ))}
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    Each tool sends webhook alerts to Alert Whisperer
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    Alerts include: asset_name, severity, message, tool_source
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    Authentication via API key (and optional HMAC signature)
                  </div>
                </div>
                <div className="mt-3 bg-black rounded p-3">
                  <p className="text-xs text-slate-400 mb-1">Example Webhook Request:</p>
                  <pre className="text-green-400 text-xs overflow-x-auto">
{`POST /api/webhooks/alerts?api_key=comp-xxx-xxx
{
  "asset_name": "prod-web-01",
  "signature": "disk_space_critical",
  "severity": "critical",
  "message": "Disk usage at 95%",
  "tool_source": "Datadog"
}`}
                  </pre>
                </div>
              </div>
            </div>
          </div>

          <ArrowRight className="w-6 h-6 text-cyan-400 mx-auto" />

          {/* Step 4: Alert Processing */}
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
              <span className="text-cyan-400 font-bold text-lg">4</span>
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-bold text-white mb-2">Automated Alert Processing</h3>
              <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                <p className="text-slate-300 mb-3">
                  <strong className="text-cyan-400">System Action:</strong> Alert Whisperer processes alerts automatically
                </p>
                <div className="space-y-3">
                  <div className="flex items-start gap-3">
                    <Badge className="bg-green-500/20 text-green-400 mt-1">AI</Badge>
                    <div>
                      <p className="text-white font-medium">AI Classification (Bedrock + Gemini)</p>
                      <p className="text-slate-400 text-sm">Adjusts severity if AI confidence > 70%</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <Badge className="bg-cyan-500/20 text-cyan-400 mt-1">Correlation</Badge>
                    <div>
                      <p className="text-white font-medium">Alert Correlation Engine</p>
                      <p className="text-slate-400 text-sm">Groups related alerts within 15-min window by asset + signature</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <Badge className="bg-purple-500/20 text-purple-400 mt-1">Priority</Badge>
                    <div>
                      <p className="text-white font-medium">Priority Scoring</p>
                      <p className="text-slate-400 text-sm">
                        Score = severity + critical_asset_bonus + duplicate_factor + multi_tool_bonus - age_decay
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <Badge className="bg-amber-500/20 text-amber-400 mt-1">Incident</Badge>
                    <div>
                      <p className="text-white font-medium">Incident Creation</p>
                      <p className="text-slate-400 text-sm">Correlated alerts become incidents with priority scores</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <ArrowRight className="w-6 h-6 text-cyan-400 mx-auto" />

          {/* Step 5: Technician Assignment */}
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
              <span className="text-cyan-400 font-bold text-lg">5</span>
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-bold text-white mb-2">Technician Assignment & Resolution</h3>
              <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                <p className="text-slate-300 mb-3">
                  <strong className="text-cyan-400">MSP Action:</strong> Assign incidents to technicians
                </p>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2 text-slate-400">
                    <Users className="w-4 h-4 text-green-400" />
                    MSP Admin assigns incident to a technician
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <Bell className="w-4 h-4 text-green-400" />
                    Technician receives notification
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <Settings className="w-4 h-4 text-green-400" />
                    Technician can execute runbooks via AWS SSM (no SSH needed)
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    Technician marks incident as resolved with notes
                  </div>
                </div>
                <div className="mt-3 p-3 bg-cyan-500/10 border border-cyan-500/30 rounded">
                  <p className="text-cyan-400 text-sm font-medium">Real-Time Updates:</p>
                  <p className="text-slate-300 text-sm mt-1">
                    All status changes broadcast via WebSocket to all connected users instantly
                  </p>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Key Differences from Traditional Tools */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white">
            ✨ How This Matches Real MSP Software
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <h4 className="text-lg font-bold text-cyan-400">Just Like ConnectWise / Datto</h4>
              <ul className="space-y-2 text-slate-300 text-sm">
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                  Multi-tenant architecture (each company isolated)
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                  Per-company API keys and security settings
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                  Webhook-based alert ingestion from any tool
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                  Automated correlation and noise reduction
                </li>
              </ul>
            </div>
            <div className="space-y-3">
              <h4 className="text-lg font-bold text-cyan-400">Advanced Features</h4>
              <ul className="space-y-2 text-slate-300 text-sm">
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                  AI-powered severity classification (Bedrock + Gemini)
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                  AWS SSM integration (SSH-free remote execution)
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                  Real-time WebSocket updates (instant notifications)
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                  RBAC with 3 roles (MSP Admin, Company Admin, Technician)
                </li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Data Flow Summary */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white">
            📊 Data Flow: Client Infrastructure → MSP Dashboard
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-slate-900 rounded-lg p-4 font-mono text-sm">
            <div className="space-y-2 text-slate-300">
              <div className="flex items-center gap-2">
                <span className="text-cyan-400">1.</span>
                <span>Client Server → Monitoring Tool (Datadog/Zabbix/etc)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-cyan-400">2.</span>
                <span>Monitoring Tool → Webhook → Alert Whisperer API</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-cyan-400">3.</span>
                <span>Alert Whisperer → AI Classification + Correlation</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-cyan-400">4.</span>
                <span>Correlated Alerts → Incident Created</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-cyan-400">5.</span>
                <span>Incident → WebSocket Broadcast → MSP Dashboard</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-cyan-400">6.</span>
                <span>MSP Admin → Assigns to Technician</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-cyan-400">7.</span>
                <span>Technician → Executes Runbook via AWS SSM</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-cyan-400">8.</span>
                <span>Technician → Marks Resolved → Client Notification</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default MSPIntegrationGuide;
