import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Key, Copy, RefreshCw, Code, BookOpen, Cloud, Terminal, Check, Building2, Users, Send, Workflow } from 'lucide-react';
import { toast } from 'sonner';

const IntegrationSettings = ({ companyId }) => {
  const [company, setCompany] = useState(null);
  const [loading, setLoading] = useState(true);
  const [regenerating, setRegenerating] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);

  useEffect(() => {
    if (companyId) {
      loadCompany();
    }
  }, [companyId]);

  const loadCompany = async () => {
    try {
      const response = await api.get(`/companies/${companyId}`);
      setCompany(response.data);
    } catch (error) {
      console.error('Failed to load company:', error);
      toast.error('Failed to load company details');
    } finally {
      setLoading(false);
    }
  };

  const handleRegenerateKey = async () => {
    if (!window.confirm('Are you sure you want to regenerate the API key? This will invalidate the current key.')) {
      return;
    }

    setRegenerating(true);
    try {
      const response = await api.post(`/companies/${companyId}/regenerate-api-key`);
      setCompany(response.data);
      toast.success('API key regenerated successfully');
    } catch (error) {
      toast.error('Failed to regenerate API key');
    } finally {
      setRegenerating(false);
    }
  };

  const handleCopy = async (text, index) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedIndex(index);
      toast.success('Copied to clipboard');
      setTimeout(() => setCopiedIndex(null), 2000);
    } catch (error) {
      toast.error('Failed to copy');
    }
  };

  const backendUrl = process.env.REACT_APP_BACKEND_URL || window.location.origin;
  const webhookUrl = `${backendUrl}/api/webhooks/alerts`;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-slate-950">
        <div className="text-cyan-400 text-xl">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 py-8">
      <div className="max-w-7xl mx-auto px-6">
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-white mb-3">Client Company Integration</h1>
          <p className="text-lg text-slate-300 mb-2">How to Onboard New Companies & Receive Their Alerts</p>
          <p className="text-slate-400">Complete guide to integrating client companies into your Alert Whisperer system</p>
        </div>

        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="bg-slate-900/50 border border-slate-800">
            <TabsTrigger 
              value="overview"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Workflow className="w-4 h-4 mr-2" />
              Integration Overview
            </TabsTrigger>
            <TabsTrigger 
              value="onboarding"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Building2 className="w-4 h-4 mr-2" />
              Add New Company
            </TabsTrigger>
            <TabsTrigger 
              value="api-keys"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Key className="w-4 h-4 mr-2" />
              API Keys
            </TabsTrigger>
            <TabsTrigger 
              value="send-alerts"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Send className="w-4 h-4 mr-2" />
              Send Alerts
            </TabsTrigger>
            <TabsTrigger 
              value="technicians"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Users className="w-4 h-4 mr-2" />
              Technician Routing
            </TabsTrigger>
            <TabsTrigger 
              value="guides"
              className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <BookOpen className="w-4 h-4 mr-2" />
              Tool Integrations
            </TabsTrigger>
          </TabsList>

          {/* API Keys Tab */}
          <TabsContent value="api-keys">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">API Key Management</CardTitle>
                <CardDescription className="text-slate-400">
                  Your API key for authenticating webhook requests
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="p-6 bg-slate-800/50 rounded-lg border border-slate-700">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-1">Company API Key</h3>
                      <p className="text-sm text-slate-400">Use this key for all webhook integrations</p>
                    </div>
                    <Button
                      onClick={handleRegenerateKey}
                      disabled={regenerating}
                      variant="outline"
                      size="sm"
                      className="border-slate-700 text-slate-300 hover:bg-slate-800"
                    >
                      <RefreshCw className={`w-4 h-4 mr-2 ${regenerating ? 'animate-spin' : ''}`} />
                      Regenerate
                    </Button>
                  </div>
                  
                  <div className="flex items-center gap-2 p-3 bg-slate-900 rounded border border-slate-700 font-mono text-sm">
                    <code className="flex-1 text-cyan-400 overflow-x-auto">
                      {company?.api_key || 'No API key available'}
                    </code>
                    <Button
                      onClick={() => handleCopy(company?.api_key, 'api-key')}
                      size="sm"
                      variant="ghost"
                      className="text-slate-400 hover:text-white"
                    >
                      {copiedIndex === 'api-key' ? (
                        <Check className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </Button>
                  </div>
                  
                  {company?.api_key_created_at && (
                    <p className="text-xs text-slate-500 mt-2">
                      Created: {new Date(company.api_key_created_at).toLocaleString()}
                    </p>
                  )}
                </div>

                <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                  <h4 className="text-amber-400 font-semibold mb-2 flex items-center">
                    <Terminal className="w-4 h-4 mr-2" />
                    Security Best Practices
                  </h4>
                  <ul className="text-sm text-amber-200/80 space-y-1">
                    <li>• Never commit API keys to version control</li>
                    <li>• Store keys in environment variables or secrets managers</li>
                    <li>• Regenerate keys if compromised</li>
                    <li>• Use HTTPS for all API requests</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Webhooks Tab */}
          <TabsContent value="webhooks">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">Webhook Integration</CardTitle>
                <CardDescription className="text-slate-400">
                  Configure your monitoring tools to send alerts to Alert Whisperer
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Webhook URL */}
                <div>
                  <h3 className="text-lg font-semibold text-white mb-3">Webhook Endpoint</h3>
                  <div className="flex items-center gap-2 p-3 bg-slate-800/50 rounded border border-slate-700 font-mono text-sm">
                    <code className="flex-1 text-cyan-400 overflow-x-auto">{webhookUrl}</code>
                    <Button
                      onClick={() => handleCopy(webhookUrl, 'webhook-url')}
                      size="sm"
                      variant="ghost"
                      className="text-slate-400 hover:text-white"
                    >
                      {copiedIndex === 'webhook-url' ? (
                        <Check className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </Button>
                  </div>
                </div>

                {/* cURL Example */}
                <div>
                  <h3 className="text-lg font-semibold text-white mb-3">Example Request</h3>
                  <div className="relative">
                    <pre className="p-4 bg-slate-900 border border-slate-700 rounded-lg overflow-x-auto text-sm">
                      <code className="text-cyan-300">{`curl -X POST "${webhookUrl}?api_key=${company?.api_key || 'YOUR_API_KEY'}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "asset_name": "srv-app-01",
    "signature": "service_down:nginx",
    "severity": "high",
    "message": "Nginx service is down",
    "tool_source": "Datadog"
  }'`}</code>
                    </pre>
                    <Button
                      onClick={() => handleCopy(`curl -X POST "${webhookUrl}?api_key=${company?.api_key}" -H "Content-Type: application/json" -d '{"asset_name": "srv-app-01", "signature": "service_down:nginx", "severity": "high", "message": "Nginx service is down", "tool_source": "Datadog"}'`, 'curl')}
                      size="sm"
                      variant="ghost"
                      className="absolute top-2 right-2 text-slate-400 hover:text-white"
                    >
                      {copiedIndex === 'curl' ? (
                        <Check className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </Button>
                  </div>
                </div>

                {/* Request Format */}
                <div>
                  <h3 className="text-lg font-semibold text-white mb-3">Request Format</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-slate-700">
                          <th className="text-left py-2 px-3 text-slate-300">Field</th>
                          <th className="text-left py-2 px-3 text-slate-300">Type</th>
                          <th className="text-left py-2 px-3 text-slate-300">Required</th>
                          <th className="text-left py-2 px-3 text-slate-300">Description</th>
                        </tr>
                      </thead>
                      <tbody className="text-slate-400">
                        <tr className="border-b border-slate-800">
                          <td className="py-2 px-3"><code className="text-cyan-400">api_key</code></td>
                          <td className="py-2 px-3">Query Param</td>
                          <td className="py-2 px-3">Yes</td>
                          <td className="py-2 px-3">Your company API key</td>
                        </tr>
                        <tr className="border-b border-slate-800">
                          <td className="py-2 px-3"><code className="text-cyan-400">asset_name</code></td>
                          <td className="py-2 px-3">String</td>
                          <td className="py-2 px-3">Yes</td>
                          <td className="py-2 px-3">Name of the asset generating the alert</td>
                        </tr>
                        <tr className="border-b border-slate-800">
                          <td className="py-2 px-3"><code className="text-cyan-400">signature</code></td>
                          <td className="py-2 px-3">String</td>
                          <td className="py-2 px-3">Yes</td>
                          <td className="py-2 px-3">Alert signature (e.g., "service_down:nginx")</td>
                        </tr>
                        <tr className="border-b border-slate-800">
                          <td className="py-2 px-3"><code className="text-cyan-400">severity</code></td>
                          <td className="py-2 px-3">String</td>
                          <td className="py-2 px-3">Yes</td>
                          <td className="py-2 px-3">low, medium, high, or critical</td>
                        </tr>
                        <tr className="border-b border-slate-800">
                          <td className="py-2 px-3"><code className="text-cyan-400">message</code></td>
                          <td className="py-2 px-3">String</td>
                          <td className="py-2 px-3">Yes</td>
                          <td className="py-2 px-3">Alert description</td>
                        </tr>
                        <tr className="border-b border-slate-800">
                          <td className="py-2 px-3"><code className="text-cyan-400">tool_source</code></td>
                          <td className="py-2 px-3">String</td>
                          <td className="py-2 px-3">No</td>
                          <td className="py-2 px-3">Monitoring tool name (default: "External")</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* AWS Tab - Continued in next message due to size */}
          <TabsContent value="aws">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">AWS Systems Manager Setup</CardTitle>
                <CardDescription className="text-slate-400">
                  Configure secure remote access to your infrastructure using AWS SSM
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Step 1 */}
                <div>
                  <h3 className="text-lg font-semibold text-white mb-3">Step 1: Create IAM Role</h3>
                  <p className="text-slate-400 mb-3">Create an IAM role that allows Alert Whisperer to execute commands via SSM</p>
                  <pre className="p-4 bg-slate-900 border border-slate-700 rounded-lg overflow-x-auto text-sm">
                    <code className="text-cyan-300">{`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:ListCommandInvocations"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ssm:resourceTag/Environment": "production"
        }
      }
    }
  ]
}`}</code>
                  </pre>
                </div>

                {/* Step 2 */}
                <div>
                  <h3 className="text-lg font-semibold text-white mb-3">Step 2: Install SSM Agent</h3>
                  <p className="text-slate-400 mb-3">Install SSM Agent on your EC2 instances</p>
                  <div className="space-y-2">
                    <p className="text-sm text-slate-300">Ubuntu/Debian:</p>
                    <pre className="p-3 bg-slate-900 border border-slate-700 rounded text-sm">
                      <code className="text-cyan-300">sudo snap install amazon-ssm-agent --classic</code>
                    </pre>
                    <p className="text-sm text-slate-300 mt-4">Amazon Linux 2:</p>
                    <pre className="p-3 bg-slate-900 border border-slate-700 rounded text-sm">
                      <code className="text-cyan-300">sudo yum install -y amazon-ssm-agent</code>
                    </pre>
                  </div>
                </div>

                {/* Step 3 */}
                <div>
                  <h3 className="text-lg font-semibold text-white mb-3">Step 3: Run Commands</h3>
                  <p className="text-slate-400 mb-3">Execute runbooks via SSM Run Command</p>
                  <pre className="p-4 bg-slate-900 border border-slate-700 rounded-lg overflow-x-auto text-sm">
                    <code className="text-cyan-300">{`aws ssm send-command \\
  --instance-ids "i-1234567890abcdef0" \\
  --document-name "AWS-RunShellScript" \\
  --parameters 'commands=["systemctl restart nginx"]' \\
  --comment "Alert Whisperer: Restart nginx service"`}</code>
                  </pre>
                </div>

                {/* Best Practices */}
                <div className="p-4 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
                  <h4 className="text-cyan-400 font-semibold mb-2">Best Practices</h4>
                  <ul className="text-sm text-cyan-200/80 space-y-1">
                    <li>• Use least-privilege IAM policies</li>
                    <li>• Enable SSM Session Manager for secure shell access</li>
                    <li>• Tag resources for granular access control</li>
                    <li>• Enable CloudWatch logging for audit trails</li>
                    <li>• Use Automation Documents for complex workflows</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Integration Guides Tab */}
          <TabsContent value="guides">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Datadog */}
              <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Code className="w-5 h-5 mr-2 text-cyan-400" />
                    Datadog
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-sm text-slate-400">Configure Datadog webhook to send alerts</p>
                  <ol className="text-sm text-slate-300 space-y-2 list-decimal list-inside">
                    <li>Go to Integrations → Webhooks</li>
                    <li>Create new webhook</li>
                    <li>Set URL to: <code className="text-cyan-400">{webhookUrl}?api_key=YOUR_KEY</code></li>
                    <li>Set payload format to JSON</li>
                    <li>Add to monitors you want to track</li>
                  </ol>
                </CardContent>
              </Card>

              {/* Zabbix */}
              <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Terminal className="w-5 h-5 mr-2 text-cyan-400" />
                    Zabbix
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-sm text-slate-400">Setup Zabbix webhook media type</p>
                  <ol className="text-sm text-slate-300 space-y-2 list-decimal list-inside">
                    <li>Go to Administration → Media types</li>
                    <li>Create webhook media type</li>
                    <li>Use our webhook URL as endpoint</li>
                    <li>Map Zabbix fields to our API format</li>
                    <li>Assign to users/user groups</li>
                  </ol>
                </CardContent>
              </Card>

              {/* Prometheus */}
              <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Cloud className="w-5 h-5 mr-2 text-cyan-400" />
                    Prometheus Alertmanager
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-sm text-slate-400">Configure Alertmanager webhook receiver</p>
                  <pre className="p-3 bg-slate-900 border border-slate-700 rounded text-xs overflow-x-auto">
                    <code className="text-cyan-300">{`receivers:
  - name: 'alert-whisperer'
    webhook_configs:
      - url: '${webhookUrl}?api_key=YOUR_KEY'
        send_resolved: true`}</code>
                  </pre>
                </CardContent>
              </Card>

              {/* CloudWatch */}
              <Card className="bg-slate-900/50 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Cloud className="w-5 h-5 mr-2 text-cyan-400" />
                    AWS CloudWatch
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-sm text-slate-400">Use SNS + Lambda to forward alerts</p>
                  <ol className="text-sm text-slate-300 space-y-2 list-decimal list-inside">
                    <li>Create SNS topic for CloudWatch alarms</li>
                    <li>Create Lambda function to transform & forward</li>
                    <li>Lambda calls our webhook with API key</li>
                    <li>Subscribe Lambda to SNS topic</li>
                  </ol>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default IntegrationSettings;
