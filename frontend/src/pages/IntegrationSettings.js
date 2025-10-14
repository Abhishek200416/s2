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

          {/* Overview Tab */}
          <TabsContent value="overview">
            <Card className="bg-slate-900/50 border-slate-800 mb-6">
              <CardHeader>
                <CardTitle className="text-white text-2xl">Complete Integration Workflow</CardTitle>
                <CardDescription className="text-slate-400 text-base">
                  Follow these steps to integrate new client companies and start receiving their alerts
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Workflow Steps */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-5 bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-lg">
                    <div className="flex items-center mb-3">
                      <div className="w-8 h-8 rounded-full bg-cyan-500 text-white flex items-center justify-center font-bold mr-3">1</div>
                      <h3 className="text-lg font-semibold text-white">Add Company</h3>
                    </div>
                    <p className="text-sm text-slate-300">Create a new client company account in Alert Whisperer</p>
                  </div>
                  
                  <div className="p-5 bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-lg">
                    <div className="flex items-center mb-3">
                      <div className="w-8 h-8 rounded-full bg-purple-500 text-white flex items-center justify-center font-bold mr-3">2</div>
                      <h3 className="text-lg font-semibold text-white">Get API Key</h3>
                    </div>
                    <p className="text-sm text-slate-300">Each company automatically receives a unique API key</p>
                  </div>
                  
                  <div className="p-5 bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-lg">
                    <div className="flex items-center mb-3">
                      <div className="w-8 h-8 rounded-full bg-green-500 text-white flex items-center justify-center font-bold mr-3">3</div>
                      <h3 className="text-lg font-semibold text-white">Send Alerts</h3>
                    </div>
                    <p className="text-sm text-slate-300">Company uses API key to send alerts from their systems</p>
                  </div>
                </div>

                {/* What Happens Next */}
                <div className="p-6 bg-slate-800/50 rounded-lg border border-slate-700">
                  <h3 className="text-xl font-semibold text-white mb-4 flex items-center">
                    <Workflow className="w-5 h-5 mr-2 text-cyan-400" />
                    What Happens After Integration?
                  </h3>
                  <div className="space-y-3">
                    <div className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <div>
                        <p className="text-slate-200 font-medium">Alerts are Received</p>
                        <p className="text-sm text-slate-400">Your Alert Whisperer system receives and stores all incoming alerts from the company</p>
                      </div>
                    </div>
                    <div className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <div>
                        <p className="text-slate-200 font-medium">AI Correlation & Analysis</p>
                        <p className="text-sm text-slate-400">Similar alerts are automatically correlated into incidents for easier management</p>
                      </div>
                    </div>
                    <div className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <div>
                        <p className="text-slate-200 font-medium">Technician Assignment</p>
                        <p className="text-sm text-slate-400">Incidents can be assigned to technicians who handle and resolve them</p>
                      </div>
                    </div>
                    <div className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <div>
                        <p className="text-slate-200 font-medium">Resolution Tracking</p>
                        <p className="text-sm text-slate-400">Track progress, add notes, and maintain a complete audit trail</p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Key Benefits */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                    <h4 className="text-blue-400 font-semibold mb-2">For MSPs</h4>
                    <ul className="text-sm text-slate-300 space-y-1">
                      <li>• Centralized alert management for all clients</li>
                      <li>• Automated incident correlation</li>
                      <li>• Easy technician assignment and tracking</li>
                      <li>• Multi-company dashboard view</li>
                    </ul>
                  </div>
                  <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                    <h4 className="text-green-400 font-semibold mb-2">For Clients</h4>
                    <ul className="text-sm text-slate-300 space-y-1">
                      <li>• Simple webhook integration</li>
                      <li>• Works with existing monitoring tools</li>
                      <li>• Secure API key authentication</li>
                      <li>• No software installation required</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Company Onboarding Tab */}
          <TabsContent value="onboarding">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white text-2xl flex items-center">
                  <Building2 className="w-6 h-6 mr-2 text-cyan-400" />
                  How to Add a New Client Company
                </CardTitle>
                <CardDescription className="text-slate-400 text-base">
                  Step-by-step guide to onboard new companies into Alert Whisperer
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Step-by-step instructions */}
                <div className="space-y-6">
                  <div className="border-l-4 border-cyan-500 pl-6 py-2">
                    <h3 className="text-lg font-semibold text-white mb-2">Step 1: Navigate to Companies</h3>
                    <p className="text-slate-300 mb-2">Go to the <strong>Companies</strong> page from the main navigation menu</p>
                  </div>

                  <div className="border-l-4 border-cyan-500 pl-6 py-2">
                    <h3 className="text-lg font-semibold text-white mb-2">Step 2: Add New Company</h3>
                    <p className="text-slate-300 mb-2">Click the <strong>"Add Company"</strong> button</p>
                    <p className="text-sm text-slate-400">Fill in the company details:</p>
                    <ul className="text-sm text-slate-400 mt-1 ml-4 space-y-1">
                      <li>• Company Name (e.g., "Acme Corporation")</li>
                      <li>• Company ID (unique identifier, e.g., "comp-acme")</li>
                      <li>• Contact Email</li>
                      <li>• Phone Number (optional)</li>
                    </ul>
                  </div>

                  <div className="border-l-4 border-cyan-500 pl-6 py-2">
                    <h3 className="text-lg font-semibold text-white mb-2">Step 3: API Key is Auto-Generated</h3>
                    <p className="text-slate-300 mb-2">When you create the company, an <strong>API key is automatically generated</strong></p>
                    <div className="mt-3 p-3 bg-green-500/10 border border-green-500/30 rounded">
                      <p className="text-sm text-green-300">✓ The API key is unique to this company</p>
                      <p className="text-sm text-green-300">✓ It's used to authenticate all alert submissions</p>
                    </div>
                  </div>

                  <div className="border-l-4 border-cyan-500 pl-6 py-2">
                    <h3 className="text-lg font-semibold text-white mb-2">Step 4: Share Integration Details with Client</h3>
                    <p className="text-slate-300 mb-3">Provide the following to your client:</p>
                    <div className="space-y-2">
                      <div className="p-3 bg-slate-800/50 rounded border border-slate-700">
                        <p className="text-sm text-slate-400 mb-1">Webhook URL:</p>
                        <code className="text-cyan-400 text-sm">{webhookUrl}</code>
                      </div>
                      <div className="p-3 bg-slate-800/50 rounded border border-slate-700">
                        <p className="text-sm text-slate-400 mb-1">Their API Key:</p>
                        <code className="text-amber-400 text-sm">Found in API Keys tab after company creation</code>
                      </div>
                      <div className="p-3 bg-slate-800/50 rounded border border-slate-700">
                        <p className="text-sm text-slate-400 mb-1">Integration Instructions:</p>
                        <p className="text-slate-300 text-sm">Share the "Send Alerts" and "Tool Integrations" tabs with them</p>
                      </div>
                    </div>
                  </div>

                  <div className="border-l-4 border-green-500 pl-6 py-2">
                    <h3 className="text-lg font-semibold text-white mb-2">Step 5: Client Configures Their Systems</h3>
                    <p className="text-slate-300 mb-2">The client configures their monitoring tools to send alerts to your webhook</p>
                    <ul className="text-sm text-slate-400 mt-2 ml-4 space-y-1">
                      <li>• They use the webhook URL with their API key</li>
                      <li>• Alerts start flowing into Alert Whisperer automatically</li>
                      <li>• You can see their alerts in the dashboard immediately</li>
                    </ul>
                  </div>
                </div>

                {/* Important Notes */}
                <div className="p-5 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                  <h4 className="text-amber-400 font-semibold mb-3 flex items-center text-lg">
                    <Terminal className="w-5 h-5 mr-2" />
                    Important Notes
                  </h4>
                  <ul className="text-sm text-amber-200/90 space-y-2">
                    <li>• Each company must have a unique Company ID</li>
                    <li>• API keys are sensitive - share them securely (encrypted email, password manager)</li>
                    <li>• You can regenerate API keys anytime from the API Keys tab</li>
                    <li>• Regenerating a key will invalidate the old one</li>
                    <li>• Test the integration by sending a test alert (see "Send Alerts" tab)</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

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

          {/* Send Alerts Tab */}
          <TabsContent value="send-alerts">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white text-2xl flex items-center">
                  <Send className="w-6 h-6 mr-2 text-cyan-400" />
                  How to Send Alerts to Alert Whisperer
                </CardTitle>
                <CardDescription className="text-slate-400 text-base">
                  Guide for your clients to configure their systems and send alerts
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

          {/* Technician Routing Tab */}
          <TabsContent value="technicians">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white text-2xl flex items-center">
                  <Users className="w-6 h-6 mr-2 text-cyan-400" />
                  How Alerts are Routed to Technicians
                </CardTitle>
                <CardDescription className="text-slate-400 text-base">
                  Understanding the alert → incident → technician workflow
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Workflow Overview */}
                <div className="p-6 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-lg">
                  <h3 className="text-xl font-semibold text-white mb-4">Alert Processing Workflow</h3>
                  <div className="space-y-4">
                    <div className="flex items-start">
                      <div className="flex-shrink-0 w-10 h-10 rounded-full bg-cyan-500 text-white flex items-center justify-center font-bold mr-4">1</div>
                      <div className="flex-1">
                        <h4 className="text-lg font-semibold text-white mb-1">Alerts Received</h4>
                        <p className="text-slate-300">Alerts arrive from client companies via webhook with their API key</p>
                      </div>
                    </div>
                    <div className="border-l-2 border-cyan-500/50 ml-5 pl-9 pb-4">
                      <p className="text-sm text-slate-400">Each alert contains: asset name, signature, severity, message, and tool source</p>
                    </div>

                    <div className="flex items-start">
                      <div className="flex-shrink-0 w-10 h-10 rounded-full bg-purple-500 text-white flex items-center justify-center font-bold mr-4">2</div>
                      <div className="flex-1">
                        <h4 className="text-lg font-semibold text-white mb-1">AI Correlation</h4>
                        <p className="text-slate-300">Similar alerts are automatically grouped into incidents</p>
                      </div>
                    </div>
                    <div className="border-l-2 border-purple-500/50 ml-5 pl-9 pb-4">
                      <p className="text-sm text-slate-400">Alerts with similar signatures and assets are correlated together</p>
                      <p className="text-sm text-slate-400 mt-1">Example: Multiple "service_down:nginx" alerts → Single incident</p>
                    </div>

                    <div className="flex items-start">
                      <div className="flex-shrink-0 w-10 h-10 rounded-full bg-green-500 text-white flex items-center justify-center font-bold mr-4">3</div>
                      <div className="flex-1">
                        <h4 className="text-lg font-semibold text-white mb-1">Technician Assignment</h4>
                        <p className="text-slate-300">Incidents can be assigned to technicians for resolution</p>
                      </div>
                    </div>
                    <div className="border-l-2 border-green-500/50 ml-5 pl-9 pb-4">
                      <p className="text-sm text-slate-400">MSP administrators assign incidents to available technicians</p>
                      <p className="text-sm text-slate-400 mt-1">Technicians receive the incident details and begin troubleshooting</p>
                    </div>

                    <div className="flex items-start">
                      <div className="flex-shrink-0 w-10 h-10 rounded-full bg-amber-500 text-white flex items-center justify-center font-bold mr-4">4</div>
                      <div className="flex-1">
                        <h4 className="text-lg font-semibold text-white mb-1">Resolution & Tracking</h4>
                        <p className="text-slate-300">Technicians work on incidents and update their status</p>
                      </div>
                    </div>
                    <div className="border-l-2 border-amber-500/50 ml-5 pl-9">
                      <p className="text-sm text-slate-400">Technicians add notes, track progress, and mark incidents as resolved</p>
                      <p className="text-sm text-slate-400 mt-1">Complete audit trail maintained for compliance</p>
                    </div>
                  </div>
                </div>

                {/* Assignment Options */}
                <div>
                  <h3 className="text-xl font-semibold text-white mb-4">How to Assign Incidents to Technicians</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                      <h4 className="text-lg font-semibold text-cyan-400 mb-2">Manual Assignment</h4>
                      <p className="text-sm text-slate-300 mb-3">MSP admins manually assign incidents based on:</p>
                      <ul className="text-sm text-slate-400 space-y-1 ml-4">
                        <li>• Technician expertise and skills</li>
                        <li>• Current workload distribution</li>
                        <li>• Incident severity and priority</li>
                        <li>• Client relationship assignment</li>
                      </ul>
                    </div>

                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                      <h4 className="text-lg font-semibold text-purple-400 mb-2">Automation Options</h4>
                      <p className="text-sm text-slate-300 mb-3">Future enhancements can include:</p>
                      <ul className="text-sm text-slate-400 space-y-1 ml-4">
                        <li>• Round-robin assignment</li>
                        <li>• Skill-based routing</li>
                        <li>• Load balancing</li>
                        <li>• On-call schedule integration</li>
                      </ul>
                    </div>
                  </div>
                </div>

                {/* Technician Capabilities */}
                <div>
                  <h3 className="text-xl font-semibold text-white mb-4">What Technicians Can Do</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                      <h4 className="text-blue-400 font-semibold mb-2 flex items-center">
                        <Workflow className="w-4 h-4 mr-2" />
                        View & Analyze
                      </h4>
                      <ul className="text-sm text-slate-300 space-y-1">
                        <li>• View incident details</li>
                        <li>• See correlated alerts</li>
                        <li>• Review alert history</li>
                        <li>• Check asset information</li>
                      </ul>
                    </div>

                    <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                      <h4 className="text-green-400 font-semibold mb-2 flex items-center">
                        <Terminal className="w-4 h-4 mr-2" />
                        Take Action
                      </h4>
                      <ul className="text-sm text-slate-300 space-y-1">
                        <li>• Add resolution notes</li>
                        <li>• Update incident status</li>
                        <li>• Execute runbooks</li>
                        <li>• Document fixes</li>
                      </ul>
                    </div>

                    <div className="p-4 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                      <h4 className="text-purple-400 font-semibold mb-2 flex items-center">
                        <Check className="w-4 h-4 mr-2" />
                        Close & Report
                      </h4>
                      <ul className="text-sm text-slate-300 space-y-1">
                        <li>• Mark as resolved</li>
                        <li>• Generate reports</li>
                        <li>• Provide client updates</li>
                        <li>• Track resolution time</li>
                      </ul>
                    </div>
                  </div>
                </div>

                {/* Integration with Systems */}
                <div className="p-5 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
                  <h4 className="text-cyan-400 font-semibold mb-3 flex items-center text-lg">
                    <Cloud className="w-5 h-5 mr-2" />
                    System Integration for Automated Response
                  </h4>
                  <p className="text-slate-300 mb-3">
                    Technicians can execute automated responses directly from Alert Whisperer:
                  </p>
                  <div className="space-y-2">
                    <div className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <div>
                        <p className="text-slate-200 font-medium">AWS Systems Manager Integration</p>
                        <p className="text-sm text-slate-400">Execute commands and runbooks on client infrastructure via SSM</p>
                      </div>
                    </div>
                    <div className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <div>
                        <p className="text-slate-200 font-medium">Runbook Automation</p>
                        <p className="text-sm text-slate-400">Predefined scripts for common issues (service restart, disk cleanup, etc.)</p>
                      </div>
                    </div>
                    <div className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <div>
                        <p className="text-slate-200 font-medium">Notification Systems</p>
                        <p className="text-sm text-slate-400">Alert clients via email, SMS, or ticketing system integration</p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Best Practices */}
                <div className="p-5 bg-green-500/10 border border-green-500/30 rounded-lg">
                  <h4 className="text-green-400 font-semibold mb-3 text-lg">Best Practices for Incident Management</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <p className="text-sm font-semibold text-green-300 mb-2">Assignment:</p>
                      <ul className="text-sm text-slate-300 space-y-1">
                        <li>• Assign high-severity incidents immediately</li>
                        <li>• Match technician skills to incident type</li>
                        <li>• Balance workload across team</li>
                      </ul>
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-green-300 mb-2">Resolution:</p>
                      <ul className="text-sm text-slate-300 space-y-1">
                        <li>• Document all actions taken</li>
                        <li>• Update status regularly</li>
                        <li>• Create runbooks for recurring issues</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tool Integrations Tab */}
          <TabsContent value="guides">
            <div className="mb-6">
              <h2 className="text-2xl font-bold text-white mb-2">Monitoring Tool Integrations</h2>
              <p className="text-slate-400">Configure popular monitoring tools to send alerts to Alert Whisperer</p>
            </div>
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
