import React, { useState, useEffect, useRef } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Progress } from '@/components/ui/progress';
import { 
  X, Code, Play, Zap, AlertCircle, Check, Copy, Download, Loader
} from 'lucide-react';
import { toast } from 'sonner';

const DemoModeModal = ({ isOpen, onClose, onDemoCompanySelected }) => {
  const [loading, setLoading] = useState(false);
  const [demoCompany, setDemoCompany] = useState(null);
  const [testScript, setTestScript] = useState(null);
  const [dataCount, setDataCount] = useState('100');
  const [generating, setGenerating] = useState(false);
  const [progress, setProgress] = useState({ current: 0, total: 0, percentage: 0 });
  const [status, setStatus] = useState('');
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      loadDemoCompany();
      setupWebSocket();
    }
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [isOpen]);

  const setupWebSocket = () => {
    const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
    const wsUrl = backendUrl.replace('http', 'ws').replace('/api', '') + '/ws';
    
    const ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      console.log('WebSocket connected for demo mode');
      setWsConnected(true);
    };
    
    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        console.log('WebSocket message received:', message);
        
        if (message.type === 'demo_progress') {
          setProgress({
            current: message.data.current,
            total: message.data.total,
            percentage: message.data.percentage
          });
        } else if (message.type === 'demo_status') {
          setStatus(message.data.message || message.data.status);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      setWsConnected(false);
    };
    
    ws.onclose = () => {
      console.log('WebSocket disconnected');
      setWsConnected(false);
    };
    
    wsRef.current = ws;
  };

  const loadDemoCompany = async () => {
    try {
      const response = await api.get('/demo/company');
      setDemoCompany(response.data);
    } catch (error) {
      console.error('Failed to load demo company:', error);
      toast.error('Failed to load demo company');
    }
  };

  const loadTestScript = async () => {
    if (!demoCompany) return;
    
    setLoading(true);
    try {
      const response = await api.get(`/demo/script?company_id=${demoCompany.id}`);
      setTestScript(response.data);
    } catch (error) {
      console.error('Failed to load test script:', error);
      toast.error('Failed to load test script');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateData = async () => {
    if (!demoCompany) {
      toast.error('Demo company not loaded');
      return;
    }

    setGenerating(true);
    setProgress({ current: 0, total: parseInt(dataCount), percentage: 0 });
    setStatus('Starting generation...');
    
    try {
      const response = await api.post('/demo/generate-data', {
        count: parseInt(dataCount),
        company_id: demoCompany.id
      });
      
      toast.success(`Generated ${response.data.count} test alerts!`);
      setStatus('Complete!');
      
      // Wait a moment before closing to show completion
      setTimeout(() => {
        // Select demo company and close modal
        if (onDemoCompanySelected) {
          onDemoCompanySelected(demoCompany);
        }
        onClose();
        setGenerating(false);
        setProgress({ current: 0, total: 0, percentage: 0 });
        setStatus('');
      }, 1500);
    } catch (error) {
      console.error('Failed to generate data:', error);
      toast.error('Failed to generate test data');
      setGenerating(false);
      setProgress({ current: 0, total: 0, percentage: 0 });
      setStatus('');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const downloadScript = () => {
    if (!testScript) return;
    
    const blob = new Blob([testScript.script], { type: 'text/x-python' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = testScript.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('Script downloaded');
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 rounded-xl border border-slate-700 w-full max-w-4xl max-h-[90vh] overflow-auto shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-slate-900 border-b border-slate-700 p-6 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-2">
              <Zap className="w-6 h-6 text-cyan-400" />
              Demo Mode
            </h2>
            <p className="text-slate-400 mt-1">Test Alert Whisperer with demo data</p>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-2 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          {demoCompany && (
            <div className="mb-6 p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
              <div className="flex items-center gap-2 text-green-400 font-semibold mb-2">
                <Check className="w-5 h-5" />
                Demo Company Ready
              </div>
              <p className="text-sm text-slate-300">
                Company: <span className="font-semibold">{demoCompany.name}</span>
              </p>
              <p className="text-sm text-slate-300">
                Assets: <span className="font-semibold">{demoCompany.assets?.length || 0}</span> configured
              </p>
            </div>
          )}

          <Tabs defaultValue="internal" className="w-full">
            <TabsList className="grid w-full grid-cols-2 mb-6">
              <TabsTrigger value="internal">
                <Play className="w-4 h-4 mr-2" />
                Internal Testing
              </TabsTrigger>
              <TabsTrigger value="external">
                <Code className="w-4 h-4 mr-2" />
                External Testing
              </TabsTrigger>
            </TabsList>

            {/* Internal Testing Tab */}
            <TabsContent value="internal">
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Generate Test Data</CardTitle>
                  <CardDescription className="text-slate-400">
                    Click the button below to generate alerts directly in the system
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <label className="text-sm text-slate-300 font-medium mb-2 block">
                      Number of Alerts
                    </label>
                    <Select value={dataCount} onValueChange={setDataCount}>
                      <SelectTrigger className="bg-slate-900 border-slate-700 text-white">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="bg-slate-900 border-slate-700 text-white">
                        <SelectItem value="100">100 Alerts (Default)</SelectItem>
                        <SelectItem value="1000">1,000 Alerts</SelectItem>
                        <SelectItem value="10000">10,000 Alerts</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
                    <h4 className="text-white font-semibold mb-3">What will be generated:</h4>
                    <ul className="space-y-2 text-sm text-slate-300">
                      <li className="flex items-start gap-2">
                        <AlertCircle className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                        Realistic alerts across all severity levels (Critical, High, Medium, Low)
                      </li>
                      <li className="flex items-start gap-2">
                        <AlertCircle className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                        Multiple categories: Server, Database, Network, Security, Storage, Application
                      </li>
                      <li className="flex items-start gap-2">
                        <AlertCircle className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                        Auto-correlation will run to create incidents
                      </li>
                      <li className="flex items-start gap-2">
                        <AlertCircle className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                        Real-time WebSocket updates to dashboard
                      </li>
                    </ul>
                  </div>

                  {/* Note about webhook integration */}
                  <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                    <h4 className="text-blue-400 font-semibold mb-2 flex items-center gap-2">
                      <AlertCircle className="w-4 h-4" />
                      Note: External Webhook Integration
                    </h4>
                    <p className="text-sm text-slate-300">
                      For production use, configure your monitoring tools (Datadog, New Relic, etc.) to send alerts directly to your webhook endpoint. 
                      Find your API key and webhook URL in the company settings.
                    </p>
                  </div>

                  {/* Progress Bar */}
                  {generating && (
                    <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-slate-300 font-medium">Progress</span>
                        <span className="text-sm text-cyan-400 font-semibold">
                          {progress.current} / {progress.total} ({progress.percentage}%)
                        </span>
                      </div>
                      <Progress value={progress.percentage} className="h-2" />
                      {status && (
                        <div className="flex items-center gap-2 text-sm text-slate-400">
                          <Loader className="w-4 h-4 animate-spin text-cyan-400" />
                          {status}
                        </div>
                      )}
                    </div>
                  )}

                  <Button
                    onClick={handleGenerateData}
                    disabled={generating || !demoCompany}
                    className="w-full bg-cyan-600 hover:bg-cyan-700 text-white"
                  >
                    {generating ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent mr-2" />
                        Generating Alerts...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 mr-2" />
                        Generate Test Data
                      </>
                    )}
                  </Button>
                </CardContent>
              </Card>
            </TabsContent>

            {/* External Testing Tab */}
            <TabsContent value="external">
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">External Testing - Python Code</CardTitle>
                  <CardDescription className="text-slate-400">
                    Generate Python code to test webhook integration from external systems
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {!testScript ? (
                    <div className="text-center py-12">
                      <Code className="w-16 h-16 mx-auto mb-4 text-slate-600" />
                      <p className="text-slate-400 mb-6">Click the button below to generate the webhook testing script</p>
                      <Button
                        onClick={loadTestScript}
                        disabled={loading || !demoCompany}
                        className="bg-cyan-600 hover:bg-cyan-700 text-white"
                      >
                        {loading ? (
                          <>
                            <Loader className="w-4 h-4 mr-2 animate-spin" />
                            Generating...
                          </>
                        ) : (
                          <>
                            <Code className="w-4 h-4 mr-2" />
                            Generate Script Code
                          </>
                        )}
                      </Button>
                    </div>
                  ) : (
                    <>
                      <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-3">
                          <h4 className="text-white font-semibold flex items-center gap-2">
                            <Code className="w-4 h-4 text-cyan-400" />
                            {testScript.filename}
                          </h4>
                          <div className="flex gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => copyToClipboard(testScript.script)}
                              className="bg-slate-800 border-slate-700 hover:bg-slate-700 text-white"
                            >
                              <Copy className="w-4 h-4 mr-2" />
                              Copy
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={downloadScript}
                              className="bg-slate-800 border-slate-700 hover:bg-slate-700 text-white"
                            >
                              <Download className="w-4 h-4 mr-2" />
                              Download
                            </Button>
                          </div>
                        </div>
                        <pre className="bg-black/50 rounded p-4 overflow-x-auto max-h-96 text-xs text-slate-300 font-mono">
                          {testScript.script}
                        </pre>
                      </div>

                      {/* Instructions */}
                      <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                        <h4 className="text-blue-400 font-semibold mb-3 flex items-center gap-2">
                          <AlertCircle className="w-4 h-4" />
                          How to Use This Script
                        </h4>
                        <ol className="space-y-2 text-sm text-slate-300 list-decimal list-inside">
                          {testScript.instructions?.map((instruction, index) => (
                            <li key={index}>{instruction}</li>
                          ))}
                          {!testScript.instructions && (
                            <>
                              <li>Copy the code above or download the script file</li>
                              <li>Install required packages: <code className="bg-slate-900 px-2 py-0.5 rounded text-cyan-400">pip install requests</code></li>
                              <li>Run the script: <code className="bg-slate-900 px-2 py-0.5 rounded text-cyan-400">python {testScript.filename}</code></li>
                              <li>The script will send test alerts to your webhook endpoint with HMAC signatures</li>
                              <li>Check the dashboard to see alerts appearing in real-time</li>
                            </>
                          )}
                        </ol>
                      </div>

                      {/* API Configuration Info */}
                      {demoCompany && (
                        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
                          <h4 className="text-white font-semibold mb-3">API Configuration</h4>
                          <div className="space-y-2 text-sm">
                            <div className="flex justify-between">
                              <span className="text-slate-400">Company ID:</span>
                              <code className="text-cyan-400 font-mono">{demoCompany.id}</code>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-400">API Key:</span>
                              <code className="text-cyan-400 font-mono truncate max-w-xs">
                                {demoCompany.api_key || 'Not available'}
                              </code>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-400">Webhook URL:</span>
                              <code className="text-cyan-400 font-mono text-xs">
                                {process.env.REACT_APP_BACKEND_URL}/webhooks/alerts
                              </code>
                            </div>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
};

export default DemoModeModal;
