import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Server, Cloud, Terminal, Check, X, AlertCircle, Copy, 
  Play, RefreshCw, CheckCircle, XCircle, Loader, ArrowRight 
} from 'lucide-react';
import { toast } from 'sonner';

const ClientOnboardingWizard = ({ companyId, companyName, onComplete }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [selectedPlatform, setSelectedPlatform] = useState('ubuntu');
  const [setupGuide, setSetupGuide] = useState(null);
  const [agentHealth, setAgentHealth] = useState(null);
  const [testing, setTesting] = useState(false);
  const [testResults, setTestResults] = useState({});
  const [copiedIndex, setCopiedIndex] = useState(null);

  const platforms = [
    { id: 'ubuntu', name: 'Ubuntu', icon: '🐧' },
    { id: 'amazon-linux', name: 'Amazon Linux', icon: '📦' },
    { id: 'windows', name: 'Windows Server', icon: '🪟' }
  ];

  useEffect(() => {
    loadSetupGuide();
  }, [selectedPlatform]);

  useEffect(() => {
    if (currentStep === 2) {
      loadAgentHealth();
      const interval = setInterval(loadAgentHealth, 10000); // Refresh every 10 seconds
      return () => clearInterval(interval);
    }
  }, [currentStep]);

  const loadSetupGuide = async () => {
    try {
      const response = await api.get(`/ssm/setup-guide/${selectedPlatform}`);
      setSetupGuide(response.data);
    } catch (error) {
      console.error('Failed to load setup guide:', error);
      toast.error('Failed to load setup guide');
    }
  };

  const loadAgentHealth = async () => {
    try {
      const response = await api.get(`/companies/${companyId}/agent-health`);
      setAgentHealth(response.data);
    } catch (error) {
      console.error('Failed to load agent health:', error);
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

  const testConnection = async (instanceId) => {
    setTesting(true);
    setTestResults(prev => ({ ...prev, [instanceId]: { status: 'testing' } }));
    
    try {
      const response = await api.post(`/companies/${companyId}/ssm/test-connection`, null, {
        params: { instance_id: instanceId }
      });
      
      setTestResults(prev => ({ 
        ...prev, 
        [instanceId]: { 
          status: response.data.success ? 'success' : 'error',
          ...response.data 
        } 
      }));
      
      if (response.data.success) {
        toast.success('SSM connection successful!');
      } else {
        toast.error(`Connection failed: ${response.data.error}`);
      }
    } catch (error) {
      setTestResults(prev => ({ 
        ...prev, 
        [instanceId]: { 
          status: 'error',
          error: error.response?.data?.detail || error.message 
        } 
      }));
      toast.error('Connection test failed');
    } finally {
      setTesting(false);
    }
  };

  const steps = [
    {
      title: 'Welcome',
      description: 'Get started with client infrastructure setup',
      icon: Server
    },
    {
      title: 'Install SSM Agent',
      description: 'Install AWS Systems Manager agent on servers',
      icon: Terminal
    },
    {
      title: 'Test Connectivity',
      description: 'Verify SSM agent connection',
      icon: Cloud
    },
    {
      title: 'Complete',
      description: 'You\'re all set!',
      icon: Check
    }
  ];

  return (
    <div className="min-h-screen bg-slate-950 py-8">
      <div className="max-w-7xl mx-auto px-6">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-white mb-3">
            Client Infrastructure Setup
          </h1>
          <p className="text-lg text-slate-300">
            Connect {companyName}'s servers to Alert Whisperer
          </p>
        </div>

        {/* Progress Steps */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            {steps.map((step, index) => {
              const StepIcon = step.icon;
              const isActive = index === currentStep;
              const isCompleted = index < currentStep;
              
              return (
                <React.Fragment key={index}>
                  <div className="flex flex-col items-center">
                    <div className={`w-16 h-16 rounded-full flex items-center justify-center mb-2 transition-all ${
                      isCompleted 
                        ? 'bg-green-500 text-white' 
                        : isActive 
                          ? 'bg-cyan-500 text-white ring-4 ring-cyan-500/30' 
                          : 'bg-slate-800 text-slate-500'
                    }`}>
                      {isCompleted ? (
                        <Check className="w-8 h-8" />
                      ) : (
                        <StepIcon className="w-8 h-8" />
                      )}
                    </div>
                    <p className={`text-sm font-medium ${
                      isActive || isCompleted ? 'text-white' : 'text-slate-500'
                    }`}>
                      {step.title}
                    </p>
                    <p className="text-xs text-slate-600 text-center max-w-[120px]">
                      {step.description}
                    </p>
                  </div>
                  {index < steps.length - 1 && (
                    <div className={`flex-1 h-1 mx-4 rounded ${
                      isCompleted ? 'bg-green-500' : 'bg-slate-800'
                    }`} />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>

        {/* Step Content */}
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-8">
            {/* Step 0: Welcome */}
            {currentStep === 0 && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-3xl font-bold text-white mb-4">
                    Welcome to Infrastructure Setup! 🚀
                  </h2>
                  <p className="text-slate-300 text-lg mb-6">
                    This wizard will guide you through connecting <span className="text-cyan-400 font-semibold">{companyName}'s</span> servers 
                    to Alert Whisperer for automated monitoring and incident management.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-6 bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-lg">
                    <Terminal className="w-10 h-10 text-cyan-400 mb-3" />
                    <h3 className="text-lg font-semibold text-white mb-2">1. Install SSM Agent</h3>
                    <p className="text-sm text-slate-300">
                      Install AWS Systems Manager agent on your servers (takes 2-3 minutes)
                    </p>
                  </div>

                  <div className="p-6 bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-lg">
                    <Cloud className="w-10 h-10 text-purple-400 mb-3" />
                    <h3 className="text-lg font-semibold text-white mb-2">2. Configure IAM</h3>
                    <p className="text-sm text-slate-300">
                      Set up IAM role for secure MSP access (no VPN/SSH needed)
                    </p>
                  </div>

                  <div className="p-6 bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-lg">
                    <Check className="w-10 h-10 text-green-400 mb-3" />
                    <h3 className="text-lg font-semibold text-white mb-2">3. Test & Go Live</h3>
                    <p className="text-sm text-slate-300">
                      Verify connectivity and start receiving automated alerts
                    </p>
                  </div>
                </div>

                <div className="p-6 bg-slate-800/50 rounded-lg border border-slate-700">
                  <h3 className="text-xl font-semibold text-white mb-4 flex items-center">
                    <AlertCircle className="w-5 h-5 mr-2 text-amber-400" />
                    What You'll Need
                  </h3>
                  <ul className="space-y-2 text-slate-300">
                    <li className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <span><strong>AWS Account Access:</strong> Admin permissions to install SSM agent and configure IAM</span>
                    </li>
                    <li className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <span><strong>Server Access:</strong> SSH/RDP access to your EC2 instances</span>
                    </li>
                    <li className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <span><strong>Time Required:</strong> 10-15 minutes for complete setup</span>
                    </li>
                  </ul>
                </div>

                <div className="flex justify-end">
                  <Button 
                    onClick={() => setCurrentStep(1)}
                    className="bg-cyan-500 hover:bg-cyan-600 text-white px-8 py-6 text-lg"
                  >
                    Get Started
                    <ArrowRight className="w-5 h-5 ml-2" />
                  </Button>
                </div>
              </div>
            )}

            {/* Step 1: Install SSM Agent */}
            {currentStep === 1 && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-3xl font-bold text-white mb-4">
                    Install SSM Agent on Your Servers
                  </h2>
                  <p className="text-slate-300 text-lg">
                    Choose your server platform and follow the installation instructions
                  </p>
                </div>

                {/* Platform Selector */}
                <div className="grid grid-cols-3 gap-4">
                  {platforms.map(platform => (
                    <button
                      key={platform.id}
                      onClick={() => setSelectedPlatform(platform.id)}
                      className={`p-6 rounded-lg border-2 transition-all ${
                        selectedPlatform === platform.id
                          ? 'border-cyan-500 bg-cyan-500/10'
                          : 'border-slate-700 bg-slate-800/30 hover:border-slate-600'
                      }`}
                    >
                      <div className="text-4xl mb-2">{platform.icon}</div>
                      <div className="text-lg font-semibold text-white">{platform.name}</div>
                    </button>
                  ))}
                </div>

                {setupGuide && (
                  <>
                    {/* Installation Commands */}
                    <div>
                      <h3 className="text-xl font-semibold text-white mb-4">
                        Installation Commands
                      </h3>
                      <div className="space-y-3">
                        {setupGuide.install_commands.map((cmd, index) => (
                          <div key={index} className="relative">
                            <div className="bg-slate-800 border border-slate-700 rounded-lg p-4 pr-12 font-mono text-sm text-slate-300">
                              {cmd}
                            </div>
                            <button
                              onClick={() => handleCopy(cmd, `install-${index}`)}
                              className="absolute right-3 top-1/2 -translate-y-1/2 p-2 hover:bg-slate-700 rounded transition-colors"
                            >
                              {copiedIndex === `install-${index}` ? (
                                <Check className="w-4 h-4 text-green-400" />
                              ) : (
                                <Copy className="w-4 h-4 text-slate-400" />
                              )}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Verify Commands */}
                    <div>
                      <h3 className="text-xl font-semibold text-white mb-4">
                        Verify Installation
                      </h3>
                      <div className="space-y-3">
                        {setupGuide.verify_commands.map((cmd, index) => (
                          <div key={index} className="relative">
                            <div className="bg-slate-800 border border-slate-700 rounded-lg p-4 pr-12 font-mono text-sm text-slate-300">
                              {cmd}
                            </div>
                            <button
                              onClick={() => handleCopy(cmd, `verify-${index}`)}
                              className="absolute right-3 top-1/2 -translate-y-1/2 p-2 hover:bg-slate-700 rounded transition-colors"
                            >
                              {copiedIndex === `verify-${index}` ? (
                                <Check className="w-4 h-4 text-green-400" />
                              ) : (
                                <Copy className="w-4 h-4 text-slate-400" />
                              )}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* IAM Role Setup */}
                    <div className="p-6 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                      <h3 className="text-xl font-semibold text-white mb-3 flex items-center">
                        <AlertCircle className="w-5 h-5 mr-2 text-amber-400" />
                        Important: IAM Role Configuration
                      </h3>
                      <p className="text-slate-300 mb-4">
                        After installing SSM agent, you must attach an IAM role to your EC2 instances with SSM permissions:
                      </p>
                      <ol className="list-decimal list-inside space-y-2 text-slate-300">
                        <li>Go to EC2 Console → Select your instances</li>
                        <li>Actions → Security → Modify IAM role</li>
                        <li>Create/Select role with <code className="px-2 py-1 bg-slate-800 rounded text-cyan-400">AmazonSSMManagedInstanceCore</code> policy</li>
                        <li>Save and wait 2-3 minutes for agent to register</li>
                      </ol>
                    </div>
                  </>
                )}

                <div className="flex justify-between">
                  <Button 
                    onClick={() => setCurrentStep(0)}
                    variant="outline"
                    className="border-slate-700 text-slate-300"
                  >
                    Back
                  </Button>
                  <Button 
                    onClick={() => setCurrentStep(2)}
                    className="bg-cyan-500 hover:bg-cyan-600 text-white"
                  >
                    Next: Test Connectivity
                    <ArrowRight className="w-4 h-4 ml-2" />
                  </Button>
                </div>
              </div>
            )}

            {/* Step 2: Test Connectivity */}
            {currentStep === 2 && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-3xl font-bold text-white mb-4">
                    Test SSM Connectivity
                  </h2>
                  <p className="text-slate-300 text-lg">
                    Verify that your servers are connected and ready for remote management
                  </p>
                </div>

                {agentHealth ? (
                  <>
                    {/* Status Summary */}
                    <div className="grid grid-cols-3 gap-4">
                      <div className="p-6 bg-slate-800/50 border border-slate-700 rounded-lg">
                        <div className="text-3xl font-bold text-white mb-2">
                          {agentHealth.total_instances}
                        </div>
                        <div className="text-sm text-slate-400">Total Instances</div>
                      </div>
                      <div className="p-6 bg-green-500/10 border border-green-500/30 rounded-lg">
                        <div className="text-3xl font-bold text-green-400 mb-2">
                          {agentHealth.online_instances}
                        </div>
                        <div className="text-sm text-slate-400">Online</div>
                      </div>
                      <div className="p-6 bg-red-500/10 border border-red-500/30 rounded-lg">
                        <div className="text-3xl font-bold text-red-400 mb-2">
                          {agentHealth.offline_instances}
                        </div>
                        <div className="text-sm text-slate-400">Offline</div>
                      </div>
                    </div>

                    {/* Instance List */}
                    <div>
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-xl font-semibold text-white">
                          Connected Instances
                        </h3>
                        <Button
                          onClick={loadAgentHealth}
                          variant="outline"
                          className="border-slate-700 text-slate-300"
                          size="sm"
                        >
                          <RefreshCw className="w-4 h-4 mr-2" />
                          Refresh
                        </Button>
                      </div>

                      {agentHealth.instances.length > 0 ? (
                        <div className="space-y-3">
                          {agentHealth.instances.map(instance => (
                            <div 
                              key={instance.instance_id}
                              className="p-4 bg-slate-800/50 border border-slate-700 rounded-lg"
                            >
                              <div className="flex items-center justify-between">
                                <div className="flex-1">
                                  <div className="flex items-center mb-2">
                                    {instance.is_online ? (
                                      <CheckCircle className="w-5 h-5 text-green-400 mr-2" />
                                    ) : (
                                      <XCircle className="w-5 h-5 text-red-400 mr-2" />
                                    )}
                                    <span className="font-mono text-white">{instance.instance_id}</span>
                                    <span className={`ml-3 px-2 py-1 rounded text-xs font-semibold ${
                                      instance.is_online 
                                        ? 'bg-green-500/20 text-green-400' 
                                        : 'bg-red-500/20 text-red-400'
                                    }`}>
                                      {instance.ping_status}
                                    </span>
                                  </div>
                                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                                    <div>
                                      <div className="text-slate-500">Platform</div>
                                      <div className="text-slate-300">{instance.platform_name || instance.platform_type}</div>
                                    </div>
                                    <div>
                                      <div className="text-slate-500">IP Address</div>
                                      <div className="text-slate-300">{instance.ip_address || 'N/A'}</div>
                                    </div>
                                    <div>
                                      <div className="text-slate-500">Agent Version</div>
                                      <div className="text-slate-300">{instance.agent_version}</div>
                                    </div>
                                    <div>
                                      <div className="text-slate-500">Last Ping</div>
                                      <div className="text-slate-300">
                                        {new Date(instance.last_ping).toLocaleString()}
                                      </div>
                                    </div>
                                  </div>
                                </div>
                                <div className="ml-4">
                                  <Button
                                    onClick={() => testConnection(instance.instance_id)}
                                    disabled={testing || !instance.is_online}
                                    className={`${
                                      testResults[instance.instance_id]?.status === 'success'
                                        ? 'bg-green-500 hover:bg-green-600'
                                        : testResults[instance.instance_id]?.status === 'error'
                                          ? 'bg-red-500 hover:bg-red-600'
                                          : 'bg-cyan-500 hover:bg-cyan-600'
                                    } text-white`}
                                    size="sm"
                                  >
                                    {testResults[instance.instance_id]?.status === 'testing' ? (
                                      <>
                                        <Loader className="w-4 h-4 mr-2 animate-spin" />
                                        Testing...
                                      </>
                                    ) : testResults[instance.instance_id]?.status === 'success' ? (
                                      <>
                                        <Check className="w-4 h-4 mr-2" />
                                        Success
                                      </>
                                    ) : testResults[instance.instance_id]?.status === 'error' ? (
                                      <>
                                        <X className="w-4 h-4 mr-2" />
                                        Failed
                                      </>
                                    ) : (
                                      <>
                                        <Play className="w-4 h-4 mr-2" />
                                        Test
                                      </>
                                    )}
                                  </Button>
                                </div>
                              </div>
                              {testResults[instance.instance_id]?.error && (
                                <div className="mt-3 p-3 bg-red-500/10 border border-red-500/30 rounded text-sm text-red-400">
                                  {testResults[instance.instance_id].error}
                                </div>
                              )}
                              {testResults[instance.instance_id]?.suggestion && (
                                <div className="mt-2 p-3 bg-amber-500/10 border border-amber-500/30 rounded text-sm text-amber-400">
                                  💡 {testResults[instance.instance_id].suggestion}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="p-8 text-center bg-slate-800/30 border border-slate-700 rounded-lg">
                          <Server className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                          <p className="text-slate-400 mb-2">No instances found with SSM agent</p>
                          <p className="text-sm text-slate-500">
                            Make sure you've installed SSM agent and configured IAM roles
                          </p>
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="flex items-center justify-center p-12">
                    <Loader className="w-8 h-8 text-cyan-400 animate-spin mr-3" />
                    <span className="text-slate-400">Loading instance information...</span>
                  </div>
                )}

                <div className="flex justify-between">
                  <Button 
                    onClick={() => setCurrentStep(1)}
                    variant="outline"
                    className="border-slate-700 text-slate-300"
                  >
                    Back
                  </Button>
                  <Button 
                    onClick={() => setCurrentStep(3)}
                    className="bg-cyan-500 hover:bg-cyan-600 text-white"
                    disabled={!agentHealth || agentHealth.online_instances === 0}
                  >
                    Complete Setup
                    <Check className="w-4 h-4 ml-2" />
                  </Button>
                </div>
              </div>
            )}

            {/* Step 3: Complete */}
            {currentStep === 3 && (
              <div className="space-y-6 text-center py-8">
                <div className="w-20 h-20 rounded-full bg-green-500 text-white flex items-center justify-center mx-auto mb-6">
                  <Check className="w-10 h-10" />
                </div>
                
                <h2 className="text-4xl font-bold text-white mb-4">
                  Setup Complete! 🎉
                </h2>
                
                <p className="text-lg text-slate-300 max-w-2xl mx-auto mb-8">
                  <span className="text-cyan-400 font-semibold">{companyName}</span> is now connected to Alert Whisperer. 
                  Your servers are ready for automated monitoring and incident management.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-4xl mx-auto mb-8">
                  <div className="p-6 bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-lg">
                    <Check className="w-10 h-10 text-green-400 mx-auto mb-3" />
                    <h3 className="text-lg font-semibold text-white mb-2">SSM Agent Installed</h3>
                    <p className="text-sm text-slate-300">
                      {agentHealth?.online_instances || 0} servers connected
                    </p>
                  </div>

                  <div className="p-6 bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-lg">
                    <Cloud className="w-10 h-10 text-cyan-400 mx-auto mb-3" />
                    <h3 className="text-lg font-semibold text-white mb-2">Ready for Alerts</h3>
                    <p className="text-sm text-slate-300">
                      Start sending monitoring alerts
                    </p>
                  </div>

                  <div className="p-6 bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-lg">
                    <Terminal className="w-10 h-10 text-purple-400 mx-auto mb-3" />
                    <h3 className="text-lg font-semibold text-white mb-2">Remote Management</h3>
                    <p className="text-sm text-slate-300">
                      Execute runbooks remotely
                    </p>
                  </div>
                </div>

                <div className="p-6 bg-slate-800/50 rounded-lg border border-slate-700 max-w-2xl mx-auto text-left">
                  <h3 className="text-xl font-semibold text-white mb-4">What's Next?</h3>
                  <ul className="space-y-3 text-slate-300">
                    <li className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <span>Configure your monitoring tools to send alerts to the webhook endpoint</span>
                    </li>
                    <li className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <span>Set up auto-assignment rules to route incidents to technicians</span>
                    </li>
                    <li className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <span>Create custom runbooks for automated remediation</span>
                    </li>
                    <li className="flex items-start">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 mt-2 mr-3"></div>
                      <span>Monitor KPIs and track incident resolution times</span>
                    </li>
                  </ul>
                </div>

                <Button 
                  onClick={onComplete}
                  className="bg-cyan-500 hover:bg-cyan-600 text-white px-8 py-6 text-lg"
                >
                  Go to Dashboard
                  <ArrowRight className="w-5 h-5 ml-2" />
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default ClientOnboardingWizard;
