import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { 
  Server, Cloud, Terminal, Check, X, AlertCircle, Copy, 
  Play, RefreshCw, CheckCircle, XCircle, Loader, ArrowRight,
  Building2, Shield, Settings, Sparkles, Clock
} from 'lucide-react';
import { toast } from 'sonner';

/**
 * MSP-Style Company Onboarding Wizard
 * Real MSP Flow: Collect Info → Install Agent → Test Connection → Create Company (Only on Success)
 * If test fails, company is NOT created
 */
const MSPOnboardingWizard = ({ onSuccess, onCancel }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [loading, setLoading] = useState(false);
  
  // Company data (not saved until test passes)
  const [companyData, setCompanyData] = useState({
    name: '',
    contact_email: '',
    maintenance_window: 'Saturday 22:00-02:00 EST'
  });
  
  // SSM Setup
  const [selectedPlatform, setSelectedPlatform] = useState('ubuntu');
  const [setupGuide, setSetupGuide] = useState(null);
  const [agentHealth, setAgentHealth] = useState(null);
  const [testResults, setTestResults] = useState({});
  const [testing, setTesting] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  
  // Track if at least one instance passed the test
  const [hasSuccessfulTest, setHasSuccessfulTest] = useState(false);
  
  // Created company (after successful test)
  const [createdCompany, setCreatedCompany] = useState(null);

  const platforms = [
    { id: 'ubuntu', name: 'Ubuntu', icon: '🐧' },
    { id: 'amazon-linux', name: 'Amazon Linux', icon: '📦' },
    { id: 'windows', name: 'Windows Server', icon: '🪟' }
  ];

  const steps = [
    { id: 0, name: 'Company Details', icon: Building2 },
    { id: 1, name: 'Install SSM Agent', icon: Terminal },
    { id: 2, name: 'Test Connectivity', icon: CheckCircle },
    { id: 3, name: 'Complete Setup', icon: Sparkles }
  ];

  useEffect(() => {
    if (currentStep === 1) {
      loadSetupGuide();
    }
  }, [selectedPlatform, currentStep]);

  useEffect(() => {
    if (currentStep === 2) {
      loadAgentHealth();
      const interval = setInterval(loadAgentHealth, 10000);
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
    // For test connectivity step, we need a temporary company ID
    // We'll use a special endpoint that doesn't require company to exist yet
    try {
      const response = await api.get(`/ssm/check-instances`);
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
      const response = await api.post(`/ssm/test-connection`, null, {
        params: { instance_id: instanceId }
      });
      
      const success = response.data.success;
      setTestResults(prev => ({ 
        ...prev, 
        [instanceId]: { 
          status: success ? 'success' : 'error',
          ...response.data 
        } 
      }));
      
      if (success) {
        setHasSuccessfulTest(true);
        toast.success('SSM connection successful! You can now complete setup.');
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

  const handleNext = async () => {
    // Step 0: Validate company details
    if (currentStep === 0) {
      if (!companyData.name.trim()) {
        toast.error('Company name is required');
        return;
      }
      if (!companyData.contact_email.trim() || !companyData.contact_email.includes('@')) {
        toast.error('Valid contact email is required');
        return;
      }
      setCurrentStep(1);
      return;
    }

    // Step 1: Move to test connectivity
    if (currentStep === 1) {
      setCurrentStep(2);
      return;
    }

    // Step 2: Create company ONLY if test passed
    if (currentStep === 2) {
      if (!hasSuccessfulTest) {
        toast.error('⛔ You must successfully test at least one SSM connection before proceeding.');
        return;
      }
      
      // Create company now that SSM is verified
      setLoading(true);
      try {
        const response = await api.post('/companies', {
          name: companyData.name,
          contact_email: companyData.contact_email,
          policy: {
            auto_approve_low_risk: true,
            maintenance_window: companyData.maintenance_window
          },
          assets: []
        });
        
        const company = response.data;
        setCreatedCompany(company);
        toast.success('🎉 Company created successfully!');
        setCurrentStep(3);
      } catch (error) {
        toast.error(error.response?.data?.detail || 'Failed to create company');
      } finally {
        setLoading(false);
      }
      return;
    }

    // Step 3: Complete
    if (currentStep === 3) {
      if (onSuccess) {
        onSuccess(createdCompany);
      }
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  return (
    <div className="max-w-5xl mx-auto p-6">
      {/* Progress Steps */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          {steps.map((step, index) => (
            <React.Fragment key={step.id}>
              <div className="flex flex-col items-center">
                <div className={`
                  w-12 h-12 rounded-full flex items-center justify-center
                  ${currentStep === step.id ? 'bg-cyan-500 text-white' : 
                    currentStep > step.id ? 'bg-green-500 text-white' : 
                    'bg-slate-700 text-slate-400'}
                  transition-all duration-300
                `}>
                  {currentStep > step.id ? (
                    <Check className="w-6 h-6" />
                  ) : (
                    <step.icon className="w-6 h-6" />
                  )}
                </div>
                <div className={`
                  mt-2 text-sm font-medium
                  ${currentStep === step.id ? 'text-cyan-400' : 
                    currentStep > step.id ? 'text-green-400' : 
                    'text-slate-500'}
                `}>
                  {step.name}
                </div>
              </div>
              
              {index < steps.length - 1 && (
                <div className={`
                  flex-1 h-1 mx-4
                  ${currentStep > step.id ? 'bg-green-500' : 'bg-slate-700'}
                  transition-all duration-300
                `} />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Step 0: Company Details */}
      {currentStep === 0 && (
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-2xl text-white flex items-center gap-2">
              <Building2 className="w-6 h-6 text-cyan-400" />
              Company Information
            </CardTitle>
            <CardDescription>
              Enter the basic details for the client company you're onboarding
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="company-name" className="text-white">Company Name *</Label>
              <Input
                id="company-name"
                placeholder="e.g., Acme Corporation"
                value={companyData.name}
                onChange={(e) => setCompanyData({ ...companyData, name: e.target.value })}
                className="bg-slate-700 border-slate-600 text-white mt-2"
              />
            </div>

            <div>
              <Label htmlFor="contact-email" className="text-white">Contact Email *</Label>
              <Input
                id="contact-email"
                type="email"
                placeholder="e.g., it@acme.com"
                value={companyData.contact_email}
                onChange={(e) => setCompanyData({ ...companyData, contact_email: e.target.value })}
                className="bg-slate-700 border-slate-600 text-white mt-2"
              />
            </div>

            <div>
              <Label htmlFor="maintenance-window" className="text-white">Maintenance Window</Label>
              <Input
                id="maintenance-window"
                placeholder="e.g., Saturday 22:00-02:00 EST"
                value={companyData.maintenance_window}
                onChange={(e) => setCompanyData({ ...companyData, maintenance_window: e.target.value })}
                className="bg-slate-700 border-slate-600 text-white mt-2"
              />
              <p className="text-slate-400 text-sm mt-1">
                When can automated maintenance tasks run?
              </p>
            </div>

            <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4 mt-6">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-blue-400 mt-0.5" />
                <div>
                  <h4 className="text-blue-300 font-semibold mb-1">Next Steps</h4>
                  <p className="text-slate-300 text-sm">
                    After entering company details, you'll install the AWS SSM agent on their servers 
                    and test the connection. <strong className="text-white">The company will only be created 
                    if the SSM connection test succeeds.</strong>
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Step 1: Install SSM Agent */}
      {currentStep === 1 && (
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-2xl text-white flex items-center gap-2">
              <Terminal className="w-6 h-6 text-cyan-400" />
              Install AWS Systems Manager Agent
            </CardTitle>
            <CardDescription>
              The SSM agent allows remote management without SSH/VPN access
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Platform Selection */}
            <div>
              <Label className="text-white mb-3 block">Select Server Platform</Label>
              <div className="grid grid-cols-3 gap-4">
                {platforms.map((platform) => (
                  <button
                    key={platform.id}
                    onClick={() => setSelectedPlatform(platform.id)}
                    className={`
                      p-4 rounded-lg border-2 transition-all
                      ${selectedPlatform === platform.id 
                        ? 'border-cyan-500 bg-cyan-500/10' 
                        : 'border-slate-600 bg-slate-700 hover:border-slate-500'}
                    `}
                  >
                    <div className="text-3xl mb-2">{platform.icon}</div>
                    <div className="text-white font-medium">{platform.name}</div>
                  </button>
                ))}
              </div>
            </div>

            {setupGuide && (
              <>
                {/* Prerequisites */}
                {setupGuide.prerequisites && (
                  <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
                    <h4 className="text-blue-300 font-semibold mb-2 flex items-center gap-2">
                      <AlertCircle className="w-4 h-4" />
                      Prerequisites
                    </h4>
                    <ul className="text-slate-300 text-sm space-y-1">
                      {setupGuide.prerequisites.map((prereq, idx) => (
                        <li key={idx}>{prereq}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Installation Commands */}
                <div>
                  <h4 className="text-white font-semibold mb-3 flex items-center gap-2">
                    <Terminal className="w-4 h-4" />
                    Step 1: Install SSM Agent
                  </h4>
                  {setupGuide.install_commands.map((cmd, index) => (
                    <div key={index} className="mb-3">
                      <div className="flex items-center justify-between bg-slate-900 rounded-t-lg px-4 py-2 border border-slate-700">
                        <span className="text-slate-400 text-sm">Command {index + 1}</span>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleCopy(cmd, `install-${index}`)}
                          className="h-7"
                        >
                          {copiedIndex === `install-${index}` ? (
                            <Check className="w-4 h-4 text-green-400" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </Button>
                      </div>
                      <pre className="bg-black text-green-400 p-4 rounded-b-lg overflow-x-auto border border-t-0 border-slate-700 text-sm">
                        <code>{cmd}</code>
                      </pre>
                    </div>
                  ))}
                </div>

                {/* Verification Commands */}
                <div>
                  <h4 className="text-white font-semibold mb-3 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" />
                    Step 2: Verify Installation
                  </h4>
                  {setupGuide.verify_commands.map((cmd, index) => (
                    <div key={index} className="mb-3">
                      <div className="flex items-center justify-between bg-slate-900 rounded-t-lg px-4 py-2 border border-slate-700">
                        <span className="text-slate-400 text-sm">Verify Command</span>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleCopy(cmd, `verify-${index}`)}
                          className="h-7"
                        >
                          {copiedIndex === `verify-${index}` ? (
                            <Check className="w-4 h-4 text-green-400" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </Button>
                      </div>
                      <pre className="bg-black text-green-400 p-4 rounded-b-lg overflow-x-auto border border-t-0 border-slate-700 text-sm">
                        <code>{cmd}</code>
                      </pre>
                    </div>
                  ))}
                  {setupGuide.expected_output && (
                    <div className="bg-green-900/20 border border-green-500/30 rounded p-3 text-sm">
                      <span className="text-green-300 font-medium">Expected Output: </span>
                      <span className="text-slate-300">{setupGuide.expected_output}</span>
                    </div>
                  )}
                </div>

                {/* IAM Role Setup with Detailed Steps */}
                <div className="bg-amber-900/20 border border-amber-500/30 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <Shield className="w-5 h-5 text-amber-400 mt-0.5 flex-shrink-0" />
                    <div className="flex-1">
                      <h4 className="text-amber-300 font-semibold mb-2">Step 3: Configure IAM Role (CRITICAL)</h4>
                      
                      {setupGuide.iam_setup_steps && (
                        <div className="mb-3">
                          <p className="text-slate-300 text-sm mb-2">Follow these steps to create and attach the IAM role:</p>
                          <ol className="text-slate-300 text-sm space-y-1 list-decimal list-inside">
                            {setupGuide.iam_setup_steps.map((step, idx) => (
                              <li key={idx} className="ml-2">{step}</li>
                            ))}
                          </ol>
                        </div>
                      )}

                      <div className="space-y-3 mt-4">
                        <div>
                          <div className="text-slate-300 text-sm mb-2">Trust Policy:</div>
                          <div className="relative">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleCopy(JSON.stringify(setupGuide.iam_role_policy, null, 2), 'iam-trust')}
                              className="absolute top-2 right-2 z-10"
                            >
                              {copiedIndex === 'iam-trust' ? (
                                <Check className="w-4 h-4 text-green-400" />
                              ) : (
                                <Copy className="w-4 h-4" />
                              )}
                            </Button>
                            <pre className="bg-black text-blue-300 p-4 rounded-lg overflow-x-auto text-xs">
                              <code>{JSON.stringify(setupGuide.iam_role_policy, null, 2)}</code>
                            </pre>
                          </div>
                        </div>

                        <div>
                          <div className="text-slate-300 text-sm mb-2">Permissions Policy (or use AmazonSSMManagedInstanceCore):</div>
                          <div className="relative">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleCopy(JSON.stringify(setupGuide.iam_permissions, null, 2), 'iam-perms')}
                              className="absolute top-2 right-2 z-10"
                            >
                              {copiedIndex === 'iam-perms' ? (
                                <Check className="w-4 h-4 text-green-400" />
                              ) : (
                                <Copy className="w-4 h-4" />
                              )}
                            </Button>
                            <pre className="bg-black text-blue-300 p-4 rounded-lg overflow-x-auto text-xs">
                              <code>{JSON.stringify(setupGuide.iam_permissions, null, 2)}</code>
                            </pre>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Wait Time Notice */}
                {setupGuide.wait_time && (
                  <div className="bg-cyan-900/20 border border-cyan-500/30 rounded-lg p-4">
                    <div className="flex items-start gap-3">
                      <Clock className="w-5 h-5 text-cyan-400 mt-0.5" />
                      <div>
                        <h4 className="text-cyan-300 font-semibold mb-1">Wait Time Required</h4>
                        <p className="text-slate-300 text-sm">
                          After installation and IAM role attachment, wait <strong>{setupGuide.wait_time}</strong> before testing the connection.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Security Notes */}
                {setupGuide.security_notes && (
                  <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
                    <h4 className="text-green-300 font-semibold mb-2 flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      Security Benefits
                    </h4>
                    <ul className="text-slate-300 text-sm space-y-1">
                      {setupGuide.security_notes.map((note, idx) => (
                        <li key={idx}>{note}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Troubleshooting Commands (Expandable) */}
                {setupGuide.troubleshooting_commands && (
                  <details className="bg-slate-900/50 border border-slate-700 rounded-lg p-4">
                    <summary className="text-white font-semibold cursor-pointer flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 text-amber-400" />
                      Troubleshooting Commands (Click to expand)
                    </summary>
                    <div className="mt-3 space-y-2">
                      {setupGuide.troubleshooting_commands.map((cmd, idx) => (
                        <div key={idx}>
                          {cmd.startsWith('#') ? (
                            <div className="text-slate-400 text-sm mt-3 mb-1 font-medium">{cmd}</div>
                          ) : cmd.trim() === '' ? (
                            <div className="h-2" />
                          ) : (
                            <div className="flex items-center gap-2">
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => handleCopy(cmd, `troubleshoot-${idx}`)}
                                className="h-7 flex-shrink-0"
                              >
                                {copiedIndex === `troubleshoot-${idx}` ? (
                                  <Check className="w-4 h-4 text-green-400" />
                                ) : (
                                  <Copy className="w-4 h-4" />
                                )}
                              </Button>
                              <pre className="bg-black text-amber-400 p-2 rounded flex-1 overflow-x-auto text-xs">
                                <code>{cmd}</code>
                              </pre>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </details>
                )}
              </>
            )}
          </CardContent>
        </Card>
      )}

      {/* Step 2: Test Connectivity */}
      {currentStep === 2 && (
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-2xl text-white flex items-center gap-2">
              <CheckCircle className="w-6 h-6 text-cyan-400" />
              Test SSM Connectivity
            </CardTitle>
            <CardDescription>
              Verify that Alert Whisperer can connect to the client's servers
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!agentHealth && (
              <div className="text-center py-8">
                <Loader className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-3" />
                <p className="text-slate-400">Scanning for SSM-enabled instances...</p>
              </div>
            )}

            {agentHealth && agentHealth.instances && agentHealth.instances.length === 0 && (
              <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-6">
                <div className="flex items-start gap-3">
                  <XCircle className="w-6 h-6 text-red-400 mt-0.5" />
                  <div>
                    <h4 className="text-red-300 font-semibold mb-2">No SSM Instances Found</h4>
                    <p className="text-slate-300 text-sm mb-3">
                      We couldn't find any EC2 instances with the SSM agent installed and running.
                    </p>
                    <div className="text-sm text-slate-400 space-y-1">
                      <p><strong>Troubleshooting:</strong></p>
                      <ul className="list-disc list-inside ml-4 space-y-1">
                        <li>Verify SSM agent is installed and running on the server</li>
                        <li>Check that the EC2 instance has the correct IAM role attached</li>
                        <li>Wait 2-3 minutes after installation for the agent to register</li>
                        <li>Ensure the instance has internet connectivity to reach AWS SSM endpoints</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {agentHealth && agentHealth.instances && agentHealth.instances.length > 0 && (
              <div>
                <div className="mb-4 flex items-center justify-between">
                  <div>
                    <h4 className="text-white font-semibold">Discovered Instances</h4>
                    <p className="text-slate-400 text-sm">
                      {agentHealth.online_instances} of {agentHealth.total_instances} instances online
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={loadAgentHealth}
                    className="border-slate-600"
                  >
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                  </Button>
                </div>

                <div className="space-y-3">
                  {agentHealth.instances.map((instance) => (
                    <div
                      key={instance.instance_id}
                      className="bg-slate-900 border border-slate-700 rounded-lg p-4"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-3">
                          <Server className="w-5 h-5 text-slate-400" />
                          <div>
                            <div className="text-white font-medium">{instance.instance_id}</div>
                            <div className="text-slate-400 text-sm">
                              {instance.platform_name} • {instance.ip_address}
                            </div>
                          </div>
                        </div>
                        <div className={`
                          px-3 py-1 rounded-full text-xs font-medium
                          ${instance.is_online 
                            ? 'bg-green-500/20 text-green-400' 
                            : 'bg-red-500/20 text-red-400'}
                        `}>
                          {instance.ping_status}
                        </div>
                      </div>

                      <div className="space-y-3">
                        <div className="flex items-center gap-3">
                          <Button
                            size="sm"
                            onClick={() => testConnection(instance.instance_id)}
                            disabled={testing || !instance.is_online}
                            className="bg-cyan-600 hover:bg-cyan-700"
                          >
                            {testResults[instance.instance_id]?.status === 'testing' ? (
                              <>
                                <Loader className="w-4 h-4 mr-2 animate-spin" />
                                Testing...
                              </>
                            ) : (
                              <>
                                <Play className="w-4 h-4 mr-2" />
                                Test Connection
                              </>
                            )}
                          </Button>

                          {testResults[instance.instance_id]?.status === 'success' && (
                            <div className="flex items-center gap-2 text-green-400 text-sm">
                              <CheckCircle className="w-4 h-4" />
                              <span>All Validations Passed ✅</span>
                            </div>
                          )}

                          {testResults[instance.instance_id]?.status === 'error' && (
                            <div className="flex items-center gap-2 text-red-400 text-sm">
                              <XCircle className="w-4 h-4" />
                              <span>{testResults[instance.instance_id]?.error || 'Connection Failed'}</span>
                            </div>
                          )}
                        </div>

                        {/* Validation Steps Display */}
                        {testResults[instance.instance_id]?.validation_steps && (
                          <div className="bg-slate-950 border border-slate-700 rounded p-3 space-y-2">
                            <div className="text-sm font-medium text-slate-300 mb-2">Validation Checks:</div>
                            {Object.entries(testResults[instance.instance_id].validation_steps).map(([key, step]) => (
                              <div key={key} className="flex items-start gap-2 text-sm">
                                {step.status === 'passed' && <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />}
                                {step.status === 'failed' && <XCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />}
                                {step.status === 'warning' && <AlertCircle className="w-4 h-4 text-amber-400 mt-0.5 flex-shrink-0" />}
                                {step.status === 'checking' && <Loader className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0 animate-spin" />}
                                {step.status === 'pending' && <div className="w-4 h-4 mt-0.5 flex-shrink-0 rounded-full border-2 border-slate-600" />}
                                <div className="flex-1">
                                  <div className="font-medium text-slate-300 capitalize">{key.replace(/_/g, ' ')}</div>
                                  <div className={`text-xs ${
                                    step.status === 'passed' ? 'text-green-400' :
                                    step.status === 'failed' ? 'text-red-400' :
                                    step.status === 'warning' ? 'text-amber-400' :
                                    'text-slate-400'
                                  }`}>
                                    {step.message}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Troubleshooting Guide */}
                        {testResults[instance.instance_id]?.status === 'error' && testResults[instance.instance_id]?.troubleshooting && (
                          <div className="bg-amber-900/20 border border-amber-500/30 rounded p-3 mt-2">
                            <div className="text-sm font-medium text-amber-300 mb-2 flex items-center gap-2">
                              <AlertCircle className="w-4 h-4" />
                              Troubleshooting Steps:
                            </div>
                            <ul className="text-sm text-slate-300 space-y-1">
                              {testResults[instance.instance_id].troubleshooting.map((step, idx) => (
                                <li key={idx} className="pl-4">{step}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Instance Details on Success */}
                        {testResults[instance.instance_id]?.status === 'success' && testResults[instance.instance_id]?.instance_details && (
                          <div className="bg-green-900/20 border border-green-500/30 rounded p-3 text-sm">
                            <div className="font-medium text-green-300 mb-2">Instance Details:</div>
                            <div className="grid grid-cols-2 gap-2 text-slate-300">
                              <div>Platform: {testResults[instance.instance_id].instance_details.platform}</div>
                              <div>Agent: v{testResults[instance.instance_id].instance_details.agent_version}</div>
                              <div>Status: {testResults[instance.instance_id].instance_details.ping_status}</div>
                              <div className="text-xs text-slate-400 col-span-2">
                                Command ID: {testResults[instance.instance_id].command_id}
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {hasSuccessfulTest && (
              <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4 mt-4">
                <div className="flex items-center gap-3">
                  <CheckCircle className="w-5 h-5 text-green-400" />
                  <div>
                    <h4 className="text-green-300 font-semibold">✅ SSM Connection Verified!</h4>
                    <p className="text-slate-300 text-sm">
                      You can now proceed to create the company. Alert Whisperer will be able to 
                      execute runbooks and manage these servers remotely.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {!hasSuccessfulTest && agentHealth && agentHealth.instances && agentHealth.instances.length > 0 && (
              <div className="bg-amber-900/20 border border-amber-500/30 rounded-lg p-4 mt-4">
                <div className="flex items-center gap-3">
                  <AlertCircle className="w-5 h-5 text-amber-400" />
                  <div>
                    <h4 className="text-amber-300 font-semibold">Test Required</h4>
                    <p className="text-slate-300 text-sm">
                      You must successfully test at least one SSM connection before the company can be created.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Step 3: Complete */}
      {currentStep === 3 && createdCompany && (
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-2xl text-white flex items-center gap-2">
              <Sparkles className="w-6 h-6 text-green-400" />
              Company Created Successfully!
            </CardTitle>
            <CardDescription>
              {companyData.name} has been onboarded to Alert Whisperer
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Company Details */}
            <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-6">
              <h4 className="text-green-300 font-semibold mb-4">🎉 Setup Complete!</h4>
              <div className="space-y-3 text-sm">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-slate-300">Company profile created</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-slate-300">AWS SSM connection established</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-slate-300">API key generated for webhook integration</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-slate-300">Ready to receive alerts</span>
                </div>
              </div>
            </div>

            {/* API Key */}
            <div>
              <Label className="text-white mb-2 block">API Key (for webhook alerts)</Label>
              <div className="flex items-center gap-2">
                <Input
                  value={createdCompany.api_key}
                  readOnly
                  className="bg-slate-900 border-slate-700 text-white font-mono"
                />
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleCopy(createdCompany.api_key, 'api-key')}
                  className="border-slate-600"
                >
                  {copiedIndex === 'api-key' ? (
                    <Check className="w-4 h-4 text-green-400" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </Button>
              </div>
              <p className="text-slate-400 text-sm mt-1">
                Share this with {companyData.name} to configure their monitoring tools
              </p>
            </div>

            {/* Next Steps */}
            <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
              <h4 className="text-blue-300 font-semibold mb-3">📋 Next Steps</h4>
              <ol className="text-slate-300 text-sm space-y-2 list-decimal list-inside">
                <li>Configure the client's monitoring tools to send alerts to Alert Whisperer</li>
                <li>Assign technicians to handle incidents for this company</li>
                <li>Create custom runbooks for common issues</li>
                <li>Set up auto-assignment rules based on alert types</li>
              </ol>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Action Buttons */}
      <div className="flex items-center justify-between mt-6">
        <div>
          {currentStep > 0 && currentStep < 3 && (
            <Button
              variant="outline"
              onClick={handlePrevious}
              disabled={loading}
              className="border-slate-600"
            >
              Previous
            </Button>
          )}
        </div>

        <div className="flex items-center gap-3">
          {currentStep < 3 && (
            <Button
              variant="ghost"
              onClick={onCancel}
              className="text-slate-400 hover:text-white"
            >
              Cancel
            </Button>
          )}
          
          <Button
            onClick={handleNext}
            disabled={loading || (currentStep === 2 && !hasSuccessfulTest)}
            className="bg-cyan-600 hover:bg-cyan-700"
          >
            {loading ? (
              <>
                <Loader className="w-4 h-4 mr-2 animate-spin" />
                Creating...
              </>
            ) : currentStep === 3 ? (
              'Go to Dashboard'
            ) : currentStep === 2 ? (
              <>
                Create Company
                <ArrowRight className="w-4 h-4 ml-2" />
              </>
            ) : (
              <>
                Next
                <ArrowRight className="w-4 h-4 ml-2" />
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default MSPOnboardingWizard;
