import React, { useState } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { 
  Building2, Cloud, CheckCircle, XCircle, Loader, AlertCircle,
  Webhook, Key, Shield, Settings, Zap
} from 'lucide-react';
import { toast } from 'sonner';

/**
 * SIMPLIFIED Company Onboarding
 * No complex wizard - just a clean form with optional integrations
 */
const SimplifiedCompanyOnboarding = ({ onSuccess, onCancel }) => {
  const [loading, setLoading] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  
  const [formData, setFormData] = useState({
    // Basic Info
    name: '',
    contact_email: '',
    maintenance_window: 'Saturday 22:00-02:00 EST',
    
    // Integration Type
    integration_type: 'webhook_only', // webhook_only, aws, datadog, zabbix
    
    // AWS Integration (optional)
    aws_enabled: false,
    aws_role_arn: '',
    aws_external_id: '',
    aws_regions: 'us-east-1',
    
    // Datadog Integration (optional)
    datadog_enabled: false,
    datadog_api_key: '',
    datadog_app_key: '',
    
    // Zabbix Integration (optional)
    zabbix_enabled: false,
    zabbix_url: '',
    zabbix_username: '',
    zabbix_password: '',
    
    // Webhook Settings
    enable_hmac: false,
    rate_limit: 100
  });

  const integrationTypes = [
    {
      id: 'webhook_only',
      name: 'Webhook Only (PUSH)',
      description: 'Company sends alerts to your webhook. No credentials needed.',
      icon: Webhook,
      color: 'cyan',
      recommended: true
    },
    {
      id: 'aws',
      name: 'AWS Integration (PULL)',
      description: 'Auto-discover EC2 instances and pull CloudWatch data',
      icon: Cloud,
      color: 'orange',
      requiresCredentials: true
    },
    {
      id: 'datadog',
      name: 'Datadog Integration (PULL)',
      description: 'Pull monitors, hosts, and metrics from Datadog',
      icon: Zap,
      color: 'purple',
      requiresCredentials: true
    },
    {
      id: 'zabbix',
      name: 'Zabbix Integration (PULL)',
      description: 'Pull triggers and problems from Zabbix',
      icon: Shield,
      color: 'red',
      requiresCredentials: true
    }
  ];

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setTestResult(null); // Clear test result when changing fields
  };

  const testConnection = async () => {
    const { integration_type } = formData;
    
    // Webhook-only doesn't need testing
    if (integration_type === 'webhook_only') {
      setTestResult({ success: true, message: 'Webhook integration ready!' });
      return true;
    }
    
    setTesting(true);
    setTestResult(null);
    
    try {
      let response;
      
      if (integration_type === 'aws') {
        if (!formData.aws_role_arn || !formData.aws_external_id) {
          toast.error('AWS Role ARN and External ID are required');
          setTesting(false);
          return false;
        }
        
        response = await api.post('/integrations/test/aws', {
          role_arn: formData.aws_role_arn,
          external_id: formData.aws_external_id,
          regions: formData.aws_regions.split(',').map(r => r.trim())
        });
      } 
      else if (integration_type === 'datadog') {
        if (!formData.datadog_api_key || !formData.datadog_app_key) {
          toast.error('Datadog API Key and App Key are required');
          setTesting(false);
          return false;
        }
        
        response = await api.post('/integrations/test/datadog', {
          api_key: formData.datadog_api_key,
          app_key: formData.datadog_app_key
        });
      }
      else if (integration_type === 'zabbix') {
        if (!formData.zabbix_url || !formData.zabbix_username || !formData.zabbix_password) {
          toast.error('Zabbix URL, Username, and Password are required');
          setTesting(false);
          return false;
        }
        
        response = await api.post('/integrations/test/zabbix', {
          url: formData.zabbix_url,
          username: formData.zabbix_username,
          password: formData.zabbix_password
        });
      }
      
      const success = response.data.success;
      setTestResult({
        success,
        message: success 
          ? `✅ ${integration_type.toUpperCase()} connection successful!`
          : `❌ Connection failed: ${response.data.error}`,
        details: response.data.details
      });
      
      if (success) {
        toast.success('Connection test passed!');
      } else {
        toast.error('Connection test failed');
      }
      
      setTesting(false);
      return success;
    } catch (error) {
      const errorMsg = error.response?.data?.detail || error.message;
      setTestResult({
        success: false,
        message: `❌ Connection failed: ${errorMsg}`
      });
      toast.error('Connection test failed');
      setTesting(false);
      return false;
    }
  };

  const handleSubmit = async () => {
    // Validate basic info
    if (!formData.name.trim()) {
      toast.error('Company name is required');
      return;
    }
    
    if (!formData.contact_email.trim() || !formData.contact_email.includes('@')) {
      toast.error('Valid contact email is required');
      return;
    }
    
    // For pull-based integrations, require test to pass first
    const integrationType = integrationTypes.find(t => t.id === formData.integration_type);
    if (integrationType?.requiresCredentials) {
      if (!testResult || !testResult.success) {
        toast.error('⛔ Please test the connection successfully before creating the company');
        return;
      }
    }
    
    setLoading(true);
    
    try {
      // Build company data
      const companyData = {
        name: formData.name,
        contact_email: formData.contact_email,
        policy: {
          auto_approve_low_risk: true,
          maintenance_window: formData.maintenance_window
        },
        assets: [],
        integration_type: formData.integration_type
      };
      
      // Add integration credentials if applicable
      if (formData.integration_type === 'aws') {
        companyData.aws_integration = {
          enabled: true,
          role_arn: formData.aws_role_arn,
          external_id: formData.aws_external_id,
          regions: formData.aws_regions.split(',').map(r => r.trim())
        };
      } else if (formData.integration_type === 'datadog') {
        companyData.datadog_integration = {
          enabled: true,
          api_key: formData.datadog_api_key,
          app_key: formData.datadog_app_key
        };
      } else if (formData.integration_type === 'zabbix') {
        companyData.zabbix_integration = {
          enabled: true,
          url: formData.zabbix_url,
          username: formData.zabbix_username,
          password: formData.zabbix_password
        };
      }
      
      // Create company
      const response = await api.post('/companies', companyData);
      const createdCompany = response.data;
      
      toast.success('🎉 Company created successfully!');
      
      if (onSuccess) {
        onSuccess(createdCompany);
      }
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to create company');
    } finally {
      setLoading(false);
    }
  };

  const selectedIntegrationType = integrationTypes.find(t => t.id === formData.integration_type);

  return (
    <div className="max-w-3xl mx-auto p-6 space-y-6">
      {/* Basic Information */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-2xl text-white flex items-center gap-2">
            <Building2 className="w-6 h-6 text-cyan-400" />
            Company Information
          </CardTitle>
          <CardDescription>
            Enter the basic details for your client company
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="company-name" className="text-white">Company Name *</Label>
            <Input
              id="company-name"
              placeholder="e.g., Acme Corporation"
              value={formData.name}
              onChange={(e) => handleInputChange('name', e.target.value)}
              className="bg-slate-700 border-slate-600 text-white mt-2"
            />
          </div>

          <div>
            <Label htmlFor="contact-email" className="text-white">Contact Email *</Label>
            <Input
              id="contact-email"
              type="email"
              placeholder="e.g., it@acme.com"
              value={formData.contact_email}
              onChange={(e) => handleInputChange('contact_email', e.target.value)}
              className="bg-slate-700 border-slate-600 text-white mt-2"
            />
          </div>

          <div>
            <Label htmlFor="maintenance-window" className="text-white">Maintenance Window</Label>
            <Input
              id="maintenance-window"
              placeholder="e.g., Saturday 22:00-02:00 EST"
              value={formData.maintenance_window}
              onChange={(e) => handleInputChange('maintenance_window', e.target.value)}
              className="bg-slate-700 border-slate-600 text-white mt-2"
            />
            <p className="text-slate-400 text-sm mt-1">
              When can automated maintenance tasks run?
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Integration Type Selection */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-2xl text-white flex items-center gap-2">
            <Settings className="w-6 h-6 text-cyan-400" />
            Integration Type
          </CardTitle>
          <CardDescription>
            How will this company send alerts to Alert Whisperer?
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {integrationTypes.map((type) => (
              <button
                key={type.id}
                onClick={() => handleInputChange('integration_type', type.id)}
                className={`
                  relative p-4 rounded-lg border-2 transition-all text-left
                  ${formData.integration_type === type.id 
                    ? `border-${type.color}-500 bg-${type.color}-500/10` 
                    : 'border-slate-600 bg-slate-700 hover:border-slate-500'}
                `}
              >
                {type.recommended && (
                  <div className="absolute top-2 right-2">
                    <span className="bg-green-500 text-white text-xs px-2 py-1 rounded-full">
                      Recommended
                    </span>
                  </div>
                )}
                
                <type.icon className={`w-8 h-8 mb-2 text-${type.color}-400`} />
                <div className="text-white font-semibold mb-1">{type.name}</div>
                <div className="text-slate-400 text-sm">{type.description}</div>
              </button>
            ))}
          </div>

          {/* Show integration-specific fields */}
          {formData.integration_type === 'aws' && (
            <div className="mt-6 space-y-4 p-4 bg-slate-900 rounded-lg border border-slate-700">
              <h4 className="text-white font-semibold mb-2">AWS Integration Credentials</h4>
              
              <div>
                <Label className="text-white">AWS Role ARN *</Label>
                <Input
                  placeholder="arn:aws:iam::123456789012:role/AlertWhispererAccess"
                  value={formData.aws_role_arn}
                  onChange={(e) => handleInputChange('aws_role_arn', e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white mt-2"
                />
              </div>

              <div>
                <Label className="text-white">External ID *</Label>
                <Input
                  placeholder="secure-external-id-123"
                  value={formData.aws_external_id}
                  onChange={(e) => handleInputChange('aws_external_id', e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white mt-2"
                />
              </div>

              <div>
                <Label className="text-white">AWS Regions (comma-separated)</Label>
                <Input
                  placeholder="us-east-1, us-west-2"
                  value={formData.aws_regions}
                  onChange={(e) => handleInputChange('aws_regions', e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white mt-2"
                />
              </div>

              <Button
                onClick={testConnection}
                disabled={testing}
                className="w-full bg-orange-500 hover:bg-orange-600"
              >
                {testing ? (
                  <>
                    <Loader className="w-4 h-4 mr-2 animate-spin" />
                    Testing AWS Connection...
                  </>
                ) : (
                  <>
                    <Cloud className="w-4 h-4 mr-2" />
                    Test AWS Connection
                  </>
                )}
              </Button>
            </div>
          )}

          {formData.integration_type === 'datadog' && (
            <div className="mt-6 space-y-4 p-4 bg-slate-900 rounded-lg border border-slate-700">
              <h4 className="text-white font-semibold mb-2">Datadog Integration Credentials</h4>
              
              <div>
                <Label className="text-white">Datadog API Key *</Label>
                <Input
                  type="password"
                  placeholder="abc123xyz..."
                  value={formData.datadog_api_key}
                  onChange={(e) => handleInputChange('datadog_api_key', e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white mt-2"
                />
              </div>

              <div>
                <Label className="text-white">Datadog Application Key *</Label>
                <Input
                  type="password"
                  placeholder="app_key_xyz..."
                  value={formData.datadog_app_key}
                  onChange={(e) => handleInputChange('datadog_app_key', e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white mt-2"
                />
              </div>

              <Button
                onClick={testConnection}
                disabled={testing}
                className="w-full bg-purple-500 hover:bg-purple-600"
              >
                {testing ? (
                  <>
                    <Loader className="w-4 h-4 mr-2 animate-spin" />
                    Testing Datadog Connection...
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 mr-2" />
                    Test Datadog Connection
                  </>
                )}
              </Button>
            </div>
          )}

          {formData.integration_type === 'zabbix' && (
            <div className="mt-6 space-y-4 p-4 bg-slate-900 rounded-lg border border-slate-700">
              <h4 className="text-white font-semibold mb-2">Zabbix Integration Credentials</h4>
              
              <div>
                <Label className="text-white">Zabbix URL *</Label>
                <Input
                  placeholder="https://zabbix.company.com"
                  value={formData.zabbix_url}
                  onChange={(e) => handleInputChange('zabbix_url', e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white mt-2"
                />
              </div>

              <div>
                <Label className="text-white">Username *</Label>
                <Input
                  placeholder="api_user"
                  value={formData.zabbix_username}
                  onChange={(e) => handleInputChange('zabbix_username', e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white mt-2"
                />
              </div>

              <div>
                <Label className="text-white">Password *</Label>
                <Input
                  type="password"
                  placeholder="••••••••"
                  value={formData.zabbix_password}
                  onChange={(e) => handleInputChange('zabbix_password', e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white mt-2"
                />
              </div>

              <Button
                onClick={testConnection}
                disabled={testing}
                className="w-full bg-red-500 hover:bg-red-600"
              >
                {testing ? (
                  <>
                    <Loader className="w-4 h-4 mr-2 animate-spin" />
                    Testing Zabbix Connection...
                  </>
                ) : (
                  <>
                    <Shield className="w-4 h-4 mr-2" />
                    Test Zabbix Connection
                  </>
                )}
              </Button>
            </div>
          )}

          {/* Test Result Display */}
          {testResult && (
            <div className={`
              p-4 rounded-lg border-2 flex items-start gap-3
              ${testResult.success 
                ? 'bg-green-900/20 border-green-500/50' 
                : 'bg-red-900/20 border-red-500/50'}
            `}>
              {testResult.success ? (
                <CheckCircle className="w-6 h-6 text-green-400 flex-shrink-0 mt-0.5" />
              ) : (
                <XCircle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
              )}
              <div className="flex-1">
                <p className={`font-semibold ${testResult.success ? 'text-green-300' : 'text-red-300'}`}>
                  {testResult.message}
                </p>
                {testResult.details && (
                  <p className="text-slate-400 text-sm mt-1">{testResult.details}</p>
                )}
              </div>
            </div>
          )}

          {formData.integration_type === 'webhook_only' && (
            <div className="bg-cyan-900/20 border border-cyan-500/30 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <Webhook className="w-5 h-5 text-cyan-400 mt-0.5" />
                <div>
                  <h4 className="text-cyan-300 font-semibold mb-1">Webhook Integration (PUSH)</h4>
                  <p className="text-slate-300 text-sm">
                    After creating the company, you'll receive a webhook URL and API key to share with the client. 
                    They'll configure their monitoring tools to send alerts to your webhook. 
                    <strong className="text-white"> No credentials needed from them!</strong>
                  </p>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Action Buttons */}
      <div className="flex gap-3 justify-end">
        <Button
          variant="outline"
          onClick={onCancel}
          disabled={loading}
          className="bg-slate-700 border-slate-600 hover:bg-slate-600 text-white"
        >
          Cancel
        </Button>
        
        <Button
          onClick={handleSubmit}
          disabled={loading || (selectedIntegrationType?.requiresCredentials && (!testResult || !testResult.success))}
          className="bg-cyan-500 hover:bg-cyan-600 text-white"
        >
          {loading ? (
            <>
              <Loader className="w-4 h-4 mr-2 animate-spin" />
              Creating Company...
            </>
          ) : (
            <>
              <CheckCircle className="w-4 h-4 mr-2" />
              Create Company
            </>
          )}
        </Button>
      </div>

      {selectedIntegrationType?.requiresCredentials && (!testResult || !testResult.success) && (
        <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-yellow-400 mt-0.5" />
            <div>
              <h4 className="text-yellow-300 font-semibold mb-1">Connection Test Required</h4>
              <p className="text-slate-300 text-sm">
                You must test and verify the {selectedIntegrationType.name.toLowerCase()} connection 
                successfully before creating the company.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SimplifiedCompanyOnboarding;
